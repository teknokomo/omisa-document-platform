from __future__ import annotations

import argparse
import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import stat
import time
from pathlib import Path

from .breakglass import (
    BreakGlassCoordinator, BreakGlassError, CoordinatorClient, REASON_CODES,
    _b64, _recv_frame, _send_frame,
)

MAX_INPUT=20*1024*1024
MAX_FRAME=64*1024
TTL=24*60*60
ARCHIVE_RE=re.compile(r"bga_v1_[A-Za-z0-9_-]{32}")
ENTRY_RE=re.compile(r"bge_v1_[A-Za-z0-9_-]{32}")


class UnixArchiveBroker:
    def __init__(self,socket_path="/run/omisa-archive-breakglass-worker/archive.sock",timeout=90):
        self.socket_path=str(socket_path);self.timeout=timeout

    def request(self,request,fd,expect_fd=False):
        sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);sock.settimeout(self.timeout)
        try:
            sock.connect(self.socket_path);_send_frame(sock,request,fd);sock.shutdown(socket.SHUT_WR)
            result,out=_recv_frame(sock,expect_fd=None)
            if not result.get("success"):
                if out is not None:os.close(out)
                raise BreakGlassError(result.get("error","archive_failed"))
            if bool(out is not None)!=expect_fd:
                if out is not None:os.close(out)
                raise BreakGlassError("malformed_archive_response")
            return result,out
        except BreakGlassError:raise
        except (OSError,socket.timeout) as exc:raise BreakGlassError("archive_broker_unavailable") from exc
        finally:sock.close()


class ArchiveBreakGlassCoordinator(BreakGlassCoordinator):
    def __init__(self,root:Path,broker=None,archive_broker=None,now=None,expected_uid=None):
        self.archive_broker=archive_broker or UnixArchiveBroker()
        super().__init__(root,broker=broker,now=now,expected_uid=expected_uid)
        for name in ("archives","entries"):
            child=self.root/name
            if child.is_symlink():raise BreakGlassError("unsafe_state")
            child.mkdir(mode=0o700,exist_ok=True)
            st=child.stat()
            if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.getuid() or st.st_mode&0o077:raise BreakGlassError("unsafe_state")
        self._gc_state()

    def _gc_state(self):
        now=int(self.now());live=set();cutoff=now-TTL
        for name in sorted(os.listdir(self.root/"archives")):
            if not name.endswith(".json"):continue
            try:cap=self._signed_load("archives",name,b"archive-state-v1:")
            except BreakGlassError:continue
            if cap.get("expires",0)<=now:
                try:(self.root/"archives"/name).unlink()
                except OSError:pass
                continue
            if isinstance(cap.get("snapshot"),str):live.add(cap["snapshot"])
        for name in sorted(os.listdir(self.root/"entries")):
            if not name.endswith(".json"):continue
            try:cap=self._signed_load("entries",name,b"archive-entry-v1:")
            except BreakGlassError:continue
            if cap.get("expires",0)<=now:
                try:(self.root/"entries"/name).unlink()
                except OSError:pass
        for directory,suffixes in (("entries",(".used",".claim")),("parses",(".json",))):
            for name in sorted(os.listdir(self.root/directory)):
                if not name.endswith(suffixes):continue
                path=self.root/directory/name
                try:
                    st=path.stat()
                    if stat.S_ISREG(st.st_mode) and st.st_uid==os.getuid() and st.st_mtime<cutoff:path.unlink()
                except OSError:continue
        for name in sorted(os.listdir(self.root/"snapshots")):
            if name in live:continue
            path=self.root/"snapshots"/name
            try:
                st=path.stat()
                if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid():continue
                if st.st_mtime<cutoff:path.unlink()
            except OSError:continue

    def _audit(self,event,**kwargs):
        return self._receipt(event=event,**kwargs)

    def _state_dirfd(self,directory):
        fd=os.open(self.root/directory,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW)
        st=os.fstat(fd)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.getuid() or st.st_mode&0o077:
            os.close(fd);raise BreakGlassError("unsafe_state")
        return fd

    def _signed_write(self,directory,name,payload,purpose):
        encoded=json.dumps(payload,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
        envelope={"payload":payload,"hmac":_b64(hmac.new(self.key,purpose+encoded,hashlib.sha256).digest())}
        self._exclusive_write(directory,name,json.dumps(envelope,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode())

    def _signed_load(self,directory,name,purpose):
        dirfd=self._state_dirfd(directory)
        try:
            fd=os.open(name,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=dirfd)
            try:
                st=os.fstat(fd)
                if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or st.st_mode&0o077 or not 1<=st.st_size<=MAX_FRAME:raise BreakGlassError("invalid_capability")
                raw=os.read(fd,MAX_FRAME+1)
            finally:os.close(fd)
        except OSError as exc:raise BreakGlassError("invalid_capability") from exc
        finally:os.close(dirfd)
        try:
            env=json.loads(raw);payload=env["payload"]
            encoded=json.dumps(payload,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
            expected=_b64(hmac.new(self.key,purpose+encoded,hashlib.sha256).digest())
            if not hmac.compare_digest(env["hmac"],expected):raise ValueError
            return payload
        except Exception as exc:raise BreakGlassError("invalid_capability") from exc

    def _persistent_snapshot(self,source_fd):
        st=os.fstat(source_fd);identity=(st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns)
        if fcntl.fcntl(source_fd,fcntl.F_GETFL)&os.O_ACCMODE!=os.O_RDONLY:raise BreakGlassError("writable_fd_not_allowed")
        if not stat.S_ISREG(st.st_mode):raise BreakGlassError("not_regular_file")
        if not 1<=st.st_size<=MAX_INPUT:raise BreakGlassError("input_size_not_allowed")
        name="archive-"+secrets.token_urlsafe(24);dirfd=self._state_dirfd("snapshots");fd=None
        try:
            fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC|os.O_NOFOLLOW,0o400,dir_fd=dirfd)
            digest=hashlib.sha256();offset=0
            while offset<st.st_size:
                chunk=os.pread(source_fd,min(1024*1024,st.st_size-offset),offset)
                if not chunk:raise BreakGlassError("source_changed")
                digest.update(chunk);view=memoryview(chunk)
                while view:view=view[os.write(fd,view):]
                offset+=len(chunk)
            current=os.fstat(source_fd)
            if (current.st_dev,current.st_ino,current.st_size,current.st_mtime_ns,current.st_ctime_ns)!=identity:raise BreakGlassError("source_changed")
            os.fsync(fd);os.close(fd);fd=None;os.fsync(dirfd)
            return name,st.st_size,digest.hexdigest(),identity
        except Exception:
            if fd is not None:os.close(fd)
            try:os.unlink(name,dir_fd=dirfd)
            except OSError:pass
            raise
        finally:os.close(dirfd)

    def _open_snapshot(self,name):
        if not isinstance(name,str) or not re.fullmatch(r"archive-[A-Za-z0-9_-]{32}",name):raise BreakGlassError("invalid_capability")
        dirfd=self._state_dirfd("snapshots")
        try:return os.open(name,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=dirfd)
        except OSError as exc:raise BreakGlassError("invalid_capability") from exc
        finally:os.close(dirfd)

    def inspect_fd(self,source_fd,reason):
        size=digest=identity=None;snapshot=None;archive_ref=None;entry_refs=[]
        if not isinstance(reason,str) or reason not in REASON_CODES:
            self._audit("break_glass_archive_inspect",status="denied",reason="invalid",error="invalid_reason");raise BreakGlassError("invalid_reason")
        try:
            snapshot,size,digest,identity=self._persistent_snapshot(source_fd)
            fd=self._open_snapshot(snapshot)
            try:result,_=self.archive_broker.request({"operation":"inspect"},fd)
            finally:os.close(fd)
            entries=result.get("entries")
            if result.get("archive_digest")!=digest or not isinstance(entries,list):raise BreakGlassError("archive_changed")
            archive_ref="bga_v1_"+secrets.token_urlsafe(24);expires=int(self.now())+TTL
            self._signed_write("archives",archive_ref+".json",{"archive_ref":archive_ref,"snapshot":snapshot,"size":size,"digest":digest,"reason":reason,"expires":expires},b"archive-state-v1:")
            public=[]
            for entry in entries:
                if not isinstance(entry,dict):raise BreakGlassError("malformed_archive_response")
                entry_ref="bge_v1_"+secrets.token_urlsafe(24)
                self._signed_write("entries",entry_ref+".json",{"entry_ref":entry_ref,"archive_ref":archive_ref,"entry":entry,"reason":reason,"expires":expires},b"archive-entry-v1:")
                entry_refs.append(entry_ref)
                public.append({k:entry[k] for k in ("index","size","compressed_size","detected_format","eligible","reason")}|{"entry_ref":entry_ref})
            try:receipt=self._audit("break_glass_archive_inspect",status="success",reason=reason,size=size,digest=digest,identity=identity)
            except Exception:raise BreakGlassError("receipt_failed")
            return {"success":True,"archive_ref":archive_ref,"receipt_id":receipt,"entries":public,"entry_count":result.get("entry_count"),"total_uncompressed":result.get("total_uncompressed"),"expires":expires}
        except BreakGlassError as exc:
            for ref in entry_refs:
                try:(self.root/"entries"/(ref+".json")).unlink()
                except OSError:pass
            if archive_ref:
                try:(self.root/"archives"/(archive_ref+".json")).unlink()
                except OSError:pass
            if snapshot:
                try:(self.root/"snapshots"/snapshot).unlink()
                except OSError:pass
            try:self._audit("break_glass_archive_inspect",status="error",reason=reason,error=str(exc),size=size,digest=digest,identity=identity)
            except Exception:pass
            raise

    def extract(self,entry_ref):
        if not isinstance(entry_ref,str) or not ENTRY_RE.fullmatch(entry_ref):raise BreakGlassError("invalid_entry_ref")
        lockfd=None;out=None;cap=None;parsed=None;claim_created=False
        try:
            lockfd=os.open(self.root/"entries"/(entry_ref+".json"),os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW);fcntl.flock(lockfd,fcntl.LOCK_EX)
            if (self.root/"entries"/(entry_ref+".used")).exists():raise BreakGlassError("entry_ref_used")
            if (self.root/"entries"/(entry_ref+".claim")).exists():raise BreakGlassError("entry_ref_in_progress")
            cap=self._signed_load("entries",entry_ref+".json",b"archive-entry-v1:")
            if cap.get("entry_ref")!=entry_ref or int(self.now())>cap.get("expires",0):raise BreakGlassError("entry_ref_expired")
            archive_ref=cap.get("archive_ref")
            if not isinstance(archive_ref,str) or not ARCHIVE_RE.fullmatch(archive_ref):raise BreakGlassError("invalid_entry_ref")
            archive=self._signed_load("archives",archive_ref+".json",b"archive-state-v1:")
            if archive.get("archive_ref")!=archive_ref or int(self.now())>archive.get("expires",0):raise BreakGlassError("entry_ref_expired")
            self._exclusive_write("entries",entry_ref+".claim",json.dumps({"claimed":int(self.now()),"expires":cap["expires"]},separators=(",",":")).encode());claim_created=True
            source=self._open_snapshot(archive["snapshot"])
            try:result,out=self.archive_broker.request({"operation":"extract","expected_archive_digest":archive["digest"],"entry_index":cap["entry"]["index"],"expected":cap["entry"]},source,True)
            finally:os.close(source)
            st=os.fstat(out);digest=hashlib.sha256();offset=0
            while offset<st.st_size:
                chunk=os.pread(out,min(1024*1024,st.st_size-offset),offset)
                if not chunk:break
                digest.update(chunk);offset+=len(chunk)
            if st.st_size!=result.get("size") or digest.hexdigest()!=result.get("sha256"):raise BreakGlassError("entry_changed")
            parsed=self.parse_fd(out,reason=cap["reason"])
            try:self._exclusive_write("entries",entry_ref+".used",b"used\n")
            except Exception:
                try:(self.root/"parses"/(parsed["parse_ref"]+".json")).unlink()
                except OSError:pass
                try:(self.root/"entries"/(entry_ref+".claim")).unlink()
                except OSError:pass
                raise BreakGlassError("receipt_failed")
            try:receipt=self._audit("break_glass_archive_extract",status="success",reason=cap["reason"],size=st.st_size,digest=digest.hexdigest(),detected=result.get("detected_format"))
            except Exception:
                try:(self.root/"entries"/(entry_ref+".used")).unlink()
                except OSError:pass
                try:(self.root/"entries"/(entry_ref+".claim")).unlink()
                except OSError:pass
                try:(self.root/"parses"/(parsed["parse_ref"]+".json")).unlink()
                except OSError:pass
                raise BreakGlassError("receipt_failed")
            try:(self.root/"entries"/(entry_ref+".claim")).unlink()
            except OSError:pass
            return {**parsed,"receipt_id":receipt,"parse_receipt_id":parsed["receipt_id"],"archive_ref":archive_ref,"detected_format":result.get("detected_format")}
        except BreakGlassError as exc:
            if claim_created and parsed is None:
                try:(self.root/"entries"/(entry_ref+".claim")).unlink()
                except OSError:pass
            reason="archive_review"
            try:
                if isinstance(cap,dict) and cap.get("reason") in REASON_CODES:reason=cap["reason"]
            except Exception:pass
            try:self._audit("break_glass_archive_extract",status="error",reason=reason,error=str(exc))
            except Exception:pass
            raise
        except OSError as exc:
            try:self._audit("break_glass_archive_extract",status="error",reason="archive_review",error="invalid_entry_ref")
            except Exception:pass
            raise BreakGlassError("invalid_entry_ref") from exc
        finally:
            if out is not None:os.close(out)
            if lockfd is not None:os.close(lockfd)

    def handle(self,connection):
        fd=None
        try:
            import struct
            _pid,uid,_gid=struct.unpack("3i",connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            if self.expected_uid is not None and uid!=self.expected_uid:raise BreakGlassError("unauthorized")
            request,fd=_recv_frame(connection,expect_fd=None);command=request.get("command")
            allowed={"inspect":{"command","reason"},"extract":{"command","entry_ref"},"read":{"command","parse_ref","cursor","limit"}}
            if command not in allowed or set(request)-allowed[command] or bool(fd is not None)!=(command=="inspect"):raise BreakGlassError("invalid_request")
            if command=="inspect":result=self.inspect_fd(fd,request.get("reason"))
            elif command=="extract":result=self.extract(request.get("entry_ref"))
            else:result=self.read(parse_ref=request.get("parse_ref"),cursor=request.get("cursor"),limit=request.get("limit",20))
        except BreakGlassError as exc:result={"success":False,"error":str(exc)}
        finally:
            if fd is not None:os.close(fd)
        try:_send_frame(connection,result)
        except Exception:
            try:_send_frame(connection,{"success":False,"error":"coordinator_failed"})
            except Exception:pass
        finally:
            try:connection.close()
            except OSError:pass


def cli(argv=None):
    p=argparse.ArgumentParser(prog="omisa-archive-breakglass",allow_abbrev=False);sub=p.add_subparsers(dest="command",required=True)
    inspect=sub.add_parser("inspect",allow_abbrev=False);inspect.add_argument("path",type=Path);inspect.add_argument("--reason",required=True,choices=sorted(REASON_CODES))
    extract=sub.add_parser("extract",allow_abbrev=False);extract.add_argument("--entry-ref",required=True)
    read=sub.add_parser("read",allow_abbrev=False);g=read.add_mutually_exclusive_group(required=True);g.add_argument("--parse-ref");g.add_argument("--cursor");read.add_argument("--limit",type=int,default=20)
    args=p.parse_args(argv);client=CoordinatorClient("/run/omisa-archive-breakglass.sock",190);fd=None
    try:
        if args.command=="inspect":
            if args.path.is_symlink():raise BreakGlassError("symlink_not_allowed")
            fd=os.open(args.path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW);result=client.request({"command":"inspect","reason":args.reason},fd)
        elif args.command=="extract":result=client.request({"command":"extract","entry_ref":args.entry_ref})
        else:result=client.request({"command":"read","parse_ref":args.parse_ref,"cursor":args.cursor,"limit":args.limit})
    except (BreakGlassError,OSError) as exc:result={"success":False,"error":str(exc) if isinstance(exc,BreakGlassError) else "source_unavailable"}
    finally:
        if fd is not None:os.close(fd)
    print(json.dumps(result,ensure_ascii=False,separators=(",",":")));return 0 if result.get("success") else 2


def coordinator_main(argv=None):
    p=argparse.ArgumentParser(allow_abbrev=False);p.add_argument("--systemd-stdio",action="store_true",required=True);p.add_argument("--state-dir",type=Path,required=True);p.add_argument("--allowed-uid",type=int,required=True);p.add_argument("--parser-socket",required=True);p.add_argument("--archive-socket",required=True);args=p.parse_args(argv)
    from .breakglass import UnixBroker
    connection=socket.socket(fileno=os.dup(0));ArchiveBreakGlassCoordinator(args.state_dir,broker=UnixBroker(args.parser_socket),archive_broker=UnixArchiveBroker(args.archive_socket),expected_uid=args.allowed_uid).handle(connection)


def main():raise SystemExit(cli())
if __name__=="__main__":main()
