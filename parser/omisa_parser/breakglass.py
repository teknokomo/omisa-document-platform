from __future__ import annotations

import argparse
import array
import base64
import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import stat
import struct
import tempfile
import time
from pathlib import Path

from .protocol import encode_request, validate_response_stream

MAX_INPUT = 20 * 1024 * 1024
MAX_CACHE = 8 * 1024 * 1024
MAX_FRAME = 64 * 1024
MAX_REQUEST_FRAME = 4096
MAX_PAGES = 64
REASON_CODES = {"explicit_user_request", "unsupported_standard_source", "archive_review", "incident_response"}
PARSE_REF_RE = re.compile(r"bgp_v1_[A-Za-z0-9_-]{32}")
CURSOR_RE = re.compile(r"bgc_v1_[A-Za-z0-9_-]{40,256}")


class BreakGlassError(Exception):
    pass


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _send_frame(sock: socket.socket, value: dict, fd: int | None = None) -> None:
    raw=json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
    if len(raw)>MAX_FRAME:raise BreakGlassError("invalid_request")
    wire=struct.pack("!I",len(raw))+raw
    ancillary=[] if fd is None else [(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array("i",[fd]))]
    if sock.sendmsg([wire],ancillary)!=len(wire):raise BreakGlassError("coordinator_disconnect")


def _reject_duplicates(pairs):
    out={}
    for key,value in pairs:
        if key in out:raise ValueError("duplicate key")
        out[key]=value
    return out


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    out=b""
    while len(out)<count:
        chunk=sock.recv(count-len(out))
        if not chunk:raise BreakGlassError("coordinator_disconnect")
        out+=chunk
    return out


def _recv_frame(sock: socket.socket, expect_fd: bool | None = False) -> tuple[dict,int|None]:
    ancsize=socket.CMSG_SPACE(array.array("i",[0]).itemsize)
    prefix=b"";fds=[]
    while len(prefix)<4:
        data,ancillary,flags,_=sock.recvmsg(4-len(prefix),ancsize)
        if not data or flags & (socket.MSG_TRUNC|socket.MSG_CTRUNC):
            for fd in fds:os.close(fd)
            raise BreakGlassError("invalid_request")
        prefix+=data
        for level,kind,payload in ancillary:
            if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:
                values=array.array("i");values.frombytes(payload[:len(payload)-(len(payload)%values.itemsize)]);fds.extend(values)
    size=struct.unpack("!I",prefix)[0]
    if not 1<=size<=MAX_FRAME:
        for fd in fds:os.close(fd)
        raise BreakGlassError("invalid_request")
    if len(fds)>1 or (expect_fd is not None and len(fds)!=(1 if expect_fd else 0)):
        for fd in fds:os.close(fd)
        raise BreakGlassError("invalid_request")
    try:value=json.loads(_recv_exact(sock,size),object_pairs_hook=_reject_duplicates)
    except Exception:
        for fd in fds:os.close(fd)
        raise BreakGlassError("invalid_request")
    if not isinstance(value,dict):
        for fd in fds:os.close(fd)
        raise BreakGlassError("invalid_request")
    return value,(fds[0] if fds else None)


class UnixBroker:
    def __init__(self,socket_path="/run/omisa-parser-breakglass/parser.sock",credential=None,timeout=90):
        self.socket_path=str(socket_path);self.credential=credential;self.timeout=timeout

    def parse_fd(self,fd,*,artifact_ref,expected_size,options):
        request_id=secrets.token_hex(16)
        request={"protocol":"omisa.parse/1","request_id":request_id,"artifact_ref":artifact_ref,
                 "artifact_generation":0,"expected_size":expected_size,"options":options}
        wire=encode_request(request,self.credential);sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);sock.settimeout(self.timeout)
        try:
            sock.connect(self.socket_path)
            if sock.sendmsg([wire],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array("i",[fd]))])!=len(wire):raise BreakGlassError("broker_disconnect")
            sock.shutdown(socket.SHUT_WR)
            def chunks():
                while data:=sock.recv(65536):yield data
            rows=[json.loads(line) for line in validate_response_stream(chunks(),request_id=request_id)]
            if not rows or rows[-1].get("type")=="error":raise BreakGlassError(rows[-1].get("code","parser_failed") if rows else "parser_failed")
            return rows
        except (OSError,socket.timeout) as exc:raise BreakGlassError("broker_unavailable") from exc
        finally:sock.close()


class BreakGlassCoordinator:
    """Root-owned coordinator. The caller can submit FDs but cannot edit evidence."""
    def __init__(self,root:Path,broker=None,now=None,expected_uid:int|None=None):
        self.root=Path(root);self.broker=broker or UnixBroker();self.now=now or time.time;self.expected_uid=expected_uid
        self._secure_tree()
        self.key=self._load_key()

    def _secure_tree(self):
        if self.root.is_symlink():raise BreakGlassError("unsafe_state")
        self.root.mkdir(parents=True,exist_ok=True,mode=0o700)
        for child_name in ("receipts","parses","snapshots"):
            child=self.root/child_name
            if child.is_symlink():raise BreakGlassError("unsafe_state")
            child.mkdir(mode=0o700,exist_ok=True)
        for child in (self.root,self.root/"receipts",self.root/"parses",self.root/"snapshots"):
            st=child.stat()
            if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.getuid() or st.st_mode&0o077:raise BreakGlassError("unsafe_state")

    def _load_key(self):
        path=self.root/"receipt.key"
        flags=os.O_RDONLY|os.O_CLOEXEC|getattr(os,"O_NOFOLLOW",0)
        try:fd=os.open(path,flags)
        except FileNotFoundError:
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC|getattr(os,"O_NOFOLLOW",0),0o600)
            try:os.write(fd,secrets.token_bytes(32));os.fsync(fd)
            finally:os.close(fd)
            fd=os.open(path,flags)
        try:
            st=os.fstat(fd);data=os.read(fd,33)
            if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or st.st_mode&0o077 or len(data)!=32:raise BreakGlassError("unsafe_state")
            return data
        finally:os.close(fd)

    def _exclusive_write(self,directory:str,name:str,data:bytes):
        dirfd=os.open(self.root/directory,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|getattr(os,"O_NOFOLLOW",0))
        try:
            fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC|getattr(os,"O_NOFOLLOW",0),0o600,dir_fd=dirfd)
            try:
                view=memoryview(data)
                while view:view=view[os.write(fd,view):]
                os.fsync(fd)
            finally:os.close(fd)
            os.fsync(dirfd)
        finally:os.close(dirfd)

    def _receipt(self,*,status,reason,error=None,size=None,digest=None,detected=None,identity=None,event="break_glass_parse"):
        rid="bgr_v1_"+secrets.token_urlsafe(18)
        record={"schema":1,"receipt_id":rid,"event":event,"timestamp":int(self.now()),
               "caller_uid":self.expected_uid,"status":status,"reason":reason,"error":error,
               "input_size":size,"input_sha256":digest,"detected_format":detected}
        if identity is not None:
            packed=":".join(map(str,identity)).encode()
            record["source_identity_hmac"]=_b64(hmac.new(self.key,b"source-identity-v1:"+packed,hashlib.sha256).digest())
        unsigned=json.dumps(record,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
        record["receipt_hmac"]=_b64(hmac.new(self.key,b"receipt-v1:"+unsigned,hashlib.sha256).digest())
        self._exclusive_write("receipts",f"{rid}.json",json.dumps(record,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()+b"\n")
        return rid

    def _snapshot(self,source_fd:int):
        st=os.fstat(source_fd)
        identity=(st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns)
        if fcntl.fcntl(source_fd,fcntl.F_GETFL)&os.O_ACCMODE!=os.O_RDONLY:raise BreakGlassError("writable_fd_not_allowed")
        if not stat.S_ISREG(st.st_mode):raise BreakGlassError("not_regular_file")
        if not 1<=st.st_size<=MAX_INPUT:raise BreakGlassError("input_size_not_allowed")
        dirfd=os.open(self.root/"snapshots",os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
        name="snapshot-"+secrets.token_urlsafe(18);fd=None
        try:
            fd=os.open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC|os.O_NOFOLLOW,0o400,dir_fd=dirfd)
            h=hashlib.sha256();offset=0
            while offset<st.st_size:
                chunk=os.pread(source_fd,min(1024*1024,st.st_size-offset),offset)
                if not chunk:raise BreakGlassError("source_changed")
                h.update(chunk);view=memoryview(chunk)
                while view:view=view[os.write(fd,view):]
                offset+=len(chunk)
            os.fsync(fd)
            # Reopen the private snapshot read-only before unlinking. The broker
            # can consume but cannot mutate the exact bytes bound to the digest.
            read_fd=os.open(name,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=dirfd)
            os.unlink(name,dir_fd=dirfd);os.close(fd);fd=None
            return read_fd,st.st_size,h.hexdigest(),identity
        except Exception:
            if fd is not None:os.close(fd)
            try:os.unlink(name,dir_fd=dirfd)
            except OSError:pass
            raise
        finally:os.close(dirfd)

    def parse_fd(self,source_fd:int,*,reason:str):
        size=digest=identity=None;snapshot=None
        if not isinstance(reason,str) or reason not in REASON_CODES:
            self._receipt(status="denied",reason="invalid",error="invalid_reason")
            raise BreakGlassError("invalid_reason")
        try:
            snapshot,size,digest,identity=self._snapshot(source_fd)
            alias="art_v1_"+_b64(hmac.new(self.key,b"break-glass-source-v1:"+bytes.fromhex(digest),hashlib.sha256).digest())
            records=[];content_offset=unit_offset=0;header=None;units={};ids=set();orders={}
            for _ in range(MAX_PAGES):
                os.lseek(snapshot,0,os.SEEK_SET)
                page=self.broker.parse_fd(snapshot,artifact_ref=alias,expected_size=size,options={"max_records":500,"record_offset":content_offset,"unit_offset":unit_offset})
                if not isinstance(page,list) or len(page)<2 or page[0].get("type")!="document" or page[-1].get("type")!="end":raise BreakGlassError("malformed_parser_response")
                normalized={k:v for k,v in page[0].items() if k!="request_id"}
                if header is None:header=normalized;records.append(page[0])
                elif normalized!=header:raise BreakGlassError("malformed_parser_response")
                content=0
                for row in page[1:-1]:
                    if row.get("type")=="unit":
                        prior=units.get(row.get("id"))
                        if prior is not None and prior!=row:raise BreakGlassError("malformed_parser_response")
                        if prior is None:units[row["id"]]=row;records.append(row)
                    else:
                        if row.get("id") in ids or row.get("unit_id") not in units or row.get("order",0)<=orders.get(row.get("unit_id"),0):raise BreakGlassError("malformed_parser_response")
                        ids.add(row["id"]);orders[row["unit_id"]]=row["order"];records.append(row);content+=1
                terminal=page[-1]
                if not terminal.get("truncated"):
                    body=records[1:];terminal=dict(terminal);terminal["counts"]={"units_emitted":sum(x["type"]=="unit" for x in body),"records_emitted":len(records)+1,"text_chars":sum(len(x.get("text","")) for x in body if x["type"] in {"text","note"}),"tables":sum(x["type"]=="table" for x in body),"cells":sum(len(x.get("cells",[])) for x in body if x["type"]=="table")};records.append(terminal);break
                page_units=[x for x in page[1:-1] if x.get("type")=="unit"]
                if terminal.get("limit_reason") not in {"records","output_bytes"} or not(content or page_units):raise BreakGlassError("output_limit")
                content_offset+=content
                if page_units:unit_offset=max(unit_offset,max(x["index"] for x in page_units))
            else:raise BreakGlassError("output_limit")
            encoded=json.dumps(records,ensure_ascii=False,separators=(",",":"),allow_nan=False).encode()
            if len(encoded)>MAX_CACHE:raise BreakGlassError("output_limit")
            ref="bgp_v1_"+secrets.token_urlsafe(24)
            cache_mac=_b64(hmac.new(self.key,b"parse-cache-v1:"+encoded,hashlib.sha256).digest())
            envelope=json.dumps({"records":records,"cache_hmac":cache_mac},ensure_ascii=False,separators=(",",":"),allow_nan=False).encode()
            if len(envelope)>MAX_CACHE:raise BreakGlassError("output_limit")
            self._exclusive_write("parses",f"{ref}.json",envelope)
            try:rid=self._receipt(status="success",reason=reason,size=size,digest=digest,detected=records[0]["document"]["detected_format"],identity=identity)
            except Exception:
                try:(self.root/"parses"/f"{ref}.json").unlink()
                except OSError:pass
                raise BreakGlassError("receipt_failed")
            return {"success":True,"parse_ref":ref,"receipt_id":rid,"detected_format":records[0]["document"]["detected_format"],"records":len(records)}
        except BreakGlassError as exc:
            try:self._receipt(status="denied" if str(exc) in {"not_regular_file","input_size_not_allowed","writable_fd_not_allowed"} else "error",reason=reason,error=str(exc),size=size,digest=digest,identity=identity)
            except Exception:pass
            raise
        except Exception:
            try:self._receipt(status="error",reason=reason,error="broker_failed",size=size,digest=digest,identity=identity)
            except Exception:pass
            raise BreakGlassError("broker_failed")
        finally:
            if snapshot is not None:os.close(snapshot)

    def _cursor(self,ref,offset):
        payload=f"{ref}:{offset}".encode();return "bgc_v1_"+_b64(payload+hmac.new(self.key,b"cursor-v1:"+payload,hashlib.sha256).digest())

    def _decode_cursor(self,value):
        try:
            if not isinstance(value,str) or not CURSOR_RE.fullmatch(value):raise ValueError
            encoded=value[7:];raw=base64.urlsafe_b64decode(encoded+"="*((4-len(encoded)%4)%4))
            if _b64(raw)!=encoded:raise ValueError
            payload,mac=raw[:-32],raw[-32:]
            if not hmac.compare_digest(mac,hmac.new(self.key,b"cursor-v1:"+payload,hashlib.sha256).digest()):raise ValueError
            ref,text=payload.decode().rsplit(":",1);offset=int(text)
            if not PARSE_REF_RE.fullmatch(ref) or offset<0:raise ValueError
            return ref,offset
        except Exception as exc:raise BreakGlassError("invalid_cursor") from exc

    def _load_records(self,ref):
        if not isinstance(ref,str) or not PARSE_REF_RE.fullmatch(ref):raise BreakGlassError("invalid_parse_ref")
        dirfd=os.open(self.root/"parses",os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW)
        try:
            fd=os.open(f"{ref}.json",os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=dirfd)
            try:
                st=os.fstat(fd)
                if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or st.st_mode&0o077 or not 1<=st.st_size<=MAX_CACHE:raise BreakGlassError("invalid_parse_ref")
                raw=b""
                while len(raw)<st.st_size:
                    chunk=os.read(fd,min(65536,st.st_size-len(raw)))
                    if not chunk:break
                    raw+=chunk
            finally:os.close(fd)
        except OSError as exc:raise BreakGlassError("invalid_parse_ref") from exc
        finally:os.close(dirfd)
        try:
            envelope=json.loads(raw);records=envelope["records"];mac=envelope["cache_hmac"]
            encoded=json.dumps(records,ensure_ascii=False,separators=(",",":"),allow_nan=False).encode()
            expected=_b64(hmac.new(self.key,b"parse-cache-v1:"+encoded,hashlib.sha256).digest())
            if not isinstance(records,list) or not hmac.compare_digest(mac,expected):raise ValueError
            if not records or records[0].get("type")!="document" or records[-1].get("type")!="end":raise ValueError
            return records
        except Exception as exc:raise BreakGlassError("invalid_parse_ref") from exc

    def read(self,*,parse_ref=None,cursor=None,limit=20):
        if bool(parse_ref)==bool(cursor) or type(limit) is not int or not 1<=limit<=50:raise BreakGlassError("invalid_argument")
        ref,offset=(parse_ref,0) if parse_ref else self._decode_cursor(cursor)
        records=self._load_records(ref)
        if offset<0 or offset>=len(records):raise BreakGlassError("invalid_cursor" if cursor else "invalid_parse_ref")
        page=records[offset:offset+limit];following=offset+len(page)
        while page:
            payload={"success":True,"records":page,"cursor":self._cursor(ref,following) if following<len(records) else None}
            if len(json.dumps(payload,ensure_ascii=False,separators=(",",":"),allow_nan=False).encode())<=MAX_FRAME-64:return payload
            if len(page)==1:return {"success":False,"error":"output_limit"}
            page=page[:-1];following=offset+len(page)
        return {"success":False,"error":"invalid_parse_ref"}

    def handle(self,connection:socket.socket):
        fd=None
        try:
            pid,uid,gid=struct.unpack("3i",connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            if self.expected_uid is not None and uid!=self.expected_uid:raise BreakGlassError("unauthorized")
            request,fd=_recv_frame(connection,expect_fd=None)
            if len(json.dumps(request,separators=(",",":"),ensure_ascii=False).encode())>MAX_REQUEST_FRAME:raise BreakGlassError("invalid_request")
            command=request.get("command")
            if not isinstance(command,str) or command not in {"parse","read"}:raise BreakGlassError("invalid_request")
            expected=1 if command=="parse" else 0
            if int(fd is not None)!=expected:raise BreakGlassError("invalid_request")
            if set(request)-({"command","reason"} if command=="parse" else {"command","parse_ref","cursor","limit"}):raise BreakGlassError("invalid_request")
            if command=="parse":
                if fd is None:raise BreakGlassError("invalid_request")
                result=self.parse_fd(fd,reason=request.get("reason"))
            else:result=self.read(parse_ref=request.get("parse_ref"),cursor=request.get("cursor"),limit=request.get("limit",20))
        except BreakGlassError as exc:result={"success":False,"error":str(exc)}
        except Exception:result={"success":False,"error":"coordinator_failed"}
        finally:
            if fd is not None:
                try:os.close(fd)
                except OSError:pass
        try:_send_frame(connection,result)
        except Exception:
            try:_send_frame(connection,{"success":False,"error":"coordinator_failed"})
            except Exception:pass
        finally:
            try:connection.close()
            except OSError:pass


class CoordinatorClient:
    def __init__(self,socket_path="/run/omisa-breakglass.sock",timeout=190):self.socket_path=str(socket_path);self.timeout=timeout
    def request(self,value,fd=None):
        sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);sock.settimeout(self.timeout)
        try:
            sock.connect(self.socket_path);_send_frame(sock,value,fd);sock.shutdown(socket.SHUT_WR);result,_=_recv_frame(sock)
            return result
        except (OSError,socket.timeout) as exc:raise BreakGlassError("coordinator_unavailable") from exc
        finally:sock.close()


def cli(argv=None):
    p=argparse.ArgumentParser(prog="omisa-document-breakglass",allow_abbrev=False)
    sub=p.add_subparsers(dest="command",required=True)
    parse=sub.add_parser("parse",allow_abbrev=False);parse.add_argument("path",type=Path);parse.add_argument("--reason",required=True,choices=sorted(REASON_CODES))
    read=sub.add_parser("read",allow_abbrev=False);g=read.add_mutually_exclusive_group(required=True);g.add_argument("--parse-ref");g.add_argument("--cursor");read.add_argument("--limit",type=int,default=20)
    args=p.parse_args(argv);client=CoordinatorClient();fd=None
    try:
        if args.command=="parse":
            if args.path.is_symlink():raise BreakGlassError("symlink_not_allowed")
            fd=os.open(args.path,os.O_RDONLY|os.O_CLOEXEC|getattr(os,"O_NOFOLLOW",0));result=client.request({"command":"parse","reason":args.reason},fd)
        else:result=client.request({"command":"read","parse_ref":args.parse_ref,"cursor":args.cursor,"limit":args.limit})
    except BreakGlassError as exc:result={"success":False,"error":str(exc)}
    finally:
        if fd is not None:os.close(fd)
    print(json.dumps(result,ensure_ascii=False,separators=(",",":")));return 0 if result.get("success") else 2


def coordinator_main(argv=None):
    p=argparse.ArgumentParser(allow_abbrev=False);p.add_argument("--systemd-stdio",action="store_true",required=True);p.add_argument("--state-dir",type=Path,required=True);p.add_argument("--allowed-uid",type=int,required=True);p.add_argument("--parser-socket",required=True);args=p.parse_args(argv)
    connection=socket.socket(fileno=os.dup(0));BreakGlassCoordinator(args.state_dir,broker=UnixBroker(args.parser_socket),expected_uid=args.allowed_uid).handle(connection)


def main():raise SystemExit(cli())


if __name__=="__main__":main()
