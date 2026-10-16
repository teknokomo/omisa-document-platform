from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import socket
import stat
import tempfile
import unicodedata
import zipfile
from dataclasses import dataclass
from pathlib import PurePosixPath,Path

from .breakglass import _recv_frame,_send_frame

MAX_ARCHIVE=20*1024*1024;MAX_ENTRIES=200;MAX_MEMBER=20*1024*1024;MAX_TOTAL=80*1024*1024;MAX_RATIO=100;MAX_DEPTH=12

class ArchiveError(Exception):pass

@dataclass(frozen=True)
class ArchiveConfig:
    allowed_uid:int
    runtime_dir:Path


def _pdf_unescape_names(data):
    def decode(match):
        return b"/"+re.sub(br"#([0-9A-Fa-f]{2})",lambda m:bytes([int(m.group(1),16)]),match.group(1))
    return re.sub(br"/((?:#[0-9A-Fa-f]{2}|[^\x00\x09\x0a\x0c\x0d\x20()<>\[\]{}/%])+)",decode,data)


def _pdf_has_active_semantics(data):
    import pymupdf
    active=re.compile(r"/(?:AA|JavaScript|JS|OpenAction|Launch|EmbeddedFile)\b")
    with pymupdf.open(stream=data,filetype="pdf") as doc:
        if doc.page_count<1:return True
        for xref in range(1,doc.xref_length()):
            try:text=doc.xref_object(xref,compressed=False)
            except Exception:return True
            if active.search(text):return True
    return False


def _classify(data):
    head=data[:8192];lower=data.lower()
    if head.startswith((b"PK\x03\x04",b"PK\x05\x06",b"Rar!",b"7z\xbc\xaf\x27\x1c",b"\x1f\x8b")):return "archive",False,"nested_container"
    if head.startswith(b"%PDF-"):
        names=_pdf_unescape_names(data)
        if any(x in names for x in (b"/JavaScript",b"/JS",b"/OpenAction",b"/Launch",b"/EmbeddedFile")) or not re.search(br"%%EOF\s*$",data):return "pdf",False,"malformed_document"
        try:
            import pymupdf
            with pymupdf.open(stream=data,filetype="pdf") as doc:
                if doc.page_count<1 or _pdf_has_active_semantics(data):return "pdf",False,"malformed_document"
        except Exception:return "pdf",False,"malformed_document"
        return "pdf",True,None
    if head.startswith(b"{\\rtf"):return "rtf",True,None
    if head.startswith((b"MZ",b"\x7fELF")):return "executable",False,"disallowed_content"
    if b"\x00" in data:return "binary",False,"unsupported_format"
    try:text=data.decode("utf-8-sig")
    except UnicodeDecodeError:return "binary",False,"unsupported_format"
    s=text.lstrip();sl=s.lower()
    active=("<!doctype","<!entity","<html","<svg","<script","javascript:","fetch(","xmlhttprequest","#!/bin/","#!/usr/bin/")
    if any(x in sl for x in active):return "active_content",False,"disallowed_content"
    if s.startswith("<"):
        try:
            from defusedxml import ElementTree as SafeET
            SafeET.fromstring(data)
        except Exception:return "xml",False,"malformed_document"
        return "xml",True,None
    if s.startswith(("{","[")):
        try:json.loads(text)
        except Exception:return "json",False,"malformed_document"
        return "json",True,None
    if "\n" in text and any(x in text.splitlines()[0] for x in (",","\t",";")):return "csv",True,None
    if any(line.startswith("# ") for line in text.splitlines()):return "md",True,None
    return "txt",True,None


def _infos(z):
    infos=z.infolist();total=compressed=metadata=0;names=set();paths=set()
    if not infos or len(infos)>MAX_ENTRIES:raise ArchiveError("archive_policy_violation")
    for info in infos:
        name=unicodedata.normalize("NFC",info.filename);p=PurePosixPath(name);parts=p.parts;mode=(info.external_attr>>16)&0xffff
        raw=z.fp
        raw.seek(info.header_offset);local=raw.read(30)
        if len(local)!=30 or local[:4]!=b"PK\x03\x04":raise ArchiveError("archive_policy_violation")
        import struct
        _sig,_ver,local_flags,local_method,_time,_date,local_crc,local_comp,local_size,name_len,extra_len=struct.unpack("<IHHHHHIIIHH",local)
        local_name=raw.read(name_len);local_extra=raw.read(extra_len)
        if (local_flags&1 or local_method!=info.compress_type
                or (not local_flags&8 and (local_crc!=info.CRC or local_comp!=info.compress_size or local_size!=info.file_size))
                or local_name!=info.orig_filename.encode("utf-8" if info.flag_bits&0x800 else "cp437") or b"\x01\x00" in local_extra or b"\x01\x00" in info.extra):raise ArchiveError("archive_policy_violation")
        if local_flags&8:
            descriptor_offset=info.header_offset+30+name_len+extra_len+info.compress_size
            raw.seek(descriptor_offset);descriptor=raw.read(16)
            if descriptor[:4]==b"PK\x07\x08":descriptor=descriptor[4:]
            if len(descriptor)<12 or struct.unpack("<III",descriptor[:12])!=(info.CRC,info.compress_size,info.file_size):raise ArchiveError("archive_policy_violation")
        metadata+=len(name.encode("utf-8"))+len(info.extra)+len(info.comment)
        if (not name or "\\" in name or name.startswith(("/","//")) or re.match(r"^[A-Za-z]:",name) or len(parts)>MAX_DEPTH
                or "//" in name.rstrip("/") or any(x in {".",".."} for x in name.rstrip("/").split("/")) or len(parts)>MAX_DEPTH
                or any(ord(c)<32 or unicodedata.category(c)=="Cf" for c in name)
                or (not info.is_dir() and any(x.endswith((" ",".")) for x in parts)) or len(name.encode())>512 or info.flag_bits&1
                or mode and stat.S_IFMT(mode) not in {0,stat.S_IFREG,stat.S_IFDIR}
                or info.compress_type not in {zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED}):raise ArchiveError("archive_policy_violation")
        folded=name.casefold()
        if folded in names:raise ArchiveError("archive_policy_violation")
        for prior,prior_is_dir in paths:
            if (folded.startswith(prior.rstrip("/")+"/") and not prior_is_dir) or (prior.startswith(folded.rstrip("/")+"/") and not info.is_dir()):raise ArchiveError("archive_policy_violation")
        names.add(folded);paths.add((folded,info.is_dir()));total+=info.file_size;compressed+=info.compress_size
        if info.file_size>MAX_MEMBER or info.file_size/max(1,info.compress_size)>MAX_RATIO:raise ArchiveError("archive_policy_violation")
    if total>MAX_TOTAL or total/max(1,compressed)>MAX_RATIO or metadata>256*1024:raise ArchiveError("archive_policy_violation")
    return infos


def _entry(info,index,z):
    if info.is_dir():fmt,eligible,reason="directory",False,"directory"
    else:
        with z.open(info) as source:
            h=hashlib.sha256();data=bytearray();actual=0
            while chunk:=source.read(min(1024*1024,MAX_MEMBER+1-actual)):
                actual+=len(chunk)
                if actual>MAX_MEMBER:raise ArchiveError("archive_policy_violation")
                data.extend(chunk);h.update(chunk)
        if actual!=info.file_size:raise ArchiveError("malformed_archive")
        fmt,eligible,reason=_classify(bytes(data))
    return {"index":index,"size":info.file_size,"compressed_size":info.compress_size,"crc32":info.CRC,"method":info.compress_type,
            "detected_format":fmt,"eligible":eligible,"reason":reason}


class ArchiveService:
    def __init__(self,config):self.config=config
    def _snapshot(self,source_fd):
        if fcntl.fcntl(source_fd,fcntl.F_GETFL)&os.O_ACCMODE!=os.O_RDONLY:raise ArchiveError("invalid_request")
        st=os.fstat(source_fd)
        if not stat.S_ISREG(st.st_mode) or not 1<=st.st_size<=MAX_ARCHIVE:raise ArchiveError("archive_policy_violation")
        self.config.runtime_dir.mkdir(parents=True,exist_ok=True,mode=0o700)
        fd,name=tempfile.mkstemp(dir=self.config.runtime_dir);h=hashlib.sha256()
        try:
            offset=0
            while offset<st.st_size:
                chunk=os.pread(source_fd,min(1024*1024,st.st_size-offset),offset)
                if not chunk:raise ArchiveError("archive_changed")
                h.update(chunk);view=memoryview(chunk)
                while view:view=view[os.write(fd,view):]
                offset+=len(chunk)
            os.fsync(fd);readonly=os.open(name,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW);os.unlink(name);os.close(fd)
            return readonly,st.st_size,h.hexdigest()
        except Exception:
            os.close(fd)
            try:os.unlink(name)
            except OSError:pass
            raise
    def _inspect(self,path):
        import struct
        data=Path(path).read_bytes();eocd=data.rfind(b"PK\x05\x06")
        if eocd<0 or eocd+22>len(data):raise ArchiveError("malformed_archive")
        disk,cd_disk,disk_entries,total_entries,cd_size,cd_offset,comment_len=struct.unpack_from("<HHHHIIH",data,eocd+4)
        if disk or cd_disk or disk_entries!=total_entries or eocd+22+comment_len!=len(data) or cd_offset+cd_size!=eocd:
            raise ArchiveError("archive_policy_violation")
        if b"PK\x06\x06" in data[max(0,eocd-128):eocd] or b"PK\x06\x07" in data[max(0,eocd-128):eocd]:raise ArchiveError("archive_policy_violation")
        try:
            with zipfile.ZipFile(path) as z:
                infos=_infos(z);entries=[_entry(info,i,z) for i,info in enumerate(infos)]
                bad=z.testzip()
                if bad is not None:raise ArchiveError("malformed_archive")
                return entries
        except ArchiveError:raise
        except (zipfile.BadZipFile,RuntimeError,OSError,EOFError):raise ArchiveError("malformed_archive")
    def handle(self,connection):
        fd=snapshot=out=None
        try:
            pid,uid,gid=__import__('struct').unpack("3i",connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            if uid!=self.config.allowed_uid:raise ArchiveError("unauthorized")
            request,fd=_recv_frame(connection,expect_fd=True);operation=request.get("operation")
            if operation not in {"inspect","extract"}:raise ArchiveError("invalid_request")
            snapshot,size,digest=self._snapshot(fd);path=f"/proc/self/fd/{snapshot}"
            entries=self._inspect(path)
            if operation=="inspect":result={"success":True,"archive_digest":digest,"entries":entries,"entry_count":len(entries),"total_uncompressed":sum(x["size"] for x in entries)}
            else:
                if request.get("expected_archive_digest")!=digest:raise ArchiveError("archive_changed")
                index=request.get("entry_index");expected=request.get("expected")
                if type(index) is not int or not 0<=index<len(entries) or not isinstance(expected,dict):raise ArchiveError("invalid_request")
                entry=entries[index]
                if any(expected.get(k)!=entry.get(k) for k in ("index","size","compressed_size","crc32","method","detected_format","eligible","reason")):raise ArchiveError("entry_changed")
                if not entry["eligible"]:raise ArchiveError("entry_not_eligible")
                output_fd,output_name=tempfile.mkstemp(prefix="entry-",dir=self.config.runtime_dir);h=hashlib.sha256();written=0
                try:
                    with zipfile.ZipFile(path) as z, z.open(z.infolist()[index]) as source:
                        while chunk:=source.read(min(1024*1024,MAX_MEMBER+1-written)):
                            written+=len(chunk)
                            if written>MAX_MEMBER:raise ArchiveError("archive_policy_violation")
                            h.update(chunk);view=memoryview(chunk)
                            while view:view=view[os.write(output_fd,view):]
                    if written!=entry["size"]:raise ArchiveError("entry_changed")
                    os.fsync(output_fd)
                    out=os.open(output_name,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
                    os.unlink(output_name);os.close(output_fd);output_fd=None
                finally:
                    if output_fd is not None:os.close(output_fd)
                    try:os.unlink(output_name)
                    except FileNotFoundError:pass
                result={"success":True,"size":written,"sha256":h.hexdigest(),"detected_format":entry["detected_format"]}
            _send_frame(connection,result,out)
        except ArchiveError as exc:_send_frame(connection,{"success":False,"error":str(exc)})
        except Exception:
            try:_send_frame(connection,{"success":False,"error":"archive_failed"})
            except Exception:pass
        finally:
            for item in (fd,snapshot,out):
                if item is not None:
                    try:os.close(item)
                    except OSError:pass
            try:connection.close()
            except OSError:pass
