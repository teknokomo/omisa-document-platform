from __future__ import annotations

import array
import json
import os
import socket
import struct
from pathlib import Path

MAX_FRAME=64*1024


class ArchiveBrokerError(Exception):pass


def _send(sock,value,fd=None):
    raw=json.dumps(value,sort_keys=True,separators=(",",":")).encode();wire=struct.pack("!I",len(raw))+raw
    anc=[] if fd is None else [(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array("i",[fd]))]
    if sock.sendmsg([wire],anc)!=len(wire):raise ArchiveBrokerError("broker_disconnect")

def _exact(sock,n):
    out=b""
    while len(out)<n:
        data=sock.recv(n-len(out))
        if not data:raise ArchiveBrokerError("broker_disconnect")
        out+=data
    return out

def _recv(sock,expect_fd=None):
    ancsize=socket.CMSG_SPACE(array.array("i",[0]).itemsize);prefix=b"";fds=[]
    while len(prefix)<4:
        data,anc,flags,_=sock.recvmsg(4-len(prefix),ancsize)
        if not data or flags&(socket.MSG_TRUNC|socket.MSG_CTRUNC):raise ArchiveBrokerError("malformed_response")
        prefix+=data
        for level,kind,payload in anc:
            if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:
                values=array.array("i");values.frombytes(payload[:len(payload)-(len(payload)%values.itemsize)]);fds.extend(values)
    size=struct.unpack("!I",prefix)[0]
    if not 1<=size<=MAX_FRAME or len(fds)>1 or (expect_fd is not None and len(fds)!=(1 if expect_fd else 0)):
        for fd in fds:os.close(fd)
        raise ArchiveBrokerError("malformed_response")
    try:value=json.loads(_exact(sock,size))
    except Exception:
        for fd in fds:os.close(fd)
        raise ArchiveBrokerError("malformed_response")
    return value,(fds[0] if fds else None)


class ArchiveClient:
    def __init__(self,socket_path="/run/omisa-archive/archive.sock",timeout=30):self.socket_path=str(socket_path);self.timeout=timeout
    def request_socket(self,sock,fd,operation,**kwargs):
        request={"operation":operation,**kwargs}
        raw=json.dumps(request,sort_keys=True,separators=(",",":")).encode()
        if len(raw)>MAX_FRAME:raise ArchiveBrokerError("invalid_request")
        _send(sock,request,fd);sock.shutdown(socket.SHUT_WR)
        response,out=_recv(sock,expect_fd=None)
        if not response.get("success"):
            if out is not None:os.close(out)
            raise ArchiveBrokerError(response.get("error","archive_failed"))
        if operation=="inspect" and out is not None:
            os.close(out);raise ArchiveBrokerError("malformed_response")
        if operation=="extract" and out is None:raise ArchiveBrokerError("malformed_response")
        if out is not None:response["fd"]=out
        return response
    def inspect_fd(self,fd):
        sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);sock.settimeout(self.timeout)
        try:sock.connect(self.socket_path);return self.request_socket(sock,fd=fd,operation="inspect")
        except OSError as exc:raise ArchiveBrokerError("broker_unavailable") from exc
        finally:sock.close()
    def extract_fd(self,fd,*,entry_index,expected,expected_archive_digest):
        sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);sock.settimeout(self.timeout)
        try:sock.connect(self.socket_path);return self.request_socket(sock,fd=fd,operation="extract",entry_index=entry_index,expected=expected,expected_archive_digest=expected_archive_digest)
        except OSError as exc:raise ArchiveBrokerError("broker_unavailable") from exc
        finally:sock.close()
