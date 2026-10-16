from __future__ import annotations

import array
import json
import os
import socket
import threading
import zipfile
from pathlib import Path

import pytest

from omisa_parser.archive_service import ArchiveService, ArchiveConfig
from history_plugin.archive_broker import ArchiveClient, ArchiveBrokerError


def make_zip(path:Path,entries):
    with zipfile.ZipFile(path,"w",zipfile.ZIP_DEFLATED) as z:
        for name,data in entries:z.writestr(name,data)


def request(service,client,fd,operation,**kwargs):
    left,right=socket.socketpair();thread=threading.Thread(target=service.handle,args=(right,));thread.start()
    try:
        extra={}
        if operation=="extract" and "expected_archive_digest" not in kwargs:
            import hashlib
            h=hashlib.sha256();offset=0
            while chunk:=os.pread(fd,1024*1024,offset):h.update(chunk);offset+=len(chunk)
            extra["expected_archive_digest"]=h.hexdigest()
        return client.request_socket(left,fd=fd,operation=operation,**extra,**kwargs)
    finally:left.close();thread.join(timeout=5)


def test_real_service_inspect_and_extract_returns_opaque_manifest_and_readonly_fd(tmp_path):
    import pymupdf
    document=pymupdf.open();document.new_page().insert_text((72,72),"body");payload=document.tobytes();document.close()
    archive=tmp_path/"box.zip";make_zip(archive,[("docs/manual.pdf",payload),("notes/readme.txt",b"hello")])
    service=ArchiveService(ArchiveConfig(os.getuid(),tmp_path/"jobs"));client=ArchiveClient("unused")
    fd=os.open(archive,os.O_RDONLY)
    try:
        manifest=request(service,client,fd,"inspect")
        assert manifest["success"] and len(manifest["entries"])==2
        assert all("name" not in e and "path" not in e for e in manifest["entries"])
        assert manifest["entries"][0]["detected_format"]=="pdf"
        extracted=request(service,client,fd,"extract",entry_index=0,expected=manifest["entries"][0])
        out=extracted.pop("fd")
        try:
            assert os.pread(out,len(payload),0)==payload
            import fcntl
            assert fcntl.fcntl(out,fcntl.F_GETFL)&os.O_ACCMODE==os.O_RDONLY
        finally:os.close(out)
    finally:os.close(fd)


@pytest.mark.parametrize("name",["../escape.pdf","/abs.pdf","a\\b.pdf","C:/drive.pdf","a//b.pdf"])
def test_service_rejects_unsafe_paths(tmp_path,name):
    archive=tmp_path/"box.zip";make_zip(archive,[(name,b"%PDF-1.4\n%%EOF\n")])
    service=ArchiveService(ArchiveConfig(os.getuid(),tmp_path/"jobs"));client=ArchiveClient("unused");fd=os.open(archive,os.O_RDONLY)
    try:
        with pytest.raises(ArchiveBrokerError,match="archive_policy_violation"):request(service,client,fd,"inspect")
    finally:os.close(fd)


def test_directory_entry_and_its_child_are_not_a_prefix_collision(tmp_path):
    archive=tmp_path/"box.zip"
    with zipfile.ZipFile(archive,"w") as z:z.writestr("docs/",b"");z.writestr("docs/readme.txt",b"hello")
    service=ArchiveService(ArchiveConfig(os.getuid(),tmp_path/"jobs"));client=ArchiveClient("unused");fd=os.open(archive,os.O_RDONLY)
    try:assert request(service,client,fd,"inspect")["entry_count"]==2
    finally:os.close(fd)


def test_nested_archive_and_executable_are_ineligible_not_extracted(tmp_path):
    inner=tmp_path/"inner.zip";make_zip(inner,[("x.txt",b"x")])
    archive=tmp_path/"box.zip";make_zip(archive,[("nested.bin",inner.read_bytes()),("run.bin",b"MZ"+b"x"*20)])
    service=ArchiveService(ArchiveConfig(os.getuid(),tmp_path/"jobs"));client=ArchiveClient("unused");fd=os.open(archive,os.O_RDONLY)
    try:
        manifest=request(service,client,fd,"inspect")
        assert [(e["eligible"],e["reason"]) for e in manifest["entries"]]==[(False,"nested_container"),(False,"disallowed_content")]
        with pytest.raises(ArchiveBrokerError,match="entry_not_eligible"):request(service,client,fd,"extract",entry_index=0,expected=manifest["entries"][0])
    finally:os.close(fd)


def test_valid_small_json_and_xml_are_eligible(tmp_path):
    archive=tmp_path/"box.zip";make_zip(archive,[("a.json",b'{"a":1}'),("a.xml",b"<root><x>ok</x></root>")])
    service=ArchiveService(ArchiveConfig(os.getuid(),tmp_path/"jobs"));client=ArchiveClient("unused");fd=os.open(archive,os.O_RDONLY)
    try:entries=request(service,client,fd,"inspect")["entries"]
    finally:os.close(fd)
    assert [(e["detected_format"],e["eligible"]) for e in entries]==[("json",True),("xml",True)]


def test_valid_data_descriptor_zip_is_accepted_but_forged_descriptor_is_rejected(tmp_path):
    import io
    class Unseekable(io.BytesIO):
        def seekable(self):return False
        def seek(self,*args):raise io.UnsupportedOperation
    stream=Unseekable()
    with zipfile.ZipFile(stream,"w",zipfile.ZIP_DEFLATED) as z:z.writestr("x.txt",b"hello")
    archive=tmp_path/"box.zip";archive.write_bytes(stream.getvalue())
    service=ArchiveService(ArchiveConfig(os.getuid(),tmp_path/"jobs"));client=ArchiveClient("unused")
    fd=os.open(archive,os.O_RDONLY)
    try:assert request(service,client,fd,"inspect")["entries"][0]["eligible"] is True
    finally:os.close(fd)
    data=bytearray(archive.read_bytes());marker=data.find(b"PK\x07\x08");assert marker>0;data[marker+4]^=1;archive.write_bytes(data)
    fd=os.open(archive,os.O_RDONLY)
    try:
        with pytest.raises(ArchiveBrokerError,match="archive_policy_violation"):request(service,client,fd,"inspect")
    finally:os.close(fd)


def test_extract_requires_same_archive_digest_as_inspection(tmp_path):
    archive=tmp_path/"box.zip";make_zip(archive,[("x.txt",b"safe")])
    service=ArchiveService(ArchiveConfig(os.getuid(),tmp_path/"jobs"));client=ArchiveClient("unused");fd=os.open(archive,os.O_RDONLY)
    try:
        manifest=request(service,client,fd,"inspect")
        with pytest.raises(ArchiveBrokerError,match="archive_changed"):request(service,client,fd,"extract",entry_index=0,expected=manifest["entries"][0],expected_archive_digest="0"*64)
    finally:os.close(fd)


def test_pdf_name_hex_escapes_cannot_bypass_active_content_policy():
    from omisa_parser.archive_service import _classify
    base=(b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R/Open#41ction 4 0 R>>endobj\n"
          b"2 0 obj<</Type/Pages/Count 1/Kids[3 0 R]>>endobj\n3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 10 10]>>endobj\n"
          b"4 0 obj<</S/Java#53cript/J#53(app.alert)>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n")
    fmt,eligible,reason=_classify(base)
    assert fmt=="pdf" and eligible is False and reason=="malformed_document"


def test_pdf_object_stream_semantics_are_inspected():
    import pymupdf
    from omisa_parser.archive_service import _classify
    doc=pymupdf.open();page=doc.new_page();action=doc.get_new_xref();doc.update_object(action,"<</S/JavaScript/JS(app.alert)>>")
    page_xref=page.xref;doc.xref_set_key(page_xref,"AA",f"<</O {action} 0 R>>")
    data=doc.tobytes(use_objstms=1,garbage=4,clean=True);doc.close()
    assert _classify(data)==("pdf",False,"malformed_document")


def test_extract_revalidates_metadata_crc_and_archive_identity(tmp_path):
    archive=tmp_path/"box.zip";make_zip(archive,[("x.txt",b"safe")])
    service=ArchiveService(ArchiveConfig(os.getuid(),tmp_path/"jobs"));client=ArchiveClient("unused");fd=os.open(archive,os.O_RDONLY)
    try:
        manifest=request(service,client,fd,"inspect");expected=dict(manifest["entries"][0]);expected["size"]+=1
        with pytest.raises(ArchiveBrokerError,match="entry_changed"):request(service,client,fd,"extract",entry_index=0,expected=expected)
    finally:os.close(fd)
