from __future__ import annotations

import array
import fcntl
import hashlib
import hmac as hmac_mod
import json
import os
import socket
import threading
from pathlib import Path

import pytest

from omisa_parser.breakglass import BreakGlassCoordinator, BreakGlassError
from omisa_parser.archive_breakglass import ArchiveBreakGlassCoordinator, TTL


class Broker:
    def __init__(self): self.calls=[]
    def parse_fd(self,fd,*,artifact_ref,expected_size,options):
        data=os.pread(fd,expected_size,0);self.calls.append((data,artifact_ref,dict(options)))
        rid=f"{len(self.calls):032x}"
        return [
            {"schema":"omisa.document/1","type":"document","request_id":rid,"document":{"detected_format":"txt","media_type":"text/plain","size_bytes":expected_size,"title":None,"language":None},"parser":{"bundle_version":"test","registry_version":1},"structure":{"unit":"page","unit_count":1,"pagination":"logical"},"warnings":[]},
            {"schema":"omisa.document/1","type":"unit","id":"u1","unit_kind":"page","index":1,"label":"1","parent_id":None},
            {"schema":"omisa.document/1","type":"text","id":"b1","unit_id":"u1","order":1,"text":data.decode(),"source":"native","truncated":False},
            {"schema":"omisa.document/1","type":"end","request_id":rid,"status":"ok","counts":{"units_emitted":1,"records_emitted":4,"text_chars":len(data.decode()),"tables":0,"cells":0},"truncated":False,"limit_reason":None,"warnings":[]},
        ]


def coordinator(tmp_path,broker=None):
    return BreakGlassCoordinator(tmp_path/"state",broker=broker or Broker(),now=lambda:1700000000,expected_uid=os.getuid())


def test_parse_snapshots_exact_fd_and_creates_path_free_signed_receipt(tmp_path):
    source=tmp_path/"secret-name.dat";source.write_text("payload")
    broker=Broker();service=coordinator(tmp_path,broker)
    fd=os.open(source,os.O_RDONLY|os.O_CLOEXEC)
    try:result=service.parse_fd(fd,reason="explicit_user_request")
    finally:os.close(fd)
    assert result["success"] and broker.calls[0][0]==b"payload"
    receipt=json.loads((tmp_path/"state"/"receipts"/f'{result["receipt_id"]}.json').read_text())
    raw=json.dumps(receipt)
    assert str(source) not in raw and source.name not in raw and "payload" not in raw
    assert receipt["status"]=="success" and receipt["input_sha256"] and receipt["receipt_hmac"]
    page=service.read(parse_ref=result["parse_ref"],limit=2)
    final=service.read(cursor=page["cursor"],limit=10)
    assert final["cursor"] is None


def test_snapshot_fd_given_to_broker_is_read_only_and_immutable(tmp_path):
    source=tmp_path/"x";source.write_bytes(b"A")
    class MutatingBroker(Broker):
        def parse_fd(self,fd,**kwargs):
            assert fcntl.fcntl(fd,fcntl.F_GETFL)&os.O_ACCMODE==os.O_RDONLY
            with pytest.raises(OSError):os.pwrite(fd,b"B",0)
            return super().parse_fd(fd,**kwargs)
    service=coordinator(tmp_path,MutatingBroker());fd=os.open(source,os.O_RDONLY)
    try:result=service.parse_fd(fd,reason="explicit_user_request")
    finally:os.close(fd)
    assert result["success"]


def test_writable_source_fd_is_rejected_and_receipted(tmp_path):
    source=tmp_path/"x";source.write_bytes(b"A");service=coordinator(tmp_path)
    fd=os.open(source,os.O_RDWR)
    try:
        with pytest.raises(BreakGlassError,match="writable_fd_not_allowed"):service.parse_fd(fd,reason="explicit_user_request")
    finally:os.close(fd)
    receipt=json.loads(next((tmp_path/"state"/"receipts").glob("*.json")).read_text())
    assert receipt["status"]=="denied" and receipt["error"]=="writable_fd_not_allowed"


def test_snapshot_prevents_source_mutation_from_changing_parsed_bytes(tmp_path):
    source=tmp_path/"x";source.write_bytes(b"A")
    class MutatingBroker(Broker):
        def parse_fd(self,fd,**kwargs):
            source.write_bytes(b"B")
            return super().parse_fd(fd,**kwargs)
    service=coordinator(tmp_path,MutatingBroker());fd=os.open(source,os.O_RDONLY)
    try:result=service.parse_fd(fd,reason="explicit_user_request")
    finally:os.close(fd)
    assert result["success"]
    assert service.read(parse_ref=result["parse_ref"],limit=10)["records"][2]["text"]=="A"


def test_invalid_reason_and_broker_failure_are_receipted_categorically(tmp_path):
    source=tmp_path/"x";source.write_text("x");service=coordinator(tmp_path)
    fd=os.open(source,os.O_RDONLY)
    try:
        with pytest.raises(BreakGlassError,match="invalid_reason"):service.parse_fd(fd,reason="review /etc/passwd")
    finally:os.close(fd)
    class Broken:
        def parse_fd(self,*a,**k):raise RuntimeError("secret detail")
    service=BreakGlassCoordinator(tmp_path/"other",broker=Broken(),now=lambda:1700000000,expected_uid=os.getuid())
    fd=os.open(source,os.O_RDONLY)
    try:
        with pytest.raises(BreakGlassError,match="broker_failed"):service.parse_fd(fd,reason="explicit_user_request")
    finally:os.close(fd)
    receipts=list((tmp_path/"state"/"receipts").glob("*.json"))+list((tmp_path/"other"/"receipts").glob("*.json"))
    assert len(receipts)==2 and "secret detail" not in "".join(p.read_text() for p in receipts)


def test_parse_ref_traversal_cursor_tamper_and_negative_offsets_are_rejected(tmp_path):
    service=coordinator(tmp_path)
    with pytest.raises(BreakGlassError,match="invalid_parse_ref"):service.read(parse_ref="bgp_v1_/../../loot")
    with pytest.raises(BreakGlassError,match="invalid_cursor"):service.read(cursor="bgc_v1_bad")
    forged=service._cursor("bgp_v1_"+"A"*32,-1)
    with pytest.raises(BreakGlassError,match="invalid_cursor"):service.read(cursor=forged)


def test_state_tree_and_key_symlinks_are_rejected(tmp_path):
    outside=tmp_path/"outside";outside.mkdir();root=tmp_path/"state";root.symlink_to(outside,target_is_directory=True)
    with pytest.raises(BreakGlassError,match="unsafe_state"):BreakGlassCoordinator(root,broker=Broker(),expected_uid=os.getuid())


def test_malformed_command_types_get_categorical_response(tmp_path):
    from omisa_parser.breakglass import _send_frame,_recv_frame
    for command in ([],{},None,7):
        service=coordinator(tmp_path/str(len(str(command))));server,client=socket.socketpair();thread=threading.Thread(target=service.handle,args=(server,));thread.start()
        try:_send_frame(client,{"command":command});client.shutdown(socket.SHUT_WR);result,_=_recv_frame(client)
        finally:client.close();thread.join(timeout=2)
        assert not thread.is_alive() and result=={"success":False,"error":"invalid_request"}


def test_fragmented_prefix_and_malformed_reason_get_categorical_response(tmp_path):
    from omisa_parser.breakglass import _recv_frame
    service=coordinator(tmp_path);source=tmp_path/"x";source.write_text("x")
    server,client=socket.socketpair();thread=threading.Thread(target=service.handle,args=(server,));thread.start()
    payload=json.dumps({"command":"parse","reason":[]},separators=(",",":")).encode();wire=len(payload).to_bytes(4,"big")+payload
    fd=os.open(source,os.O_RDONLY)
    try:
        client.sendmsg([wire[:2]],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array("i",[fd]))]);client.sendall(wire[2:]);client.shutdown(socket.SHUT_WR)
        result,_=_recv_frame(client)
    finally:os.close(fd);client.close();thread.join(timeout=2)
    assert not thread.is_alive()
    assert result=={"success":False,"error":"invalid_reason"}


def test_socketpair_coordinator_receives_one_read_only_fd(tmp_path):
    from omisa_parser.breakglass import CoordinatorClient
    source=tmp_path/"x";source.write_text("wire")
    service=coordinator(tmp_path);server,client_sock=socket.socketpair()
    thread=threading.Thread(target=service.handle,args=(server,));thread.start()
    class PairClient(CoordinatorClient):
        def request(self,value,fd=None):
            from omisa_parser.breakglass import _send_frame,_recv_frame
            _send_frame(client_sock,value,fd);client_sock.shutdown(socket.SHUT_WR);result,_=_recv_frame(client_sock);return result
    fd=os.open(source,os.O_RDONLY)
    try:result=PairClient().request({"command":"parse","reason":"explicit_user_request"},fd)
    finally:os.close(fd);client_sock.close();thread.join()
    assert result["success"] and result["detected_format"]=="txt"


def test_coordinator_closes_unexpected_fd_on_invalid_command(tmp_path):
    from omisa_parser.breakglass import _send_frame,_recv_frame
    service=coordinator(tmp_path);source=tmp_path/"x";source.write_text("x")
    before=len(os.listdir("/proc/self/fd"))
    for _ in range(20):
        server,client=socket.socketpair();thread=threading.Thread(target=service.handle,args=(server,));thread.start();fd=os.open(source,os.O_RDONLY)
        try:_send_frame(client,{"command":"read","parse_ref":"bgp_v1_"+"A"*32},fd);client.shutdown(socket.SHUT_WR);result,_=_recv_frame(client)
        finally:os.close(fd);client.close();thread.join(timeout=2)
        assert result=={"success":False,"error":"invalid_request"}
    assert len(os.listdir("/proc/self/fd"))==before


def test_cache_tampering_is_detected(tmp_path):
    source=tmp_path/"x";source.write_text("x");service=coordinator(tmp_path);fd=os.open(source,os.O_RDONLY)
    try:result=service.parse_fd(fd,reason="explicit_user_request")
    finally:os.close(fd)
    cache=tmp_path/"state"/"parses"/f'{result["parse_ref"]}.json';cache.write_text('{}')
    with pytest.raises(BreakGlassError,match="invalid_parse_ref"):service.read(parse_ref=result["parse_ref"])


class ArchiveBroker:
    def __init__(self):self.calls=[]
    def request(self,request,fd,expect_fd=False):
        data=os.pread(fd,1<<20,0);self.calls.append((dict(request),data))
        entry={"index":0,"size":7,"compressed_size":7,"crc32":1,"method":0,"detected_format":"txt","eligible":True,"reason":None}
        if request["operation"]=="inspect":
            import hashlib
            return {"success":True,"archive_digest":hashlib.sha256(data).hexdigest(),"entries":[entry],"entry_count":1,"total_uncompressed":7},None
        fd,path=__import__('tempfile').mkstemp();os.write(fd,b"payload");os.fsync(fd);os.close(fd);readfd=os.open(path,os.O_RDONLY|os.O_CLOEXEC);os.unlink(path)
        import hashlib
        return {"success":True,"size":7,"sha256":hashlib.sha256(b"payload").hexdigest(),"detected_format":"txt"},readfd


def archive_coordinator(tmp_path,archive_broker=None):
    return ArchiveBreakGlassCoordinator(tmp_path/"archive-state",broker=Broker(),archive_broker=archive_broker or ArchiveBroker(),now=lambda:1700000000,expected_uid=os.getuid())


def test_local_archive_breakglass_inspect_extract_parse_and_read(tmp_path):
    source=tmp_path/"private-name.zip";source.write_bytes(b"PK\x03\x04fixture")
    service=archive_coordinator(tmp_path);fd=os.open(source,os.O_RDONLY|os.O_CLOEXEC)
    try:manifest=service.inspect_fd(fd,"archive_review")
    finally:os.close(fd)
    raw=json.dumps(manifest)
    assert manifest["success"] and str(source) not in raw and source.name not in raw
    assert "crc32" not in manifest["entries"][0] and manifest["entries"][0]["eligible"]
    result=service.extract(manifest["entries"][0]["entry_ref"])
    assert result["success"] and result["detected_format"]=="txt"
    assert result["receipt_id"]!=result["parse_receipt_id"]
    page=service.read(parse_ref=result["parse_ref"],limit=2)
    while page["cursor"] is not None:page=service.read(cursor=page["cursor"],limit=2)
    assert page["cursor"] is None
    with pytest.raises(BreakGlassError,match="entry_ref_used"):service.extract(manifest["entries"][0]["entry_ref"])
    receipts=[json.loads(p.read_text()) for p in (tmp_path/"archive-state"/"receipts").glob("*.json")]
    assert {x["event"] for x in receipts}>={"break_glass_archive_inspect","break_glass_archive_extract","break_glass_parse"}
    assert all(str(source) not in json.dumps(x) and source.name not in json.dumps(x) and "payload" not in json.dumps(x) for x in receipts)


def test_archive_breakglass_writable_fd_tamper_expiry_and_transient_retry(tmp_path):
    source=tmp_path/"x.zip";source.write_bytes(b"PK\x03\x04fixture")
    service=archive_coordinator(tmp_path);fd=os.open(source,os.O_RDWR)
    try:
        with pytest.raises(BreakGlassError,match="writable_fd_not_allowed"):service.inspect_fd(fd,"archive_review")
    finally:os.close(fd)
    fd=os.open(source,os.O_RDONLY)
    try:manifest=service.inspect_fd(fd,"archive_review")
    finally:os.close(fd)
    entry=manifest["entries"][0]["entry_ref"]
    class Flaky(ArchiveBroker):
        def __init__(self):super().__init__();self.failed=False
        def request(self,request,fd,expect_fd=False):
            if request["operation"]=="extract" and not self.failed:self.failed=True;raise BreakGlassError("archive_broker_unavailable")
            return super().request(request,fd,expect_fd)
    service.archive_broker=Flaky()
    with pytest.raises(BreakGlassError,match="archive_broker_unavailable"):service.extract(entry)
    assert service.extract(entry)["success"]
    cap=tmp_path/"archive-state"/"entries"/(entry+".json");cap.write_text('{}')
    with pytest.raises(BreakGlassError,match="entry_ref_used"):service.extract(entry)


def test_local_archive_breakglass_drives_real_archive_service(tmp_path):
    import hashlib,zipfile
    from omisa_parser.archive_service import ArchiveService,ArchiveConfig
    from omisa_parser.archive_breakglass import UnixArchiveBroker
    source=tmp_path/"real.zip"
    with zipfile.ZipFile(source,"w",zipfile.ZIP_STORED) as z:z.writestr("hidden-name.txt","payload")
    class SocketpairArchiveBroker:
        def request(self,request,fd,expect_fd=False):
            server,client=socket.socketpair();thread=threading.Thread(target=ArchiveService(ArchiveConfig(os.getuid(),tmp_path/"jobs")).handle,args=(server,));thread.start()
            class Client(UnixArchiveBroker):
                def request(self,request,fd,expect_fd=False):
                    from omisa_parser.breakglass import _send_frame,_recv_frame
                    _send_frame(client,request,fd);client.shutdown(socket.SHUT_WR);result,out=_recv_frame(client,expect_fd=None)
                    if not result.get("success"):raise BreakGlassError(result["error"])
                    assert bool(out is not None)==expect_fd
                    return result,out
            try:return Client().request(request,fd,expect_fd)
            finally:client.close();thread.join(timeout=5);assert not thread.is_alive()
    service=archive_coordinator(tmp_path,SocketpairArchiveBroker());fd=os.open(source,os.O_RDONLY)
    try:manifest=service.inspect_fd(fd,"archive_review")
    finally:os.close(fd)
    assert manifest["entry_count"]==1 and manifest["entries"][0]["detected_format"]=="txt"
    assert "hidden-name" not in json.dumps(manifest)
    result=service.extract(manifest["entries"][0]["entry_ref"])
    assert result["success"] and service.read(parse_ref=result["parse_ref"],limit=50)["cursor"] is None


def test_receipt_write_failure_removes_orphan_cache_and_raises_categorical(tmp_path):
    source=tmp_path/"x";source.write_text("x")
    service=coordinator(tmp_path);original=service._exclusive_write
    def failing(directory,name,data):
        if directory=="receipts":raise OSError("ENOSPC")
        return original(directory,name,data)
    service._exclusive_write=failing
    fd=os.open(source,os.O_RDONLY)
    try:
        with pytest.raises(BreakGlassError,match="receipt_failed"):service.parse_fd(fd,reason="explicit_user_request")
    finally:os.close(fd)
    assert list((tmp_path/"state"/"parses").glob("*.json"))==[]


def test_read_page_exceeding_max_frame_shrinks_and_oversized_single_record_errors(tmp_path):
    from omisa_parser.breakglass import _b64
    service=coordinator(tmp_path);ref="bgp_v1_"+"A"*32;text="x"*100000
    records=[
        {"schema":"omisa.document/1","type":"document","request_id":"0"*32,"document":{"detected_format":"txt"},"parser":{"bundle_version":"t","registry_version":1},"structure":{"unit":"page","unit_count":1,"pagination":"logical"},"warnings":[]},
        {"schema":"omisa.document/1","type":"text","id":"b1","unit_id":"u1","order":1,"text":text,"source":"native","truncated":False},
        {"schema":"omisa.document/1","type":"end","request_id":"0"*32,"status":"ok","counts":{},"truncated":False,"limit_reason":None,"warnings":[]},
    ]
    encoded=json.dumps(records,ensure_ascii=False,separators=(",",":"),allow_nan=False).encode()
    mac=_b64(hmac_mod.new(service.key,b"parse-cache-v1:"+encoded,hashlib.sha256).digest())
    envelope=json.dumps({"records":records,"cache_hmac":mac},ensure_ascii=False,separators=(",",":"),allow_nan=False).encode()
    service._exclusive_write("parses",f"{ref}.json",envelope)
    page=service.read(parse_ref=ref,limit=50)
    assert page["success"] and page["cursor"] is not None
    assert service.read(cursor=page["cursor"],limit=50)=={"success":False,"error":"output_limit"}


def test_archive_extract_used_marker_failure_rolls_back_parse_cache(tmp_path):
    source=tmp_path/"x.zip";source.write_bytes(b"PK\x03\x04fixture")
    service=archive_coordinator(tmp_path);fd=os.open(source,os.O_RDONLY)
    try:manifest=service.inspect_fd(fd,"archive_review")
    finally:os.close(fd)
    entry=manifest["entries"][0]["entry_ref"];original=service._exclusive_write;state={"fail":True}
    def failing(directory,name,data):
        if state["fail"] and directory=="entries" and name.endswith(".used"):raise OSError("ENOSPC")
        return original(directory,name,data)
    service._exclusive_write=failing
    with pytest.raises(BreakGlassError,match="receipt_failed"):service.extract(entry)
    assert list((tmp_path/"archive-state"/"parses").glob("*.json"))==[]
    state["fail"]=False
    assert service.extract(entry)["success"]


def test_archive_extract_receipt_failure_rolls_back_success_and_allows_retry(tmp_path):
    source=tmp_path/"x.zip";source.write_bytes(b"PK\x03\x04fixture")
    service=archive_coordinator(tmp_path);fd=os.open(source,os.O_RDONLY)
    try:manifest=service.inspect_fd(fd,"archive_review")
    finally:os.close(fd)
    entry=manifest["entries"][0]["entry_ref"];original=service._exclusive_write;state={"receipt_writes":0,"fail":True}
    def failing(directory,name,data):
        if directory=="receipts":
            state["receipt_writes"]+=1
            if state["fail"] and state["receipt_writes"]==2:raise OSError("ENOSPC")
        return original(directory,name,data)
    service._exclusive_write=failing
    with pytest.raises(BreakGlassError,match="receipt_failed"):service.extract(entry)
    assert not (tmp_path/"archive-state"/"entries"/(entry+".used")).exists()
    assert not (tmp_path/"archive-state"/"entries"/(entry+".claim")).exists()
    assert list((tmp_path/"archive-state"/"parses").glob("*.json"))==[]
    state["fail"]=False
    assert service.extract(entry)["success"]


def test_archive_error_receipt_preserves_original_reason(tmp_path):
    source=tmp_path/"x.zip";source.write_bytes(b"PK\x03\x04fixture")
    service=archive_coordinator(tmp_path);fd=os.open(source,os.O_RDONLY)
    try:manifest=service.inspect_fd(fd,"explicit_user_request")
    finally:os.close(fd)
    class Refusing(ArchiveBroker):
        def request(self,request,fd,expect_fd=False):
            if request["operation"]=="extract":raise BreakGlassError("entry_not_eligible")
            return super().request(request,fd,expect_fd)
    service.archive_broker=Refusing()
    with pytest.raises(BreakGlassError,match="entry_not_eligible"):service.extract(manifest["entries"][0]["entry_ref"])
    receipts=list((tmp_path/"archive-state"/"receipts").glob("*.json"))
    matches=[json.loads(p.read_text()) for p in receipts if json.loads(p.read_text()).get("event")=="break_glass_archive_extract"]
    assert matches
    err=matches[-1]
    assert err["reason"]=="explicit_user_request" and err["error"]=="entry_not_eligible"


def test_state_gc_expires_archives_entries_snapshots(tmp_path):
    source=tmp_path/"x.zip";source.write_bytes(b"PK\x03\x04fixture")
    service=archive_coordinator(tmp_path);fd=os.open(source,os.O_RDONLY)
    try:manifest=service.inspect_fd(fd,"archive_review")
    finally:os.close(fd)
    assert list((tmp_path/"archive-state"/"archives").glob("*.json")) and list((tmp_path/"archive-state"/"entries").glob("*.json"))
    for snap in (tmp_path/"archive-state"/"snapshots").glob("archive-*"):
        os.utime(snap,(1000000000,1000000000))
    ArchiveBreakGlassCoordinator(tmp_path/"archive-state",broker=Broker(),archive_broker=ArchiveBroker(),now=lambda:1700000000+TTL+1,expected_uid=os.getuid())
    assert list((tmp_path/"archive-state"/"archives").glob("*.json"))==[]
    assert list((tmp_path/"archive-state"/"entries").glob("*.json"))==[]
    assert list((tmp_path/"archive-state"/"snapshots").glob("archive-*"))==[]


def test_archive_inspect_receipt_failure_is_categorical_and_rolls_back_state(tmp_path):
    source=tmp_path/"x.zip";source.write_bytes(b"PK\x03\x04fixture")
    service=archive_coordinator(tmp_path);original=service._exclusive_write
    def failing(directory,name,data):
        if directory=="receipts":raise OSError("ENOSPC")
        return original(directory,name,data)
    service._exclusive_write=failing;fd=os.open(source,os.O_RDONLY)
    try:
        with pytest.raises(BreakGlassError,match="receipt_failed"):service.inspect_fd(fd,"archive_review")
    finally:os.close(fd)
    assert list((tmp_path/"archive-state"/"archives").glob("*.json"))==[]
    assert list((tmp_path/"archive-state"/"entries").glob("*.json"))==[]
    assert list((tmp_path/"archive-state"/"snapshots").glob("archive-*"))==[]


def test_archive_extract_crash_leaves_durable_claim_that_blocks_replay(tmp_path):
    source=tmp_path/"x.zip";source.write_bytes(b"PK\x03\x04fixture")
    service=archive_coordinator(tmp_path);fd=os.open(source,os.O_RDONLY)
    try:manifest=service.inspect_fd(fd,"archive_review")
    finally:os.close(fd)
    entry=manifest["entries"][0]["entry_ref"]
    service.parse_fd=lambda *a,**k:(_ for _ in ()).throw(SystemExit("simulated crash"))
    with pytest.raises(SystemExit,match="simulated crash"):service.extract(entry)
    assert (tmp_path/"archive-state"/"entries"/(entry+".claim")).exists()
    service=ArchiveBreakGlassCoordinator(tmp_path/"archive-state",broker=Broker(),archive_broker=ArchiveBroker(),now=lambda:1700000000,expected_uid=os.getuid())
    with pytest.raises(BreakGlassError,match="entry_ref_in_progress"):service.extract(entry)


def test_state_gc_removes_expired_used_claim_and_parse_cache(tmp_path):
    root=tmp_path/"archive-state";service=ArchiveBreakGlassCoordinator(root,broker=Broker(),archive_broker=ArchiveBroker(),now=lambda:1700000000,expected_uid=os.getuid())
    for directory,name in (("entries","bge_v1_"+"A"*32+".used"),("entries","bge_v1_"+"B"*32+".claim"),("parses","bgp_v1_"+"C"*32+".json")):
        service._exclusive_write(directory,name,b"stale")
        os.utime(root/directory/name,(1000000000,1000000000))
    ArchiveBreakGlassCoordinator(root,broker=Broker(),archive_broker=ArchiveBroker(),now=lambda:1700000000+TTL+1,expected_uid=os.getuid())
    assert list((root/"entries").glob("*.used"))==[]
    assert list((root/"entries").glob("*.claim"))==[]
    assert list((root/"parses").glob("*.json"))==[]


def test_archive_coordinator_unit_requires_backend_sockets():
    unit=(Path(__file__).parents[1]/"packaging/systemd/omisa-archive-breakglass@.service").read_text()
    assert "Requires=omisa-parser-breakglass.socket omisa-archive-breakglass-worker.socket" in unit
    assert "After=omisa-parser-breakglass.socket omisa-archive-breakglass-worker.socket" in unit
