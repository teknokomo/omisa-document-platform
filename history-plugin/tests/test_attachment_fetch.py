
import importlib.util
import json
import re
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT))
import history

NOW = 1_788_345_600_000
START = "2026-09-02T07:00:00Z"
END = "2026-09-02T08:00:00Z"


def context(key, default=""):
    return {"HERMES_SESSION_PLATFORM":"max", "HERMES_SESSION_CHAT_TYPE":"group",
            "HERMES_SESSION_CHAT_ID":"-900", "HERMES_SESSION_USER_ID":"actor",
            "HERMES_SESSION_ID":"s1", "HERMES_SESSION_MESSAGE_ID":"inbound",
            "HERMES_SESSION_PROFILE":"default", "HERMES_CRON_SESSION":""}.get(key, default)


def attachment(filename="report.txt", data_size=5, url="https://fd.oneme.ru/secret?token=CANARY"):
    return {"type":"file", "filename":filename, "size":data_size,
            "payload":{"url":url, "token":"TOKEN-CANARY", "fileId":"FILEID-CANARY"}}


def message(att=None, *, mid="m1", chat="-900", ts=None):
    start = history.parse_interval(START, END, NOW)[0]
    return {"timestamp":ts or start+1, "recipient":{"chat_id":chat},
            "sender":{"user_id":"u", "name":"Alice"},
            "body":{"mid":mid, "text":"hello", "attachments":[att or attachment()]}}


class API:
    def __init__(self, raw): self.raw=raw; self.calls=[]; self.access=True
    def check_group_access(self, chat_id): self.calls.append(("access", chat_id)); return self.access
    def get_messages(self, *, chat_id=None, message_ids=None, upper_ms=None, lower_ms=None, count=100):
        self.calls.append(("messages", chat_id, message_ids, upper_ms, lower_ms, count))
        return [self.raw] if message_ids is not None else [[self.raw], []][0]


class Downloader:
    def __init__(self, data=b"hello", mime="text/plain"): self.data=data; self.mime=mime; self.urls=[]
    def download(self, url, *, declared_size, max_bytes):
        self.urls.append((url, declared_size, max_bytes)); return self.data, self.mime


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    with sqlite3.connect(tmp_path/"state.db") as db:
        db.execute("CREATE TABLE sessions(id TEXT PRIMARY KEY,source TEXT,user_id TEXT,chat_id TEXT,chat_type TEXT,origin_json TEXT)")
        db.execute("INSERT INTO sessions VALUES(?,?,?,?,?,?)", ("s1","max","x","-900","group","{}"))
    (tmp_path/"config.yaml").write_text("platforms:\n  max:\n    groups:\n      allowed_chats: [-900]\n")
    return tmp_path


def test_vertical_slice_search_ref_download_cache_and_safe_result(home):
    raw=message(); api=API(raw); downloader=Downloader()
    service=history.HistoryService(api=api, downloader=downloader, now_ms=lambda:NOW, context_reader=context)
    found=service.search({"start_time":START,"end_time":END}, session_id="s1", turn_id="t")
    item=found["untrusted_history"]["messages"][0]["attachments"][0]
    assert set(item)=={"kind","filename","declared_size","attachment_ref"}
    result=service.attachment_fetch({"attachment_ref":item["attachment_ref"]}, session_id="s1", turn_id="t")
    assert result["success"] is True
    assert result["filename"]=="report.txt" and result["size"]==5
    assert set(result) == {"success", "artifact_ref", "filename", "size", "type", "security"}
    assert re.fullmatch(r"[A-Za-z0-9_-]{40,64}", result["artifact_ref"])
    read=service.attachment_read({"artifact_ref":result["artifact_ref"]},session_id="s1",turn_id="t")
    assert read["success"] is True and read["content"] == "hello"
    encoded=json.dumps(result)
    assert all(x not in encoded for x in ("fd.oneme.ru","CANARY","TOKEN-CANARY","FILEID-CANARY","m1","-900"))
    assert downloader.urls==[("https://fd.oneme.ru/secret?token=CANARY",5,20*1024*1024)]


def test_plugin_registers_third_closed_attachment_tool_and_latches(home):
    class Ctx:
        def __init__(self): self.tools=[]; self.hooks={}
        def register_tool(self, **kw): self.tools.append(kw)
        def register_hook(self, name, callback): self.hooks[name]=callback
    spec=importlib.util.spec_from_file_location("attachment_plugin",ROOT/"__init__.py",submodule_search_locations=[str(ROOT)])
    module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
    ctx=Ctx();module.register(ctx)
    assert {x["name"] for x in ctx.tools}=={"history_search","history_fetch","history_attachment_fetch","history_attachment_read","archive_inspect","archive_extract","document_parse","document_read"}
    tool=next(x for x in ctx.tools if x["name"]=="history_attachment_fetch")
    assert tool["schema"]["parameters"]=={"type":"object","properties":{"attachment_ref":{"type":"string"}},"required":["attachment_ref"],"additionalProperties":False}
    assert ctx.hooks["pre_tool_call"](tool_name="history_attachment_fetch",args={},turn_id="t") is None
    assert ctx.hooks["pre_tool_call"](tool_name="send_message",args={},turn_id="t")["action"]=="block"
    assert ctx.hooks["pre_tool_call"](tool_name="terminal",args={},turn_id="t")["action"]=="block"
    assert ctx.hooks["pre_tool_call"](tool_name="unknown_future_tool",args={},turn_id="t")["action"]=="block"


def test_exact_ref_is_single_use_and_modified_descriptor_is_rejected(home):
    raw=message(); api=API(raw); service=history.HistoryService(api=api,downloader=Downloader(),now_ms=lambda:NOW,context_reader=context)
    found=service.search({"start_time":START,"end_time":END},session_id="s1",turn_id="t")
    ref=found["untrusted_history"]["messages"][0]["attachments"][0]["attachment_ref"]
    api.raw=message(attachment(filename="changed.txt"))
    assert service.attachment_fetch({"attachment_ref":ref},session_id="s1",turn_id="t")["error"]=="attachment_changed"
    assert service.attachment_fetch({"attachment_ref":ref},session_id="s1",turn_id="t")["error"]=="used_attachment_ref"


@pytest.mark.parametrize("filename,data,error",[("bad.pdf",b"hello","bad_magic"),("bad.txt",b"a\0b","bad_magic"),("bad.exe",b"MZ","unsupported_attachment")])
def test_document_type_and_magic_are_enforced(home,filename,data,error):
    raw=message(attachment(filename=filename,data_size=len(data))); api=API(raw)
    service=history.HistoryService(api=api,downloader=Downloader(data),now_ms=lambda:NOW,context_reader=context)
    found=service.search({"start_time":START,"end_time":END},session_id="s1",turn_id="t")
    attachments=found["untrusted_history"]["messages"][0]["attachments"]
    if error=="unsupported_attachment":
        assert "attachment_ref" not in attachments[0]
    else:
        ref=attachments[0]["attachment_ref"]
        assert service.attachment_fetch({"attachment_ref":ref},session_id="s1",turn_id="t")["error"]==error


def test_malformed_sibling_does_not_shift_attachment_index(home):
    raw=message();raw["body"]["attachments"]=["malformed",attachment()]
    api=API(raw);service=history.HistoryService(api=api,downloader=Downloader(),now_ms=lambda:NOW,context_reader=context)
    found=service.search({"start_time":START,"end_time":END},session_id="s1",turn_id="t")
    items=found["untrusted_history"]["messages"][0]["attachments"]
    assert items[0]=={"kind":"malformed"} and "attachment_ref" in items[1]
    assert service.attachment_fetch({"attachment_ref":items[1]["attachment_ref"]},session_id="s1",turn_id="t")["success"] is True


def test_capability_db_contains_no_url_token_fileid_or_filename(home):
    raw=message();service=history.HistoryService(api=API(raw),downloader=Downloader(),now_ms=lambda:NOW,context_reader=context)
    service.search({"start_time":START,"end_time":END},session_id="s1",turn_id="t")
    blob=(home/"omisa-history"/"history.db").read_bytes()
    for canary in (b"fd.oneme.ru",b"CANARY",b"TOKEN-CANARY",b"FILEID-CANARY",b"report.txt"):
        assert canary not in blob


def test_old_ole_artifact_read_is_categorical(home):
    data=bytes.fromhex("D0CF11E0A1B11AE1")+b"x"
    raw=message(attachment(filename="legacy.doc",data_size=len(data)))
    service=history.HistoryService(api=API(raw),downloader=Downloader(data),now_ms=lambda:NOW,context_reader=context)
    found=service.search({"start_time":START,"end_time":END},session_id="s1",turn_id="t")
    fetched=service.attachment_fetch({"attachment_ref":found["untrusted_history"]["messages"][0]["attachments"][0]["attachment_ref"]},session_id="s1",turn_id="t")
    assert service.attachment_read({"artifact_ref":fetched["artifact_ref"]},session_id="s1",turn_id="t")["error"]=="extraction_unsupported"


def test_descriptor_without_stable_max_identity_gets_no_download_ref(home):
    raw = message()
    raw["body"]["attachments"][0]["payload"].pop("token")
    raw["body"]["attachments"][0]["payload"].pop("fileId")
    service=history.HistoryService(api=API(raw),downloader=Downloader(),now_ms=lambda:NOW,context_reader=context)
    found=service.search({"start_time":START,"end_time":END},session_id="s1",turn_id="t")
    item=found["untrusted_history"]["messages"][0]["attachments"][0]
    assert "attachment_ref" not in item


def test_validation_failure_deletes_quarantine_and_keeps_full_reservation(home):
    class PathDownloader:
        def __init__(self): self.path = home / "omisa-history" / "quarantine" / "bad.pdf"
        def download(self, url, *, declared_size, max_bytes):
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_bytes(b"not-a-pdf")
            return self.path, "application/pdf"
    raw=message(attachment(filename="bad.pdf",data_size=9)); downloader=PathDownloader()
    service=history.HistoryService(api=API(raw),downloader=downloader,now_ms=lambda:NOW,context_reader=context)
    found=service.search({"start_time":START,"end_time":END},session_id="s1",turn_id="t")
    ref=found["untrusted_history"]["messages"][0]["attachments"][0]["attachment_ref"]
    assert service.attachment_fetch({"attachment_ref":ref},session_id="s1",turn_id="t")["error"]=="bad_magic"
    assert not downloader.path.exists()
    with service._connect() as db:
        reserved,actual=db.execute("SELECT reserved_bytes,actual_bytes FROM attachment_usage").fetchone()
    assert reserved==history.MAX_ATTACHMENT_BYTES and actual is None


def test_artifact_read_rejects_tampered_path_outside_cache(home):
    raw=message();service=history.HistoryService(api=API(raw),downloader=Downloader(),now_ms=lambda:NOW,context_reader=context)
    found=service.search({"start_time":START,"end_time":END},session_id="s1",turn_id="t")
    fetched=service.attachment_fetch({"attachment_ref":found["untrusted_history"]["messages"][0]["attachments"][0]["attachment_ref"]},session_id="s1",turn_id="t")
    outside=home/"outside.txt";outside.write_text("SECRET",encoding="utf-8")
    with service._connect() as db:
        db.execute("UPDATE artifacts SET path=? WHERE token=?",(str(outside),fetched["artifact_ref"]))
    result=service.attachment_read({"artifact_ref":fetched["artifact_ref"]},session_id="s1",turn_id="t")
    assert result["error"]=="invalid_artifact_ref"
    assert "SECRET" not in json.dumps(result)


@pytest.mark.parametrize("field", ["fileId", "file_id"])
def test_every_present_stable_file_identity_field_is_fingerprinted(home, field):
    raw=message(); raw["body"]["attachments"][0]["payload"]["file_id"]="ALT"
    api=API(raw); downloader=Downloader(); service=history.HistoryService(api=api,downloader=downloader,now_ms=lambda:NOW,context_reader=context)
    found=service.search({"start_time":START,"end_time":END},session_id="s1",turn_id="t")
    ref=found["untrusted_history"]["messages"][0]["attachments"][0]["attachment_ref"]
    raw["body"]["attachments"][0]["payload"][field]+="-changed"
    result=service.attachment_fetch({"attachment_ref":ref},session_id="s1",turn_id="t")
    assert result["error"]=="attachment_changed"
    assert downloader.urls==[]


def test_rotating_signed_token_does_not_change_stable_file_identity(home):
    raw=message(); api=API(raw); downloader=Downloader(); service=history.HistoryService(api=api,downloader=downloader,now_ms=lambda:NOW,context_reader=context)
    found=service.search({"start_time":START,"end_time":END},session_id="s1",turn_id="t")
    ref=found["untrusted_history"]["messages"][0]["attachments"][0]["attachment_ref"]
    raw["body"]["attachments"][0]["payload"]["token"]="ROTATED-SIGNED-TOKEN"
    raw["body"]["attachments"][0]["payload"]["url"]="https://fd.oneme.ru/secret?token=ROTATED-SIGNED-TOKEN"
    result=service.attachment_fetch({"attachment_ref":ref},session_id="s1",turn_id="t")
    assert result["success"] is True
    assert downloader.urls[0][0].endswith("ROTATED-SIGNED-TOKEN")


@pytest.mark.parametrize("mutation", ["removed", "reordered", "identity", "timestamp", "chat", "revoked"])
def test_read_refetches_and_revocation_deletes_artifact(home, mutation):
    raw=message(); api=API(raw); service=history.HistoryService(api=api,downloader=Downloader(),now_ms=lambda:NOW,context_reader=context)
    found=service.search({"start_time":START,"end_time":END},session_id="s1",turn_id="t")
    fetched=service.attachment_fetch({"attachment_ref":found["untrusted_history"]["messages"][0]["attachments"][0]["attachment_ref"]},session_id="s1",turn_id="t")
    with service._connect() as db: path=Path(db.execute("SELECT path FROM artifacts WHERE token=?",(fetched["artifact_ref"],)).fetchone()[0])
    if mutation=="removed": api.raw=message(); api.raw["body"]["attachments"]=[]
    elif mutation=="reordered": api.raw=message(); api.raw["body"]["attachments"]=[attachment("other.txt"),attachment()]
    elif mutation=="identity": api.raw["body"]["attachments"][0]["payload"]["fileId"]="revoked"
    elif mutation=="timestamp": api.raw["timestamp"]=0
    elif mutation=="chat": api.raw["recipient"]["chat_id"]="-901"
    else: api.access=False
    result=service.attachment_read({"artifact_ref":fetched["artifact_ref"]},session_id="s1",turn_id="t")
    assert result["success"] is False and "content" not in result
    assert not path.exists()
    with service._connect() as db: assert db.execute("SELECT 1 FROM artifacts WHERE token=?",(fetched["artifact_ref"],)).fetchone() is None


@pytest.mark.parametrize("filename,data", [
    ("x.txt",b"<html><script>alert(1)</script></html>"), ("x.md",b"#!/bin/sh\nrm -rf /"),
    ("x.csv",b"<svg onload='x'/>") , ("x.json",b"not-json"),
    ("x.xml",b"<!DOCTYPE x [<!ENTITY e SYSTEM 'file:///etc/passwd'>]><x>&e;</x>"),
])
def test_text_formats_are_content_validated(home,filename,data):
    raw=message(attachment(filename=filename,data_size=len(data))); service=history.HistoryService(api=API(raw),downloader=Downloader(data),now_ms=lambda:NOW,context_reader=context)
    found=service.search({"start_time":START,"end_time":END},session_id="s1",turn_id="t")
    result=service.attachment_fetch({"attachment_ref":found["untrusted_history"]["messages"][0]["attachments"][0]["attachment_ref"]},session_id="s1",turn_id="t")
    assert result["error"] in {"bad_magic","unsafe_document"}


def test_artifact_db_insert_failure_removes_promoted_file(home,monkeypatch):
    raw=message(); service=history.HistoryService(api=API(raw),downloader=Downloader(),now_ms=lambda:NOW,context_reader=context)
    found=service.search({"start_time":START,"end_time":END},session_id="s1",turn_id="t")
    original=service._connect; calls=0
    class Broken:
        def __enter__(self): return self
        def __exit__(self,*a): return False
        def execute(self,*a,**k): raise sqlite3.OperationalError("TOKEN-CANARY")
    def connect():
        nonlocal calls; calls+=1
        return Broken() if calls==3 else original()
    monkeypatch.setattr(service,"_connect",connect)
    result=service.attachment_fetch({"attachment_ref":found["untrusted_history"]["messages"][0]["attachments"][0]["attachment_ref"]},session_id="s1",turn_id="t")
    assert result["success"] is False
    assert list((home/"omisa-history"/"artifacts").glob("*"))==[]


def test_shared_chat_attachment_quota_applies_across_actors(home):
    service=history.HistoryService(api=API(message()),downloader=Downloader(),now_ms=lambda:NOW,context_reader=context)
    scopes=[]
    for i in range(3):
        s={"actor":f"a{i}","chat_id":"-900","turn":f"t{i}"}; scopes.append(s)
        reservation,error=service._begin_attachment(s)
        if i<2: assert reservation and error is None; service._finish_attachment(s,reservation,None)
        else: assert error=="download_quota_exceeded"


def test_connect_janitor_removes_expired_artifact_but_not_outside_file(home):
    service=history.HistoryService(api=API(message()),downloader=Downloader(),now_ms=lambda:NOW,context_reader=context)
    root=home/"omisa-history"/"artifacts"; root.mkdir(parents=True)
    inside=root/"old.txt"; inside.write_text("old")
    outside=home/"outside.txt"; outside.write_text("keep")
    payload=json.dumps({})
    with service._connect() as db:
        db.execute("INSERT INTO artifacts(token,path,display_name,doc_type,size,expires_ms,payload) VALUES(?,?,?,?,?,?,?)",("inside",str(inside),"x.txt","txt",3,NOW-1,payload))
        db.execute("INSERT INTO artifacts(token,path,display_name,doc_type,size,expires_ms,payload) VALUES(?,?,?,?,?,?,?)",("outside",str(outside),"x.txt","txt",4,NOW-1,payload))
    with service._connect() as db:
        assert db.execute("SELECT COUNT(*) FROM artifacts WHERE expires_ms<?",(NOW,)).fetchone()[0]==0
    assert not inside.exists() and outside.exists()


def test_extraction_is_byte_bounded_and_complex_parsers_are_unsupported(home):
    path=home/"many.txt"; path.write_bytes(("😀"*100000).encode())
    text=history._extract_document(path,"txt")
    assert len(text.encode("utf-8")) <= history.MAX_EXTRACTED_BYTES
    with pytest.raises(history.AttachmentDownloadError,match="extraction_unsupported"):
        history._extract_document(path,"pdf")


def test_pid_reuse_identity_does_not_preserve_stale_lease(home,monkeypatch):
    service=history.HistoryService(api=API(message()),downloader=Downloader(),now_ms=lambda:NOW,context_reader=context)
    actor,chat=service._pseudo("actor","actor"),service._pseudo("chat","-900")
    with service._connect() as db:
        db.execute("INSERT INTO active(actor,chat,turn,started_ms,owner,pid,heartbeat_ms,process_start) VALUES(?,?,?,?,?,?,?,?)",(actor,chat,"old",NOW-999999,"owner",history.os.getpid(),NOW-999999,"wrong-boot"))
    reservation,error=service._begin_attachment({"actor":"actor","chat_id":"-900","turn":"new"})
    assert error is None and reservation


def test_nested_archive_magic_is_rejected_even_without_archive_suffix():
    import io,zipfile
    inner=io.BytesIO()
    with zipfile.ZipFile(inner,"w") as z:z.writestr("x","x")
    outer=io.BytesIO()
    with zipfile.ZipFile(outer,"w") as z:
        z.writestr("[Content_Types].xml","x");z.writestr("word/document.xml","x");z.writestr("word/media/blob.bin",inner.getvalue())
    with pytest.raises(history.AttachmentDownloadError,match="unsafe_archive"):
        history._validate_document(outer.getvalue(),"x.docx")


def test_old_production_active_schema_migrates_all_lease_columns(home):
    service=history.HistoryService(api=API(message()),downloader=Downloader(),now_ms=lambda:NOW,context_reader=context)
    db_path=home/"omisa-history"/"history.db"
    db_path.parent.mkdir(parents=True,exist_ok=True)
    with sqlite3.connect(db_path) as db:
        db.execute("CREATE TABLE active(actor TEXT,chat TEXT,turn TEXT,started_ms INTEGER,PRIMARY KEY(actor,chat))")
    with service._connect() as db:
        columns={row[1] for row in db.execute("PRAGMA table_info(active)")}
    assert {"owner","pid","heartbeat_ms","process_start"} <= columns
    scope={"actor":"actor","chat_id":"-900","turn":"migrated"}
    reservation,error=service._begin_attachment(scope)
    assert error is None and reservation
    service._finish_attachment(scope,reservation,None)


def test_artifact_reads_do_not_consume_download_byte_or_file_quota(home):
    raw=message(attachment(filename="report.txt",data_size=70000)); data=b"a"*70000
    api=API(raw); service=history.HistoryService(api=api,downloader=Downloader(data),now_ms=lambda:NOW,context_reader=context)
    found=service.search({"start_time":START,"end_time":END},session_id="s1",turn_id="t")
    fetched=service.attachment_fetch({"attachment_ref":found["untrusted_history"]["messages"][0]["attachments"][0]["attachment_ref"]},session_id="s1",turn_id="t")
    first=service.attachment_read({"artifact_ref":fetched["artifact_ref"],"offset":0,"limit":32768},session_id="s1",turn_id="t")
    second=service.attachment_read({"artifact_ref":fetched["artifact_ref"],"offset":first["next_offset"],"limit":32768},session_id="s1",turn_id="t")
    assert first["success"] and second["success"]
    scope,_=service._scope("s1","t"); actor=service._pseudo("actor",scope["actor"]);chat=service._pseudo("chat",scope["chat_id"])
    with service._connect() as db:
        count,total=db.execute("SELECT COUNT(*),SUM(reserved_bytes) FROM attachment_usage WHERE actor=? AND chat=?",(actor,chat)).fetchone()
    assert count==1 and total==history.MAX_ATTACHMENT_BYTES
