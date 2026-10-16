from __future__ import annotations

import json
import os
import sqlite3
import zipfile
from pathlib import Path

from history_plugin import history

NOW=1_900_000_000_000

class API:
    def check_group_access(self,*a,**k):return True

class ArchiveClientStub:
    def __init__(self,payload=b"%PDF-1.4\n%%EOF\n"):self.payload=payload;self.calls=[]
    def inspect_fd(self,fd):
        self.calls.append("inspect")
        return {"success":True,"archive_digest":"a"*64,"entry_count":1,"total_uncompressed":len(self.payload),"entries":[{"index":0,"size":len(self.payload),"compressed_size":8,"crc32":123,"method":8,"detected_format":"pdf","eligible":True,"reason":None}]}
    def extract_fd(self,fd,*,entry_index,expected,expected_archive_digest=None):
        self.calls.append("extract")
        r,w=os.pipe();os.write(w,self.payload);os.close(w)
        return {"success":True,"fd":r,"size":len(self.payload),"sha256":__import__('hashlib').sha256(self.payload).hexdigest(),"detected_format":"pdf"}

def context(name,default=""):
    values={"HERMES_SESSION_PLATFORM":"telegram","HERMES_SESSION_CHAT_TYPE":"dm","HERMES_SESSION_CHAT_ID":"42","HERMES_SESSION_USER_ID":"42","HERMES_SESSION_MESSAGE_ID":"m1","HERMES_SESSION_ID":"s1","HERMES_SESSION_PROFILE":"default"}
    return values.get(name,default)

def test_archive_artifact_can_enter_document_parse_in_same_telegram_turn(tmp_path,monkeypatch):
    monkeypatch.setenv("HERMES_HOME",str(tmp_path));cache=tmp_path/"cache"/"documents";cache.mkdir(parents=True)
    with sqlite3.connect(tmp_path/"state.db") as db:
        db.execute("CREATE TABLE sessions(id TEXT PRIMARY KEY,source TEXT,user_id TEXT,chat_id TEXT,chat_type TEXT,origin_json TEXT)");db.execute("INSERT INTO sessions VALUES(?,?,?,?,?,?)",("s1","telegram","42","42","dm","{}"))
    archive=cache/"box.zip"
    with zipfile.ZipFile(archive,"w") as z:z.writestr("manual.pdf",b"%PDF-1.4\n%%EOF\n")
    service=history.HistoryService(api=API(),now_ms=lambda:NOW,context_reader=context,current_attachment_reader=lambda:({"path":str(archive),"message_id":"m1","platform":"telegram","chat_type":"dm","chat_id":"42","actor":"42"},),archive_client=ArchiveClientStub(),broker_client=type("B",(),{"parse_fd":lambda self,fd,**kw:[{"schema":"omisa.document/1","type":"document","request_id":"a"*32,"document":{"detected_format":"pdf","media_type":"application/pdf","size_bytes":len(ArchiveClientStub().payload),"title":None,"language":None},"parser":{"bundle_version":"test","registry_version":1},"structure":{"unit":"page","unit_count":0},"warnings":[]},{"schema":"omisa.document/1","type":"end","counts":{"units_emitted":0,"records_emitted":2,"text_chars":0,"tables":0,"cells":0},"truncated":False,"limit_reason":None}]} )())
    a=service.archive_inspect({"source":{"kind":"attachment","path":str(archive)}},session_id="s1",turn_id="t1")
    x=service.archive_extract({"entry_ref":a["entries"][0]["entry_ref"]},session_id="s1",turn_id="t1")
    claim,error=service._artifact_claim(x["artifact_ref"],service._scope("s1","t1",history_only=False)[0]);assert error is None
    assert service._revalidate_source(service._scope("s1","t1",history_only=False)[0],claim["claim"],claim["path"],claim["identity"]) is None
    parsed=service.document_parse({"source":{"kind":"artifact","artifact_ref":x["artifact_ref"]}},session_id="s1",turn_id="t1")
    assert parsed.get("success"),parsed


def test_archive_inspect_then_single_use_extract_returns_normal_artifact(tmp_path,monkeypatch):
    monkeypatch.setenv("HERMES_HOME",str(tmp_path));cache=tmp_path/"cache"/"documents";cache.mkdir(parents=True)
    with sqlite3.connect(tmp_path/"state.db") as db:
        db.execute("CREATE TABLE sessions(id TEXT PRIMARY KEY,source TEXT,user_id TEXT,chat_id TEXT,chat_type TEXT,origin_json TEXT)")
        db.execute("INSERT INTO sessions VALUES(?,?,?,?,?,?)",("s1","telegram","42","42","dm","{}"))
    archive=cache/"box.zip"
    with zipfile.ZipFile(archive,"w") as z:z.writestr("manual.pdf",b"%PDF-1.4\n%%EOF\n")
    client=ArchiveClientStub();service=history.HistoryService(api=API(),now_ms=lambda:NOW,context_reader=context,
      current_attachment_reader=lambda:({"path":str(archive),"message_id":"m1","platform":"telegram","chat_type":"dm","chat_id":"42","actor":"42"},),archive_client=client)
    inspected=service.archive_inspect({"source":{"kind":"attachment","path":str(archive)}},session_id="s1",turn_id="t1")
    assert inspected.get("success"), inspected
    assert len(inspected["entries"])==1 and inspected["entries"][0]["entry_ref"].startswith("ent_v1_")
    assert "path" not in json.dumps(inspected).lower() and "manual.pdf" not in json.dumps(inspected)
    extracted=service.archive_extract({"entry_ref":inspected["entries"][0]["entry_ref"]},session_id="s1",turn_id="t1")
    assert extracted["success"] and extracted["artifact_ref"].startswith("src_v1_")
    denied=service.archive_extract({"entry_ref":inspected["entries"][0]["entry_ref"]},session_id="s1",turn_id="t1")
    assert denied=={"success":False,"error":"entry_ref_replayed"}
    claim,error=service._artifact_claim(extracted["artifact_ref"],service._scope("s1","t1",history_only=False)[0])
    assert error is None and Path(claim["path"]).read_bytes()==client.payload
