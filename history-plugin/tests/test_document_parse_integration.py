import hashlib
import json
import os
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT))
import history

NOW = 1_788_345_600_000


def context(key, default=""):
    return {"HERMES_SESSION_PLATFORM":"max", "HERMES_SESSION_CHAT_TYPE":"group",
            "HERMES_SESSION_CHAT_ID":"-900", "HERMES_SESSION_USER_ID":"actor",
            "HERMES_SESSION_ID":"s1", "HERMES_SESSION_MESSAGE_ID":"inbound",
            "HERMES_SESSION_PROFILE":"default", "HERMES_CRON_SESSION":""}.get(key, default)


def raw_message():
    return {"timestamp":NOW-1000, "recipient":{"chat_id":"-900"},
            "body":{"mid":"m1", "attachments":[{"type":"file", "filename":"report.txt", "size":11,
                    "payload":{"url":"https://fd.oneme.ru/x", "fileId":"secret-file-id"}}]}}


class API:
    def __init__(self): self.raw=raw_message(); self.access=True; self.access_calls=0
    def check_group_access(self, _chat): self.access_calls += 1; return self.access
    def get_messages(self, **_kwargs): return [self.raw]


class Broker:
    def __init__(self): self.calls=[]
    def parse_fd(self, fd, *, artifact_ref, expected_size, options):
        self.calls.append((os.read(fd, 100), artifact_ref, expected_size, options))
        rid="a"*32
        return [
            {"schema":"omisa.document/1","type":"document","request_id":rid,
             "document":{"detected_format":"txt","media_type":"text/plain","size_bytes":11,"title":None,"language":None},
             "parser":{"bundle_version":"test","registry_version":1},
             "structure":{"unit":"page","unit_count":1},"warnings":[]},
            {"schema":"omisa.document/1","type":"unit","id":"u1","unit_kind":"page","index":1,"label":None,"parent_id":None},
            {"schema":"omisa.document/1","type":"text","id":"b1","unit_id":"u1","order":1,"text":"hello world","source":"native","truncated":False},
            {"schema":"omisa.document/1","type":"end","request_id":rid,"status":"ok",
             "counts":{"units_emitted":1,"records_emitted":4,"text_chars":11,"tables":0,"cells":0},
             "truncated":False,"limit_reason":None,"warnings":[]},
        ]


class PagingBroker:
    def __init__(self,total=620):self.total=total;self.calls=[]
    def parse_fd(self,fd,*,artifact_ref,expected_size,options):
        offset=options.get("record_offset",0);limit=options.get("max_records",200)-2
        end=min(offset+limit,self.total);self.calls.append(dict(options));rid="a"*32
        rows=[{"schema":"omisa.document/1","type":"document","request_id":rid,"document":{"detected_format":"docx","media_type":"application/vnd.openxmlformats-officedocument.wordprocessingml.document","size_bytes":expected_size,"title":None,"language":None},"parser":{"bundle_version":"test","registry_version":1},"structure":{"unit":"page","unit_count":1},"warnings":[]},
              {"schema":"omisa.document/1","type":"unit","id":"u1","unit_kind":"page","index":1,"label":"1","parent_id":None}]
        rows += [{"schema":"omisa.document/1","type":"text","id":f"b{i+1}","unit_id":"u1","order":i+1,"text":f"Paragraph {i:04d}","source":"native","truncated":False} for i in range(offset,end)]
        rows.append({"schema":"omisa.document/1","type":"end","request_id":rid,"status":"ok","counts":{"units_emitted":1,"records_emitted":len(rows)+1,"text_chars":sum(len(r.get("text","")) for r in rows),"tables":0,"cells":0},"truncated":end<self.total,"limit_reason":"records" if end<self.total else None,"warnings":[]})
        return rows


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    with sqlite3.connect(tmp_path/"state.db") as db:
        db.execute("CREATE TABLE sessions(id TEXT PRIMARY KEY,source TEXT,user_id TEXT,chat_id TEXT,chat_type TEXT,origin_json TEXT)")
        db.execute("INSERT INTO sessions VALUES('s1','max','x','-900','group','{}')")
    (tmp_path/"config.yaml").write_text("platforms:\n  max:\n    groups:\n      allowed_chats: [-900]\n")
    monkeypatch.setattr(history,"_max_config",lambda:{"groups":{"allowed_chats":["-900"]}})
    api=API(); broker=Broker(); service=history.HistoryService(api=api,now_ms=lambda:NOW,context_reader=context,broker_client=broker)
    root=tmp_path/"omisa-history"/"artifacts"; root.mkdir(parents=True)
    path=root/"history-token.txt"; path.write_bytes(b"hello world"); os.chmod(path,0o600)
    claim={"schema":history.CAP_SCHEMA_VERSION,"binding":service._binding(service._scope("s1","t")[0]),
           "search":"opaque","mid":"m1","start":NOW-2000,"end":NOW,"index":0,"type":"file",
           "fingerprint":history._descriptor_fingerprint(service,api.raw["body"]["attachments"][0])}
    token="legacyOpaqueArtifactToken_0123456789abcd"
    st=path.stat()
    with service._connect() as db:
        db.execute("INSERT INTO artifacts(token,path,display_name,doc_type,size,expires_ms,payload,device,inode,mtime_ns) VALUES(?,?,?,?,?,?,?,?,?,?)",
                   (token,str(path),"report.txt","txt",11,NOW+10000,json.dumps(claim),st.st_dev,st.st_ino,st.st_mtime_ns))
    return service,api,broker,token,path


def test_parse_authorizes_opens_safe_fd_and_returns_only_opaque_ref(setup):
    service,api,broker,token,_=setup
    result=service.document_parse({"artifact_ref":token},session_id="s1",turn_id="t")
    assert result["success"] is True and set(result)=={"success","parse_ref","security"}
    assert token not in json.dumps(result) and "report" not in json.dumps(result)
    assert broker.calls[0][0]==b"hello world" and broker.calls[0][1]==token
    assert api.access_calls >= 2


def test_parse_is_idempotent_for_same_artifact_and_scope(setup):
    service,_,broker,token,_=setup
    a=service.document_parse({"artifact_ref":token},session_id="s1",turn_id="t")
    b=service.document_parse({"artifact_ref":token},session_id="s1",turn_id="t")
    assert a==b and len(broker.calls)==1


def test_parse_aggregates_internal_pages_before_document_read(setup):
    service,_,_,token,_=setup
    broker=PagingBroker();service.broker_client=broker
    parsed=service.document_parse({"artifact_ref":token,"options":{"max_records":200}},session_id="s1",turn_id="t")
    assert parsed["success"] is True
    assert [call.get("record_offset",0) for call in broker.calls]==[0,498]
    cursor=None;seen=[]
    while True:
        args={"cursor":cursor,"limit":50} if cursor else {"parse_ref":parsed["parse_ref"],"limit":50}
        page=service.document_read(args,session_id="s1",turn_id="t")
        seen += [row["text"] for row in page["records"] if row["type"]=="text"]
        cursor=page["cursor"]
        if not cursor:break
    assert seen==[f"Paragraph {i:04d}" for i in range(620)]


def live_context(values):
    base={
        "HERMES_SESSION_PLATFORM":"telegram", "HERMES_SESSION_CHAT_TYPE":"dm",
        "HERMES_SESSION_CHAT_ID":"42", "HERMES_SESSION_USER_ID":"42",
        "HERMES_SESSION_ID":"telegram-session", "HERMES_SESSION_MESSAGE_ID":"msg-1",
        "HERMES_SESSION_PROFILE":"default", "HERMES_SESSION_ATTACHMENT_PATHS":"[]",
        "HERMES_CRON_SESSION":"",
    }
    base.update(values)
    return lambda key, default="": base.get(key, default)


def live_state(home, *, source="telegram", chat_id="42", chat_type="dm"):
    with sqlite3.connect(home/"state.db") as db:
        db.execute("CREATE TABLE sessions(id TEXT PRIMARY KEY,source TEXT,user_id TEXT,chat_id TEXT,chat_type TEXT,origin_json TEXT)")
        db.execute("INSERT INTO sessions VALUES(?,?,?,?,?,?)",("telegram-session",source,"42",chat_id,chat_type,"{}"))


def test_fresh_attachment_source_parses_only_exact_current_turn_cache_path(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME",str(tmp_path)); live_state(tmp_path)
    cache=tmp_path/"cache"/"documents"; cache.mkdir(parents=True)
    current=cache/"doc_current.txt"; current.write_bytes(b"hello world")
    extensionless=cache/"doc_extensionless"; extensionless.write_bytes(b"# Extensionless markdown\nbody")
    other=cache/"doc_other.txt"; other.write_bytes(b"other bytes")
    broker=Broker()
    service=history.HistoryService(
        api=API(), now_ms=lambda:NOW, broker_client=broker,
        context_reader=live_context({}),
        current_attachment_reader=lambda: (
            {"path":str(current),"message_id":"msg-1","platform":"telegram","chat_type":"dm","chat_id":"42","actor":"42"},
            {"path":str(extensionless),"message_id":"msg-1","platform":"telegram","chat_type":"dm","chat_id":"42","actor":"42"},
        ),
    )

    result=service.document_parse(
        {"source":{"kind":"attachment","path":str(current)}},
        session_id="telegram-session",turn_id="turn-1",
    )

    assert result["success"] is True
    assert broker.calls[0][0] == b"hello world"
    assert str(current) not in json.dumps(result)
    denied=service.document_parse(
        {"source":{"kind":"attachment","path":str(other)}},
        session_id="telegram-session",turn_id="turn-1",
    )
    assert denied == {"success":False,"error":"attachment_not_in_current_turn"}
    assert len(broker.calls)==1
    extensionless_result=service.document_parse(
        {"source":{"kind":"attachment","path":str(extensionless)}},
        session_id="telegram-session",turn_id="turn-1",
    )
    assert extensionless_result["success"] is True
    assert broker.calls[-1][0].startswith(b"# Extensionless markdown")


def test_durable_source_resolves_document_id_and_enforces_visibility(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME",str(tmp_path)); live_state(tmp_path)
    workspace=tmp_path.parent/"workspace"; monkeypatch.setenv("OMISA_WORKSPACE",str(workspace))
    doc_id="doc-0123456789abcdef"; doc_dir=workspace/"knowledge"/"documents"/doc_id; doc_dir.mkdir(parents=True)
    stored=doc_dir/"brief.txt"; stored.write_bytes(b"durable doc")
    service=history.HistoryService(api=API(),now_ms=lambda:NOW,broker_client=Broker(),context_reader=live_context({}))
    (doc_dir/"metadata.json").write_text(json.dumps({
        "document_id":doc_id,"stored_path":str(stored),"stored_filename":"brief.txt","size":stored.stat().st_size,
        "sha256":hashlib.sha256(stored.read_bytes()).hexdigest(),"visibility":"private",
        "source":{"schema":2,"sender_mac":service._durable_mac("sender","42"),"chat_mac":service._durable_mac("chat","42")},
    }))
    broker=service.broker_client

    parsed=service.document_parse(
        {"source":{"kind":"durable","document_id":doc_id}},
        session_id="telegram-session",turn_id="turn-1",
    )
    assert parsed["success"] is True, parsed
    read=service.document_read({"parse_ref":parsed["parse_ref"]},session_id="telegram-session",turn_id="turn-1")
    assert read["success"] is True

    other=history.HistoryService(api=API(),now_ms=lambda:NOW,broker_client=Broker(),context_reader=live_context({"HERMES_SESSION_USER_ID":"99"}))
    assert other.document_parse(
        {"source":{"kind":"durable","document_id":doc_id}},session_id="telegram-session",turn_id="turn-1"
    ) == {"success":False,"error":"access_denied"}
    assert stored.read_bytes()==b"durable doc"


def test_legacy_v1_private_metadata_remains_readable(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME",str(tmp_path)); live_state(tmp_path)
    workspace=tmp_path.parent/"workspace"; monkeypatch.setenv("OMISA_WORKSPACE",str(workspace))
    doc_id="doc-1020304050607080"; doc_dir=workspace/"knowledge"/"documents"/doc_id; doc_dir.mkdir(parents=True)
    stored=doc_dir/"legacy.txt"; stored.write_bytes(b"legacy durable")
    (doc_dir/"metadata.json").write_text(json.dumps({
        "document_id":doc_id,"stored_filename":"legacy.txt","size":stored.stat().st_size,
        "sha256":hashlib.sha256(stored.read_bytes()).hexdigest(),"visibility":"private",
        "source":{"sender_hash":hashlib.sha256(b"42").hexdigest()[:16],"chat_hash":hashlib.sha256(b"42").hexdigest()[:16]},
    }))
    service=history.HistoryService(api=API(),now_ms=lambda:NOW,broker_client=Broker(),context_reader=live_context({}))
    parsed=service.document_parse({"source":{"kind":"durable","document_id":doc_id}},session_id="telegram-session",turn_id="turn-1")
    assert parsed["success"] is True, parsed
    assert service.document_read({"parse_ref":parsed["parse_ref"]},session_id="telegram-session",turn_id="turn-1")["success"] is True


def test_team_document_is_scoped_to_saving_conversation(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME",str(tmp_path)); live_state(tmp_path)
    workspace=tmp_path.parent/"workspace"; monkeypatch.setenv("OMISA_WORKSPACE",str(workspace))
    doc_id="doc-a1b2c3d4e5f60718"; doc_dir=workspace/"knowledge"/"documents"/doc_id; doc_dir.mkdir(parents=True)
    stored=doc_dir/"notes.txt"; stored.write_bytes(b"team notes")
    service=history.HistoryService(api=API(),now_ms=lambda:NOW,broker_client=Broker(),context_reader=live_context({}))
    scope_mac=service._durable_mac("scope","telegram:dm:42")
    (doc_dir/"metadata.json").write_text(json.dumps({
        "document_id":doc_id,"stored_filename":"notes.txt","size":stored.stat().st_size,
        "sha256":hashlib.sha256(stored.read_bytes()).hexdigest(),"visibility":"team",
        "source":{"schema":2,"scope_mac":scope_mac},
    }))
    parsed=service.document_parse({"source":{"kind":"durable","document_id":doc_id}},session_id="telegram-session",turn_id="turn-1")
    assert parsed["success"] is True, parsed
    # Until an explicit team-membership authority exists, team is enforced as the
    # exact saving conversation — a different chat must fail closed.
    with sqlite3.connect(tmp_path/"state.db") as db:
        db.execute("INSERT INTO sessions VALUES(?,?,?,?,?,?)",("other-session","telegram","43","43","dm","{}"))
    other_chat=history.HistoryService(api=API(),now_ms=lambda:NOW,broker_client=Broker(),context_reader=live_context({"HERMES_SESSION_CHAT_ID":"43","HERMES_SESSION_USER_ID":"43","HERMES_SESSION_ID":"other-session"}))
    assert other_chat.document_parse({"source":{"kind":"durable","document_id":doc_id}},session_id="other-session",turn_id="turn-1")=={"success":False,"error":"access_denied"}


def test_durable_read_revokes_after_file_mutation(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME",str(tmp_path)); live_state(tmp_path)
    workspace=tmp_path.parent/"workspace"; monkeypatch.setenv("OMISA_WORKSPACE",str(workspace))
    doc_id="doc-5566778899aabbcc"; doc_dir=workspace/"knowledge"/"documents"/doc_id; doc_dir.mkdir(parents=True)
    stored=doc_dir/"mutable.txt"; stored.write_bytes(b"original")
    service=history.HistoryService(api=API(),now_ms=lambda:NOW,broker_client=Broker(),context_reader=live_context({}))
    (doc_dir/"metadata.json").write_text(json.dumps({
        "document_id":doc_id,"stored_filename":"mutable.txt","size":stored.stat().st_size,
        "sha256":hashlib.sha256(stored.read_bytes()).hexdigest(),"visibility":"team",
        "source":{"schema":2,"scope_mac":service._durable_mac("scope","telegram:dm:42")},
    }))
    parsed=service.document_parse({"source":{"kind":"durable","document_id":doc_id}},session_id="telegram-session",turn_id="turn-1")
    assert parsed["success"] is True
    stored.write_bytes(b"tampered")
    os.utime(stored,ns=(NOW*1_000_000,NOW*1_000_000))
    read=service.document_read({"parse_ref":parsed["parse_ref"]},session_id="telegram-session",turn_id="turn-1")
    assert read=={"success":False,"error":"artifact_revoked"}
    assert stored.read_bytes()==b"tampered"


def test_revoking_local_source_never_deletes_cache_or_durable_bytes(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME",str(tmp_path)); live_state(tmp_path)
    cache=tmp_path/"cache"/"documents"; cache.mkdir(parents=True)
    source=cache/"kept.txt"; source.write_text("keep")
    service=history.HistoryService(api=API(),now_ms=lambda:NOW,broker_client=Broker(),context_reader=live_context({}),current_attachment_reader=lambda:({"path":str(source),"message_id":"msg-1","platform":"telegram","chat_type":"dm","chat_id":"42","actor":"42"},))
    parsed=service.document_parse({"source":{"kind":"attachment","path":str(source)}},session_id="telegram-session",turn_id="turn-1")
    service.current_attachment_reader=lambda:()
    assert service.document_read({"parse_ref":parsed["parse_ref"]},session_id="telegram-session",turn_id="turn-1")["error"]=="artifact_revoked"
    assert source.read_text()=="keep"


def test_local_sources_reject_symlink_outside_oversize_and_cross_turn_read(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME",str(tmp_path)); live_state(tmp_path)
    cache=tmp_path/"cache"/"documents"; cache.mkdir(parents=True)
    outside=tmp_path/"secret.txt"; outside.write_text("secret")
    link=cache/"link.txt"; link.symlink_to(outside)
    huge=cache/"huge.pdf"
    with huge.open("wb") as stream: stream.truncate(history.MAX_ATTACHMENT_BYTES+1)
    broker=Broker()
    for path,expected in ((link,"attachment_not_in_current_turn"),(outside,"path_not_allowed"),(huge,"file_too_large")):
        service=history.HistoryService(api=API(),now_ms=lambda:NOW,broker_client=broker,context_reader=live_context({}),current_attachment_reader=lambda p=path:({"path":str(p),"message_id":"msg-1","platform":"telegram","chat_type":"dm","chat_id":"42","actor":"42"},))
        result=service.document_parse({"source":{"kind":"attachment","path":str(path)}},session_id="telegram-session",turn_id="turn-1")
        assert result["error"]==expected
    assert broker.calls==[]


def test_durable_source_rejects_metadata_id_id_size_digest_and_visibility_tampering(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME",str(tmp_path)); live_state(tmp_path)
    workspace=tmp_path.parent/"workspace"; monkeypatch.setenv("OMISA_WORKSPACE",str(workspace))
    doc_id="doc-fedcba9876543210"; doc_dir=workspace/"knowledge"/"documents"/doc_id; doc_dir.mkdir(parents=True)
    stored=doc_dir/"brief.txt"; stored.write_bytes(b"durable")
    base={"document_id":doc_id,"stored_path":str(stored),"stored_filename":"brief.txt","size":7,"sha256":hashlib.sha256(b"durable").hexdigest(),"visibility":"restricted","source":{"scope_hash":hashlib.sha256(b"telegram:dm:42").hexdigest()[:16]}}
    broker=Broker()
    for field,value in (("document_id","doc-0000000000000000"),("size",99),("sha256","0"*64),("visibility","public")):
        meta=dict(base);meta[field]=value;(doc_dir/"metadata.json").write_text(json.dumps(meta))
        service=history.HistoryService(api=API(),now_ms=lambda:NOW,broker_client=broker,context_reader=live_context({}))
        result=service.document_parse({"source":{"kind":"durable","document_id":doc_id}},session_id="telegram-session",turn_id="turn-1")
        assert result["success"] is False
    assert broker.calls==[]


def test_read_is_bounded_cursor_single_use_and_revalidates_before_release(setup):
    service,api,_,token,_=setup
    parsed=service.document_parse({"artifact_ref":token},session_id="s1",turn_id="t")
    first=service.document_read({"parse_ref":parsed["parse_ref"],"limit":2},session_id="s1",turn_id="t")
    assert first["success"] and len(first["records"])==2 and first["cursor"]
    second=service.document_read({"cursor":first["cursor"],"limit":10},session_id="s1",turn_id="t")
    assert second["success"] and second["cursor"] is None
    assert service.document_read({"cursor":first["cursor"]},session_id="s1",turn_id="t")["error"]=="replayed_parse_cursor"
    api.access=False
    assert service.document_read({"parse_ref":parsed["parse_ref"]},session_id="s1",turn_id="t")["error"]=="access_denied"


def test_read_caps_complete_serialized_utf8_response_and_cursor_has_exact_offset(setup):
    service,_,_,token,_=setup
    parsed=service.document_parse({"artifact_ref":token},session_id="s1",turn_id="t")
    rows=[{"schema":"omisa.document/1","type":"text","id":str(i),"text":"漢"*4000} for i in range(12)]
    encoded=json.dumps(rows,ensure_ascii=False,separators=(",",":"))
    with service._connect() as db:
        db.execute("UPDATE parse_cache SET records=?,record_bytes=? WHERE token=?",(encoded,len(encoded.encode("utf-8")),parsed["parse_ref"]))

    seen=[]
    args={"parse_ref":parsed["parse_ref"],"limit":50}
    cursors=[]
    while True:
        result=service.document_read(args,session_id="s1",turn_id="t")
        assert result["success"] is True
        assert len(json.dumps(result,ensure_ascii=False).encode("utf-8")) <= history.MAX_BYTES
        seen.extend(int(row["id"]) for row in result["records"])
        if result["cursor"] is None:
            break
        cursors.append(result["cursor"])
        args={"cursor":result["cursor"],"limit":50}
    assert seen == list(range(12))
    assert len(cursors) >= 2
    assert service.document_read({"cursor":cursors[0]},session_id="s1",turn_id="t")["error"] == "replayed_parse_cursor"


def test_read_returns_record_too_large_without_partial_record_or_cursor(setup):
    service,_,_,token,_=setup
    parsed=service.document_parse({"artifact_ref":token},session_id="s1",turn_id="t")
    rows=[{"schema":"omisa.document/1","type":"text","id":"huge","text":"漢"*30000}]
    encoded=json.dumps(rows,ensure_ascii=False,separators=(",",":"))
    with service._connect() as db:
        db.execute("UPDATE parse_cache SET records=?,record_bytes=? WHERE token=?",(encoded,len(encoded.encode("utf-8")),parsed["parse_ref"]))
    result=service.document_read({"parse_ref":parsed["parse_ref"],"limit":50},session_id="s1",turn_id="t")
    assert result == {"success":False,"error":"record_too_large"}
    assert len(json.dumps(result,ensure_ascii=False).encode("utf-8")) <= history.MAX_BYTES


def test_source_artifact_matches_legacy_and_mixed_contract_is_rejected(setup):
    service,_,broker,token,_=setup
    modern=service.document_parse({"source":{"kind":"artifact","artifact_ref":token}},session_id="s1",turn_id="t")
    legacy=service.document_parse({"artifact_ref":token},session_id="s1",turn_id="t")
    assert modern==legacy and modern["success"] is True and len(broker.calls)==1
    assert service.document_parse({"artifact_ref":token,"source":{"kind":"artifact","artifact_ref":token}},session_id="s1",turn_id="t")["error"]=="invalid_argument"


@pytest.mark.parametrize("mutation", ["replace", "symlink", "expire", "scope", "descriptor"])
def test_parse_rejects_substitution_expiry_cross_scope_and_revocation_without_broker(setup, mutation):
    service,api,broker,token,path=setup
    if mutation=="replace":
        path.unlink(); path.write_bytes(b"HELLO WORLD")
    elif mutation=="symlink":
        path.unlink(); outside=path.parent.parent/"outside"; outside.write_bytes(b"hello world"); path.symlink_to(outside)
    elif mutation=="expire":
        with service._connect() as db: db.execute("UPDATE artifacts SET expires_ms=? WHERE token=?",(NOW-1,token))
    elif mutation=="scope":
        service.context_reader=lambda k,d="": "other" if k=="HERMES_SESSION_USER_ID" else context(k,d)
    else:
        api.raw["body"]["attachments"][0]["payload"]["fileId"]="changed"
    result=service.document_parse({"artifact_ref":token},session_id="s1",turn_id="t")
    assert result["success"] is False and broker.calls==[]


def test_no_broker_connection_before_current_authorization(setup):
    service,api,broker,token,_=setup; api.access=False
    assert service.document_parse({"artifact_ref":token},session_id="s1",turn_id="t")["error"]=="access_denied"
    assert broker.calls==[]


def test_malformed_or_disconnected_broker_response_is_categorical_and_not_cached(setup):
    service,_,broker,token,_=setup
    broker.parse_fd=lambda *a,**k: (_ for _ in ()).throw(history.BrokerClientError("broker_disconnect"))
    assert service.document_parse({"artifact_ref":token},session_id="s1",turn_id="t")["error"]=="broker_unavailable"
    with service._connect() as db: assert db.execute("SELECT COUNT(*) FROM parse_cache").fetchone()[0]==0


def test_broker_policy_errors_are_not_mislabeled_unavailable(setup):
    service,_,broker,token,_=setup
    for code in ("active_content_policy","archive_policy_violation","malformed_document","input_too_large"):
        broker.parse_fd=lambda *a,_code=code,**k: (_ for _ in ()).throw(history.BrokerClientError(_code))
        assert service.document_parse({"artifact_ref":token},session_id="s1",turn_id="t")["error"]==code


def test_nonempty_malformed_broker_response_is_rejected(setup):
    service,_,broker,token,_=setup
    broker.parse_fd=lambda *a,**k:[{"path":"/tmp/secret"}]
    assert service.document_parse({"artifact_ref":token},session_id="s1",turn_id="t")["error"]=="malformed_parser_response"


def test_descriptor_mutation_during_broker_call_is_detected(setup):
    service,_,broker,token,path=setup
    original=broker.parse_fd
    def mutate(fd,**kwargs):
        rows=original(fd,**kwargs); path.write_bytes(b"changed-size"); return rows
    broker.parse_fd=mutate
    assert service.document_parse({"artifact_ref":token},session_id="s1",turn_id="t")["error"]=="artifact_changed"


def test_parse_cleanup_removes_expired_private_cache(setup):
    service,_,_,token,_=setup
    ref=service.document_parse({"artifact_ref":token},session_id="s1",turn_id="t")["parse_ref"]
    with service._connect() as db: db.execute("UPDATE parse_cache SET expires_ms=?",(NOW-1,))
    with service._connect() as db: assert db.execute("SELECT 1 FROM parse_cache WHERE token=?",(ref,)).fetchone() is None