import importlib.util
import json
import os
import re
import sqlite3
import sys
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT))
import history

NOW = 1_788_345_600_000
START = "2026-09-02T07:00:00Z"
END = "2026-09-02T08:00:00Z"


class FakeAPI:
    def __init__(self, pages=(), exact=None, access=True, error=None):
        self.pages=list(pages); self.exact=exact or {}; self.access=access; self.error=error; self.calls=[]
    def check_group_access(self, chat_id):
        self.calls.append(("access",chat_id)); return self.access
    def get_messages(self, *, chat_id=None, message_ids=None, upper_ms=None, lower_ms=None, count=100):
        self.calls.append(("messages",chat_id,message_ids,upper_ms,lower_ms,count))
        if self.error: raise self.error
        if message_ids is not None: return [self.exact[x] for x in message_ids if x in self.exact]
        return self.pages.pop(0) if self.pages else []


def msg(mid, ts, text="hello", chat="-900", attachments=None):
    return {"timestamp":ts,"recipient":{"chat_id":chat},"sender":{"user_id":"u1","name":"Alice"},"body":{"mid":mid,"text":text,"attachments":attachments or []}}


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME",str(tmp_path))
    db=sqlite3.connect(tmp_path/"state.db")
    db.execute("CREATE TABLE sessions(id TEXT PRIMARY KEY,source TEXT,user_id TEXT,chat_id TEXT,chat_type TEXT,origin_json TEXT)")
    db.execute("INSERT INTO sessions VALUES(?,?,?,?,?,?)",("s1","max","old-user","-900","group","{}"));db.commit();db.close()
    (tmp_path/"config.yaml").write_text("platforms:\n  max:\n    groups:\n      allowed_chats: [-900]\n    ca_bundle: /scoped/ca.pem\n")
    return tmp_path


def reader(key, default=""):
    return {"HERMES_SESSION_PLATFORM":"max","HERMES_SESSION_CHAT_TYPE":"group","HERMES_SESSION_CHAT_ID":"-900","HERMES_SESSION_USER_ID":"live-user","HERMES_SESSION_ID":"s1","HERMES_SESSION_MESSAGE_ID":"inbound","HERMES_SESSION_PROFILE":"default","HERMES_CRON_SESSION":""}.get(key,default)


def result_messages(result):
    return result["untrusted_history"]["messages"]


def service(api): return history.HistoryService(api=api,now_ms=lambda:NOW,context_reader=reader)


def test_time_parser_strict_bounds_and_integer_milliseconds():
    assert history.parse_interval("2026-09-02T07:00:00.123999Z",END,NOW)[0] % 1000 == 123
    for start,end,error in [("2026-09-02T07:00:00",END,"invalid_time"),(END,START,"invalid_interval"),("2026-08-31T00:00:00Z","2026-09-01T00:00:01Z","approval_required"),(START,"2030-01-01T00:00:00Z","future_interval")]:
        with pytest.raises(ValueError,match=error): history.parse_interval(start,end,NOW)


def test_search_filters_deduplicates_sanitizes_and_caps(home):
    start,_=history.parse_interval(START,END,NOW)
    att=[{"type":"file","payload":{"filename":"../safe.pdf","size":12,"url":"https://secret","token":"bad"}}]
    values=[msg(str(i),start+2000-i,"Needle "+"x"*800,attachments=att) for i in range(60)]
    result=service(FakeAPI([values])).search({"start_time":START,"end_time":END,"query":"needle","has_attachments":True,"limit":50},session_id="s1",turn_id="t")
    assert result["success"] and 1 <= len(result_messages(result)) <= 50
    assert len(json.dumps(result,ensure_ascii=False).encode())<=65536
    encoded=json.dumps(result).lower();assert "https://" not in encoded and '"token"' not in encoded
    sanitized=result_messages(result)[0]["attachments"][0]
    assert {k:sanitized[k] for k in ("kind","filename","declared_size")}=={"kind":"file","filename":"safe.pdf","declared_size":12}
    assert re.fullmatch(r"[A-Za-z0-9_-]{40,64}",sanitized["attachment_ref"])


def test_pagination_uses_inclusive_bounds_then_oldest_minus_one(home):
    start,end=history.parse_interval(START,END,NOW)
    page=[msg(str(i),start+2000-i) for i in range(100)]
    api=FakeAPI([page,[msg("last",start)]])
    result=service(api).search({"start_time":START,"end_time":END},session_id="s1",turn_id="t")
    calls=[x for x in api.calls if x[0]=="messages"]
    assert calls[0][3:]==(end,start,100)
    assert calls[1][3:]==(start+1900,start,100)
    assert result["success"]


def test_fetch_returns_categorical_missing_and_rejects_cross_chat(home):
    start,_=history.parse_interval(START,END,NOW); original=msg("m",start+1)
    api=FakeAPI([[original]],{"m":msg("m",start+1,chat="other")}); svc=service(api)
    searched=svc.search({"start_time":START,"end_time":END},session_id="s1",turn_id="t")
    ref=result_messages(searched)[0]["message_ref"]
    result=svc.fetch({"message_refs":[ref]},session_id="s1",turn_id="t")
    assert result["error"]=="scope_mismatch"
    # A separate search capability with absent exact result returns no cached text.
    svc2=service(FakeAPI([[original]],{})); searched2=svc2.search({"start_time":START,"end_time":END},session_id="s1",turn_id="u"); ref2=result_messages(searched2)[0]["message_ref"]
    result2=svc2.fetch({"message_refs":[ref2]},session_id="s1",turn_id="u")
    assert result_messages(result2)==[{"message_ref":ref2,"state":"removed_or_not_found"}]


def test_timeout_is_categorical_and_canary_absent_from_audit(home):
    result=service(FakeAPI(error=TimeoutError("SECRET transport"))).search({"start_time":START,"end_time":END},session_id="s1",turn_id="t")
    assert result=={"success":False,"error":"timeout"}
    with sqlite3.connect(home/"omisa-history"/"history.db") as db:
        assert "SECRET" not in repr(db.execute("SELECT * FROM audit").fetchall())


def test_audit_hmac_and_retention_boundary(home):
    start,_=history.parse_interval(START,END,NOW)
    assert service(FakeAPI([[msg("secret-mid",start+1,"TOP SECRET")]])).search({"start_time":START,"end_time":END,"query":"SECRET"},session_id="s1",turn_id="t")["success"]
    path=home/"omisa-history"/"history.db"
    with sqlite3.connect(path) as db:
        rows=db.execute("SELECT actor_pseudonym,chat_pseudonym,filter_shape FROM audit").fetchall()
    joined=repr(rows);assert all(x not in joined for x in ("live-user","-900","TOP SECRET","secret-mid","SECRET"))
    assert path.stat().st_mode & 0o777 == 0o600
    assert (home/"omisa-history"/"audit.key").stat().st_mode & 0o777 == 0o600


def test_default_transport_contract_and_permission_probe(monkeypatch,home):
    observed={}
    class Response:
        status_code=200
        def raise_for_status(self): pass
        def json(self): return {"is_admin":True,"permissions":["read_all_messages"],"messages":[]}
    class Client:
        def __init__(self,**kw): observed["client"]=kw
        def __enter__(self):return self
        def __exit__(self,*a):pass
        def get(self,path,params):observed.setdefault("requests",[]).append((path,params));return Response()
    monkeypatch.setattr(httpx,"Client",Client)
    api=history.MaxHistoryAPI(token="bot-secret",ca_bundle="/scoped/ca.pem",timeout=99)
    assert api.check_group_access("-900") is True
    api.get_messages(chat_id="-900",upper_ms=2,lower_ms=1,count=999)
    client=observed["client"]
    assert client["base_url"]=="https://platform-api2.max.ru" and client["trust_env"] is False and client["follow_redirects"] is False
    assert client["verify"]=="/scoped/ca.pem" and client["headers"]=={"Authorization":"bot-secret"}
    assert observed["requests"]==[("/chats/-900/members/me",{}),("/messages",{"count":100,"chat_id":"-900","from":2,"to":1})]


def test_plugin_loader_registration_has_closed_schemas(home):
    class Ctx:
        def __init__(self):self.tools=[];self.hooks=[]
        def register_tool(self,**kw):self.tools.append(kw)
        def register_hook(self,name,callback):self.hooks.append((name,callback))
    spec=importlib.util.spec_from_file_location("omisa_history_probe",ROOT/"__init__.py",submodule_search_locations=[str(ROOT)])
    module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
    ctx=Ctx();module.register(ctx)
    assert {x["name"] for x in ctx.tools}=={"history_search","history_fetch","history_attachment_fetch","history_attachment_read","archive_inspect","archive_extract","document_parse","document_read"}
    assert all(x["schema"]["parameters"]["additionalProperties"] is False for x in ctx.tools)
    parse=next(x["schema"] for x in ctx.tools if x["name"]=="document_parse")["parameters"]
    assert len(parse["properties"]["source"]["oneOf"])==3
    assert [row["properties"]["kind"]["const"] for row in parse["properties"]["source"]["oneOf"]]==["artifact","attachment","durable"]
    assert [x[0] for x in ctx.hooks]==["pre_tool_call"]
