import importlib.util
import json
import os
import re
import sqlite3
import subprocess
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT))
import history

NOW = 1_788_345_600_000
START = "2026-09-02T07:00:00Z"
END = "2026-09-02T08:00:00Z"


class API:
    def __init__(self, pages=(), exact=None, access=True, before_release=None):
        self.pages = list(pages)
        self.exact = exact or {}
        self.access = access
        self.calls = []
        self.before_release = before_release

    def check_group_access(self, chat_id):
        self.calls.append(("access", chat_id))
        return self.access

    def get_messages(self, *, chat_id=None, message_ids=None, upper_ms=None, lower_ms=None, count=100):
        self.calls.append(("messages", chat_id, message_ids, upper_ms, lower_ms, count))
        if message_ids is not None:
            return [self.exact[x] for x in message_ids if x in self.exact]
        return self.pages.pop(0) if self.pages else []


def message(mid="m1", ts=1_788_300_001_000, text="hello", chat="-900", sender="Alice", attachments=None):
    return {"timestamp": ts, "recipient": {"chat_id": chat},
            "sender": {"user_id": "raw-user", "name": sender},
            "body": {"mid": mid, "text": text, "attachments": attachments or []}}


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    db = sqlite3.connect(tmp_path / "state.db")
    db.execute("CREATE TABLE sessions(id TEXT PRIMARY KEY,source TEXT,user_id TEXT,chat_id TEXT,chat_type TEXT,origin_json TEXT)")
    db.execute("INSERT INTO sessions VALUES(?,?,?,?,?,?)", ("s'1", "max", "creator-A", "-900", "group", "{}"))
    db.execute("INSERT INTO sessions VALUES(?,?,?,?,?,?)", ("s2", "max", "x", "g2", "group", "{}"))
    db.commit(); db.close()
    (tmp_path / "config.yaml").write_text("platforms:\n  max:\n    groups:\n      allowed_chats: [-900]\n    ca_bundle: /ca.pem\n")
    return tmp_path


def context(**overrides):
    values = {"HERMES_SESSION_PLATFORM": "max", "HERMES_SESSION_CHAT_TYPE": "group",
              "HERMES_SESSION_CHAT_ID": "-900", "HERMES_SESSION_USER_ID": "sender-B",
              "HERMES_SESSION_ID": "s'1", "HERMES_SESSION_MESSAGE_ID": "inbound-1",
              "HERMES_SESSION_PROFILE": "default", "HERMES_CRON_SESSION": ""}
    values.update(overrides)
    return lambda key, default="": values.get(key, default)


def svc(home, api=None, ctx=None):
    return history.HistoryService(api=api or API(), now_ms=lambda: NOW,
                                  context_reader=ctx or context())


def result_messages(result):
    return result["untrusted_history"]["messages"]


def test_trusted_live_context_exactly_matches_session_and_attributes_current_sender(home):
    api = API([[]])
    result = svc(home, api).search({"start_time": START, "end_time": END}, session_id="s'1", turn_id="turn-1")
    assert result["success"] is True
    assert api.calls
    with sqlite3.connect(home / "omisa-history" / "history.db") as db:
        actor = db.execute("SELECT actor_pseudonym FROM audit ORDER BY rowid DESC LIMIT 1").fetchone()[0]
    assert actor and "sender-B" not in actor and "creator-A" not in actor


@pytest.mark.parametrize("ctx_overrides,session_id", [
    ({"HERMES_SESSION_CHAT_ID": "g2"}, "s'1"),
    ({"HERMES_SESSION_USER_ID": ""}, "s'1"),
    ({"HERMES_CRON_SESSION": "1"}, "s'1"),
    ({"HERMES_SESSION_MESSAGE_ID": ""}, "s'1"),
    ({"HERMES_SESSION_CHAT_TYPE": "dm"}, "s'1"),
    ({"HERMES_SESSION_PLATFORM": "telegram"}, "s'1"),
    ({}, "s2"),
])
def test_untrusted_or_mismatched_invocation_denies_before_network(home, ctx_overrides, session_id):
    api = API()
    result = svc(home, api, context(**ctx_overrides)).search({"start_time": START, "end_time": END}, session_id=session_id, turn_id="turn-1")
    assert result["success"] is False
    assert api.calls == []


def test_model_scope_and_unknown_arguments_are_rejected_before_network(home):
    forbidden = ["chat_id", "platform", "session_id", "sender_user_id", "destination", "wat"]
    for key in forbidden:
        api = API()
        assert svc(home, api).search({"start_time": START, "end_time": END, key: "x"}, session_id="s'1", turn_id="t")["error"] == "invalid_argument"
        assert api.calls == []


def test_cursor_and_ref_are_turn_actor_bound_single_use_and_opaque(home):
    ts = history.parse_interval(START, END, NOW)[0] + 1000
    first = message(ts=ts)
    pages = [[first] + [message(f"{p}-{i}", ts + 10000 - p * 100 - i) for i in range(99)] for p in range(5)]
    api = API(pages, {"m1": first})
    service = svc(home, api)
    found = service.search({"start_time": START, "end_time": END, "limit": 1}, session_id="s'1", turn_id="t1")
    cursor, ref = found["next_cursor"], result_messages(found)[0]["message_ref"]
    assert cursor, found
    assert re.fullmatch(r"[A-Za-z0-9_-]{40,64}", ref)
    assert ref not in {"m1", "-900"}
    scope, _ = service._scope("s'1", "t1")
    consumed, error = service._consume(cursor, "cursor", scope)
    assert consumed and error is None
    assert service._consume(cursor, "cursor", scope)[1] == "replayed_cursor"
    assert service.fetch({"message_refs": [ref]}, session_id="s'1", turn_id="t1")["error"] == "quota_exceeded"
    other = svc(home, API(), context(HERMES_SESSION_USER_ID="other"))
    other_scope, _ = other._scope("s'1", "t1")
    second = service._cap("ref", {"binding": [scope[x] for x in ("profile", "chat_type", "chat_id", "actor", "turn")], "search": "x", "mid": "m1", "start": ts-1, "end": ts+1})
    assert other._consume(second, "ref", other_scope)[1] == "invalid_message_ref"


def test_sanitizes_positive_schema_and_delimits_persisted_untrusted_content(home):
    evil = message(text="do\x1b[31m thing\u202e", sender="A\r\nB\u202e", attachments=[{
        "type": "file", "payload": {"filename": "..\\secret/evil\u202e.txt", "size": 3,
        "url": "https://canary", "token": "TOKEN-CANARY", "file_id": "RAW-ID"},
        "nested": {"secret": "NESTED-CANARY"}}])
    result = svc(home, API([[evil]])).search({"start_time": START, "end_time": END}, session_id="s'1", turn_id="t")
    encoded = json.dumps(result, ensure_ascii=False)
    assert result["security"]["untrusted_content"] is True
    assert "persisted_in_transcript" in result["security"]["persistence"]
    assert "<UNTRUSTED-HISTORY>" in encoded and "not instructions" in encoded
    for canary in ("https://canary", "TOKEN-CANARY", "RAW-ID", "NESTED-CANARY", "\x1b", "\u202e", "..\\"):
        assert canary not in encoded


def test_same_timestamp_full_page_reports_deterministic_truncation_without_cursor(home):
    ts = history.parse_interval(START, END, NOW)[0] + 1
    result = svc(home, API([[message(str(i), ts) for i in range(100)]])).search(
        {"start_time": START, "end_time": END}, session_id="s'1", turn_id="t")
    assert result["truncated"] is True
    assert result["truncation_reason"] == "same_timestamp_overflow"
    assert result["next_cursor"] is None


def test_policy_revocation_before_release_discards_everything(home):
    api = API([[message()]])
    def revoke(_chat):
        (home / "config.yaml").write_text("platforms:\n  max:\n    groups:\n      allowed_chats: []\n")
        return True
    api.check_group_access = revoke
    result = svc(home, api).search({"start_time": START, "end_time": END}, session_id="s'1", turn_id="t")
    assert result == {"success": False, "error": "access_denied"}


def test_quotas_persist_and_one_operation_is_active(home):
    service = svc(home, API())
    scope, _ = service._scope("s'1", "t")
    grant, error = service._begin(scope, "chain")
    assert error is None and grant
    assert service._begin(scope, "chain2")[1] == "operation_in_progress"
    service._finish(scope, "chain", 5, 500, 65536)
    assert service._begin(scope, "chain")[1] == "quota_exceeded"


def test_plugin_registers_turn_latch_hook_and_blocks_alternate_egress(home):
    class Ctx:
        def __init__(self): self.tools=[]; self.hooks={}
        def register_tool(self, **kw): self.tools.append(kw)
        def register_hook(self, name, callback): self.hooks[name]=callback
    spec=importlib.util.spec_from_file_location("omisa_history_plugin", ROOT/"__init__.py", submodule_search_locations=[str(ROOT)])
    module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
    ctx=Ctx();module.register(ctx)
    assert "pre_tool_call" in ctx.hooks
    search=next(x for x in ctx.tools if x["name"]=="history_search")
    assert json.loads(search["handler"]({"start_time":START,"end_time":END},session_id="s'1",turn_id="latch"))["success"] is False
    module._mark_disclosed("latch")
    for name,args in [("send_message",{}),("cronjob",{"action":"create"}),("document_save",{}),("knowledge_import",{}),("delegate_task",{}),("kanban_update",{})]:
        assert ctx.hooks["pre_tool_call"](tool_name=name,args=args,turn_id="latch")["action"]=="block"
    assert ctx.hooks["pre_tool_call"](tool_name="read_file",args={},turn_id="latch")["action"] == "block"
    assert ctx.hooks["pre_tool_call"](tool_name="history_attachment_read",args={},turn_id="latch") is None
    assert ctx.hooks["pre_tool_call"](tool_name="totally_unknown",args={},turn_id="latch")["action"] == "block"


def test_disclosure_latch_is_visible_across_fresh_hook_worker_thread(home):
    class Ctx:
        def __init__(self): self.hooks = {}
        def register_tool(self, **kw): pass
        def register_hook(self, name, callback): self.hooks[name] = callback
    spec = importlib.util.spec_from_file_location("omisa_history_cross_thread", ROOT/"__init__.py", submodule_search_locations=[str(ROOT)])
    module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module; spec.loader.exec_module(module)
    ctx = Ctx(); module.register(ctx)
    marker = threading.Thread(target=lambda: module._mark_disclosed("thread-turn"))
    marker.start(); marker.join()
    result = []
    checker = threading.Thread(target=lambda: result.append(
        ctx.hooks["pre_tool_call"](tool_name="send_message", args={}, turn_id="thread-turn")
    ))
    checker.start(); checker.join()
    assert result == [{"action":"block","message":"History disclosure turn: alternate egress and persistence are blocked."}]


def test_disclosure_latch_is_cross_process_and_concurrent_connections_fail_closed(home):
    marker = """
import importlib.util, os, pathlib, sys
root=pathlib.Path(os.environ['PLUGIN_ROOT'])
spec=importlib.util.spec_from_file_location('marker_plugin',root/'__init__.py',submodule_search_locations=[str(root)])
module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
assert module._mark_disclosed('process-turn') is True
"""
    checker = """
import importlib.util, json, os, pathlib, sys
root=pathlib.Path(os.environ['PLUGIN_ROOT'])
spec=importlib.util.spec_from_file_location('checker_plugin',root/'__init__.py',submodule_search_locations=[str(root)])
module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
print(json.dumps(module._on_pre_tool_call(tool_name='send_message',args={},turn_id='process-turn')))
"""
    env=dict(os.environ,HERMES_HOME=str(home),PLUGIN_ROOT=str(ROOT))
    subprocess.run([sys.executable,"-c",marker],env=env,check=True)
    workers=[subprocess.Popen([sys.executable,"-c",checker],env=env,stdout=subprocess.PIPE,text=True) for _ in range(6)]
    outputs=[worker.communicate(timeout=10)[0] for worker in workers]
    assert all(worker.returncode==0 for worker in workers)
    assert all(json.loads(value)["action"]=="block" for value in outputs)
    latch=home/"omisa-history"/"disclosure.db"
    assert latch.stat().st_mode & 0o777 == 0o600


def test_disclosure_latch_db_error_blocks_history_and_other_tools(home, monkeypatch):
    class Broken:
        def __enter__(self): raise sqlite3.OperationalError("CANARY")
        def __exit__(self,*_args): pass
    monkeypatch.setattr(history.HistoryService,"_connect",lambda _self:Broken())
    # Force the plugin latch path itself to fail rather than any HistoryService call.
    class Ctx:
        def __init__(self): self.hooks={}
        def register_tool(self,**_kwargs): pass
        def register_hook(self,name,callback): self.hooks[name]=callback
    spec=importlib.util.spec_from_file_location("omisa_history_broken_latch",ROOT/"__init__.py",submodule_search_locations=[str(ROOT)])
    module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
    monkeypatch.setattr(module,"_latch_connect",lambda: (_ for _ in ()).throw(sqlite3.OperationalError("CANARY")))
    ctx=Ctx();module.register(ctx);hook=ctx.hooks["pre_tool_call"]
    assert hook(tool_name="history_search",args={},turn_id="db-fail")["action"]=="block"
    assert hook(tool_name="send_message",args={},turn_id="db-fail")["action"]=="block"


def test_disclosure_latch_cannot_be_bypassed_by_omitting_available_identity(home):
    class Ctx:
        def __init__(self): self.hooks={}
        def register_tool(self,**_kwargs): pass
        def register_hook(self,name,callback): self.hooks[name]=callback
    spec=importlib.util.spec_from_file_location("omisa_history_identity_latch",ROOT/"__init__.py",submodule_search_locations=[str(ROOT)])
    module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
    assert module._mark_disclosed("identity-turn",actor="a",chat_id="-900",session_id="s'1") is True
    ctx=Ctx();module.register(ctx)
    assert ctx.hooks["pre_tool_call"](tool_name="send_message",args={},turn_id="identity-turn")["action"]=="block"


def test_disclosure_latch_normalizes_trusted_turn_before_cross_identity_fallback(home):
    class Ctx:
        def __init__(self): self.hooks={}
        def register_tool(self,**_kwargs): pass
        def register_hook(self,name,callback): self.hooks[name]=callback
    spec=importlib.util.spec_from_file_location("omisa_history_normalized_latch",ROOT/"__init__.py",submodule_search_locations=[str(ROOT)])
    module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
    assert module._mark_disclosed(" normalized-turn ",actor="a",chat_id="-900",session_id="s'1") is True
    ctx=Ctx();module.register(ctx)
    assert ctx.hooks["pre_tool_call"](tool_name="send_message",args={},turn_id="normalized-turn")["action"]=="block"


def test_disclosure_latch_expired_exact_binding_cannot_hide_active_fallback(home, monkeypatch):
    spec=importlib.util.spec_from_file_location("omisa_history_expiry_order_latch",ROOT/"__init__.py",submodule_search_locations=[str(ROOT)])
    module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
    clock=[1000.0];monkeypatch.setattr(module.time,"time",lambda:clock[0])
    exact={"actor":"a","chat_id":"-900","session_id":"s'1"}
    fallback={"actor":"b","chat_id":"-901","session_id":"s'2"}
    assert module._mark_disclosed("shared-turn",**exact) is True
    assert module._mark_disclosed("shared-turn",**fallback) is True
    exact_binding=module._latch_identity("shared-turn",**exact)
    fallback_binding=module._latch_identity("shared-turn",**fallback)
    with module._latch_connect() as db:
        db.execute("UPDATE disclosure_latch SET expires_ms=? WHERE binding=?",(999999,exact_binding))
        db.execute("UPDATE disclosure_latch SET expires_ms=? WHERE binding=?",(2000000,fallback_binding))
    clock[0]=1000.0
    # The exact binding is expired, but another active row for this trusted turn
    # must still trigger the conservative cross-worker fallback.
    assert module._turn_was_disclosed("shared-turn",**exact) is True


def test_disclosure_latch_sliding_ttl_preserves_active_turn_then_expires(home, monkeypatch):
    class Ctx:
        def __init__(self): self.hooks={}
        def register_tool(self,**_kwargs): pass
        def register_hook(self,name,callback): self.hooks[name]=callback
    spec=importlib.util.spec_from_file_location("omisa_history_ttl_latch",ROOT/"__init__.py",submodule_search_locations=[str(ROOT)])
    module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
    clock=[1000.0];monkeypatch.setattr(module.time,"time",lambda:clock[0])
    assert module._mark_disclosed("ttl-turn") is True
    clock[0]+=(module._DISCLOSURE_TTL_MS-1)/1000
    assert module._turn_was_disclosed("ttl-turn") is True
    clock[0]+=(module._DISCLOSURE_TTL_MS-1)/1000
    assert module._turn_was_disclosed("ttl-turn") is True
    clock[0]+=(module._DISCLOSURE_TTL_MS+1)/1000
    assert module._turn_was_disclosed("ttl-turn") is False


def test_http_client_disables_env_redirects_and_uses_scoped_ca(monkeypatch, home):
    observed={}
    class Resp:
        status_code=200
        def raise_for_status(self): pass
        def json(self): return {"messages":[]}
    class Client:
        def __init__(self,**kwargs):observed.update(kwargs)
        def __enter__(self):return self
        def __exit__(self,*a):pass
        def get(self,path,params):return Resp()
    import httpx
    monkeypatch.setattr(httpx,"Client",Client)
    history.MaxHistoryAPI(token="secret",ca_bundle="/ca.pem").get_messages(chat_id="-900",upper_ms=2,lower_ms=1)
    assert observed["base_url"]=="https://platform-api2.max.ru"
    assert observed["follow_redirects"] is False and observed["trust_env"] is False
    assert observed["verify"]=="/ca.pem"


def test_atomic_last_slot_allows_only_one_concurrent_operation(home):
    one = svc(home, API()); two = svc(home, API())
    scope, _ = one._scope("s'1", "parallel")
    barrier = threading.Barrier(3); results = []
    def run(service, chain):
        barrier.wait(); results.append(service._begin(scope, chain)[1])
    threads = [threading.Thread(target=run, args=(one, "a")), threading.Thread(target=run, args=(two, "b"))]
    for thread in threads: thread.start()
    barrier.wait()
    for thread in threads: thread.join()
    assert sorted(str(x) for x in results) == ["None", "operation_in_progress"]


def test_audit_retention_deletes_strictly_older_than_ninety_days(home):
    service = svc(home, API()); scope, _ = service._scope("s'1", "t")
    with service._connect() as db:
        old = NOW - history.RETENTION_MS - 1
        boundary = NOW - history.RETENTION_MS
        row = ("op", "a", "c", "ok", None, "none", "{}", 0, 0, 0)
        db.execute("INSERT INTO audit VALUES(?,?,?,?,?,?,?,?,?,?,?)", (old, *row))
        db.execute("INSERT INTO audit VALUES(?,?,?,?,?,?,?,?,?,?,?)", (boundary, *row))
    service._audit(scope, "search", "success")
    with service._connect() as db:
        stamps = [x[0] for x in db.execute("SELECT ts_ms FROM audit ORDER BY ts_ms")]
    assert old not in stamps and boundary in stamps


def test_remaining_turn_page_budget_cannot_be_overshot(home):
    service = svc(home, API())
    scope, _ = service._scope("s'1", "turn-budget")
    with service._connect() as db:
        actor = service._pseudo("actor", scope["actor"])
        chat = service._pseudo("chat", scope["chat_id"])
        db.execute(
            "INSERT INTO usage VALUES(?,?,?,?,?,?,?,?,?)",
            (NOW, actor, chat, scope["turn"], "prior", 0, 4, 400, 1024),
        )
    grant, error = service._begin(scope, "next")
    assert error is None
    assert grant["pages"] == 1
    assert grant["candidates"] == 100
    service._finish(scope, "next", 1, 100, 1024)


def test_stale_active_lease_is_reaped_but_live_lease_blocks(home):
    service = svc(home, API())
    scope, _ = service._scope("s'1", "lease")
    actor = service._pseudo("actor", scope["actor"])
    chat = service._pseudo("chat", scope["chat_id"])
    with service._connect() as db:
        db.execute("INSERT INTO active(actor,chat,turn,started_ms) VALUES(?,?,?,?)", (actor, chat, "crashed", NOW-history.ACTIVE_LEASE_MS-1))
    grant, error = service._begin(scope, "after-crash")
    assert error is None and grant
    assert service._begin(scope, "parallel")[1] == "operation_in_progress"
    service._finish(scope, "after-crash", 0, 0, 0)


def test_untrusted_delimiters_structurally_enclose_messages(home):
    result = svc(home, API([[message()]])).search(
        {"start_time": START, "end_time": END}, session_id="s'1", turn_id="wrapped"
    )
    quoted = result["untrusted_history"]
    assert quoted["delimiter_start"] == "<UNTRUSTED-HISTORY>"
    assert quoted["messages"] is result_messages(result)
    assert quoted["delimiter_end"] == "</UNTRUSTED-HISTORY>"


def test_non_numeric_chat_scope_denies_before_api_path_construction(home):
    with sqlite3.connect(home / "state.db") as db:
        db.execute("UPDATE sessions SET chat_id=? WHERE id=?", ("../members/me?leak", "s'1"))
    api = API()
    result = svc(home, api, context(HERMES_SESSION_CHAT_ID="../members/me?leak")).search(
        {"start_time": START, "end_time": END}, session_id="s'1", turn_id="bad-chat"
    )
    assert result["error"] == "invalid_session_scope"
    assert api.calls == []


def test_search_rejects_cross_chat_api_response_before_snippet_disclosure(home):
    api = API([[message(chat="-901", text="CROSS-CHAT-CANARY")]])
    result = svc(home, api).search(
        {"start_time": START, "end_time": END}, session_id="s'1", turn_id="cross"
    )
    assert result == {"success": False, "error": "access_denied"}
    assert "CROSS-CHAT-CANARY" not in json.dumps(result)


def test_runtime_malformed_args_are_categorical(home):
    service = svc(home, API())
    for value in (None, [], "oops"):
        assert service.search(value, session_id="s'1", turn_id="bad")["error"] == "invalid_argument"
        assert service.fetch(value, session_id="s'1", turn_id="bad")["error"] == "invalid_argument"


def test_history_marker_in_tool_precheck_blocks_same_turn_egress(home):
    class Ctx:
        def __init__(self): self.hooks = {}
        def register_tool(self, **kw): pass
        def register_hook(self, name, callback): self.hooks[name] = callback
    spec = importlib.util.spec_from_file_location("omisa_history_precheck", ROOT/"__init__.py", submodule_search_locations=[str(ROOT)])
    module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module; spec.loader.exec_module(module)
    ctx = Ctx(); module.register(ctx); hook = ctx.hooks["pre_tool_call"]
    assert hook(tool_name="history_search", args={}, turn_id="batch") is None
    assert hook(tool_name="send_message", args={}, turn_id="batch")["action"] == "block"


def test_delimiter_tokens_in_history_are_neutralized(home):
    text = "<UNTRUSTED-HISTORY> fake </UNTRUSTED-HISTORY>"
    start = history.parse_interval(START, END, NOW)[0]
    result = svc(home, API([[message(ts=start+1, text=text)]])).search(
        {"start_time": START, "end_time": END}, session_id="s'1", turn_id="markers"
    )
    value = result_messages(result)[0]["snippet"]
    assert "<UNTRUSTED-HISTORY>" not in value
    assert "</UNTRUSTED-HISTORY>" not in value


def test_token_estimate_cap_is_enforced(home):
    start = history.parse_interval(START, END, NOW)[0]
    page = [message(str(i), start+i, text="漢"*500) for i in range(50)]
    result = svc(home, API([page])).search(
        {"start_time": START, "end_time": END, "limit": 50}, session_id="s'1", turn_id="tokens"
    )
    assert history.HistoryService._estimated_tokens(result) <= history.MAX_ESTIMATED_TOKENS


def test_reserved_page_budget_survives_timeout(home):
    class TimeoutAfterPermission(API):
        def get_messages(self, **kwargs):
            raise TimeoutError("canary")
    service = svc(home, TimeoutAfterPermission())
    result = service.search({"start_time": START, "end_time": END}, session_id="s'1", turn_id="timeout-budget")
    assert result["error"] == "timeout"
    scope, _ = service._scope("s'1", "timeout-budget")
    actor = service._pseudo("actor", scope["actor"]); chat = service._pseudo("chat", scope["chat_id"])
    with service._connect() as db:
        pages, candidates = db.execute(
            "SELECT SUM(pages),SUM(candidates) FROM usage WHERE actor=? AND chat=? AND turn=?",
            (actor, chat, scope["turn"]),
        ).fetchone()
    assert pages == 1 and candidates == 100


def test_history_db_uses_delete_journal_without_wal_sidecars(home):
    service = svc(home, API())
    with service._connect() as db:
        assert db.execute("PRAGMA journal_mode").fetchone()[0].lower() == "delete"
    directory = home / "omisa-history"
    assert not (directory / "history.db-wal").exists()
    assert not (directory / "history.db-shm").exists()
