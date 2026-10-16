import importlib.util
import json
import os
import sqlite3
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT))
import history
from test_document_parse_integration import setup as parse_setup  # noqa: F401


def test_invalid_options_fail_before_scope_filesystem_network_or_broker(parse_setup, monkeypatch):
    service, api, broker, token, _ = parse_setup
    service.context_reader = lambda *_: (_ for _ in ()).throw(AssertionError("scope touched"))
    monkeypatch.setattr(service, "_connect", lambda: (_ for _ in ()).throw(AssertionError("fs touched")))
    invalid = [
        {"unknown": True}, {"ocr": True}, {"language_hints": ["en", "en"]},
        {"language_hints": ["de"]}, {"include": ["metadata"]}, {"max_records": True},
        {"range": {"unit": "page", "start": 2, "end": 1}},
        {"range": {"unit": "page", "start": 1, "end": 51}},
    ]
    for options in invalid:
        assert service.document_parse({"artifact_ref": token, "options": options}, session_id="s1", turn_id="t") == {"success": False, "error": "invalid_argument"}
    assert api.calls if hasattr(api, "calls") else api.access_calls == 0
    assert broker.calls == []


def test_options_are_canonical_cache_identity_and_cache_revalidates(parse_setup):
    service, api, broker, token, _ = parse_setup
    a = service.document_parse({"artifact_ref": token, "options": {"ocr": "off", "include": ["text"]}}, session_id="s1", turn_id="t")
    b = service.document_parse({"artifact_ref": token, "options": {"include": ["text"], "ocr": "off"}}, session_id="s1", turn_id="t")
    c = service.document_parse({"artifact_ref": token, "options": {"ocr": "force", "include": ["text"]}}, session_id="s1", turn_id="t")
    assert a == b and c["parse_ref"] != a["parse_ref"] and len(broker.calls) == 2
    api.access = False
    denied = service.document_parse({"artifact_ref": token, "options": {"ocr": "off", "include": ["text"]}}, session_id="s1", turn_id="t")
    assert denied["error"] == "access_denied"
    with service._connect() as db:
        assert db.execute("SELECT COUNT(*) FROM artifacts WHERE token=?", (token,)).fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM parse_cache WHERE artifact_token=?", (token,)).fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM capabilities WHERE kind='parse_cursor'").fetchone()[0] == 0


def test_model_records_strip_request_and_internal_metadata(parse_setup):
    service, _, _, token, _ = parse_setup
    parsed = service.document_parse({"artifact_ref": token}, session_id="s1", turn_id="t")
    read = service.document_read({"parse_ref": parsed["parse_ref"]}, session_id="s1", turn_id="t")
    encoded = json.dumps(read)
    assert "a" * 32 not in encoded and "bundle_version" not in encoded and '"parser"' not in encoded
    assert "hello world" in encoded and "detected_format" in encoded


def test_same_inode_same_size_restored_mtime_is_detected(parse_setup):
    service, _, broker, token, path = parse_setup
    before = path.stat()
    original = broker.parse_fd
    def mutate(fd, **kwargs):
        rows = original(fd, **kwargs)
        with path.open("r+b", buffering=0) as stream:
            stream.write(b"HELLO WORLD")
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
        return rows
    broker.parse_fd = mutate
    assert service.document_parse({"artifact_ref": token}, session_id="s1", turn_id="t")["error"] == "artifact_changed"


def test_atomic_parse_claim_allows_one_broker_call(parse_setup):
    service, api, broker, token, _ = parse_setup
    second = history.HistoryService(api=api, now_ms=service.now_ms, context_reader=service.context_reader, broker_client=broker)
    entered = threading.Event(); release = threading.Event()
    original = broker.parse_fd
    def synchronized(*args, **kwargs):
        entered.set(); release.wait(timeout=3)
        return original(*args, **kwargs)
    broker.parse_fd = synchronized
    results = []
    first = threading.Thread(target=lambda: results.append(service.document_parse({"artifact_ref": token}, session_id="s1", turn_id="t")))
    first.start(); assert entered.wait(timeout=3)
    other = threading.Thread(target=lambda: results.append(second.document_parse({"artifact_ref": token}, session_id="s1", turn_id="t")))
    other.start(); other.join(3); release.set(); first.join(3)
    assert len(broker.calls) == 1
    assert len(results) == 2
    assert sum(bool(x.get("success")) for x in results) == 1
    assert {x.get("error") for x in results if not x.get("success")} == {"parse_in_progress"}


def test_missing_turn_fails_closed_in_hook_and_service(parse_setup):
    service, api, broker, token, _ = parse_setup
    assert service.document_parse({"artifact_ref": token}, session_id="s1", turn_id=None)["error"] == "non_live_invocation"
    assert broker.calls == []
    spec = importlib.util.spec_from_file_location("final_hook", ROOT / "__init__.py", submodule_search_locations=[str(ROOT)])
    module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module; spec.loader.exec_module(module)
    assert module._on_pre_tool_call(tool_name="history_search", args={}, turn_id=None)["action"] == "block"
    assert module._on_pre_tool_call(tool_name="terminal", args={}, turn_id=None)["action"] == "block"


def test_canonical_socket_and_no_home_credential_default(monkeypatch):
    import history_broker
    monkeypatch.delenv("OMISA_PARSER_SOCKET", raising=False)
    monkeypatch.delenv("OMISA_PARSER_CREDENTIAL", raising=False)
    seen = {}
    class Client:
        def __init__(self, socket_path, credential, timeout=90): seen.update(path=str(socket_path), key=credential)
    monkeypatch.setattr(history_broker, "UnixBrokerClient", Client)
    client = history_broker.configured_client()
    assert seen["path"] == "/run/omisa-parser/parser.sock"
    assert seen["key"] is None
    assert client is not None