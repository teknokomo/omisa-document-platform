import hashlib
import importlib.util
import json
import os
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).parents[1] / "document_store.py"
spec = importlib.util.spec_from_file_location("omisa_document_store", MODULE_PATH)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

PLATFORM, CHAT_TYPE, CHAT_ID, SENDER = "max", "group", "-900", "200"
SCOPE = f"{PLATFORM}:{CHAT_TYPE}:{CHAT_ID}"


@pytest.fixture
def store(tmp_path, monkeypatch):
    hermes = tmp_path / ".hermes"
    workspace = tmp_path / "workspace"
    cache = hermes / "cache" / "documents"
    cache.mkdir(parents=True)
    workspace.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    monkeypatch.setenv("OMISA_WORKSPACE", str(workspace))
    monkeypatch.setattr(mod, "_CONTEXT_READER", _reader())
    return cache, workspace


def _reader(platform=PLATFORM, chat_type=CHAT_TYPE, chat_id=CHAT_ID, sender=SENDER):
    values = {
        "HERMES_SESSION_PLATFORM": platform,
        "HERMES_SESSION_CHAT_TYPE": chat_type,
        "HERMES_SESSION_CHAT_ID": chat_id,
        "HERMES_SESSION_USER_ID": sender,
    }
    return lambda key, default="": values.get(key, default)


def decode(value):
    return json.loads(value)


def test_save_copies_allowed_cache_file_atomically_and_records_safe_metadata(store):
    cache, workspace = store
    src = cache / "../documents/Протокол № 1.md"
    src.write_text("решение: запустить проект\n", encoding="utf-8")
    digest = hashlib.sha256(src.read_bytes()).hexdigest()

    result = decode(mod.document_save({
        "path": str(src),
        "title": "Протокол № 1",
        "visibility": "team",
    }))

    assert result["success"] is True
    assert result["document_id"] == f"doc-{digest[:16]}"
    assert result["sha256"] == digest
    assert result["status"] == "inbox"
    stored = Path(result["stored_path"])
    assert stored.read_bytes() == src.read_bytes()
    assert stored.is_relative_to(workspace / "knowledge" / "documents")
    assert "Протокол" in stored.name

    metadata = json.loads((stored.parent / "metadata.json").read_text())
    source = metadata["source"]
    assert source["schema"] == 2
    assert source["platform"] == "max"
    assert source["scope_mac"] == mod._auth_id("scope", SCOPE)
    assert source["chat_mac"] == mod._auth_id("chat", CHAT_ID)
    assert source["sender_mac"] == mod._auth_id("sender", SENDER)
    assert len(source["scope_mac"]) == 64
    assert SCOPE not in json.dumps(metadata)
    assert CHAT_ID not in json.dumps(metadata)
    assert SENDER not in json.dumps(metadata)


def test_provenance_is_derived_from_live_context_not_from_tool_args(store, monkeypatch):
    cache, _ = store
    src = cache / "plant.txt"; src.write_text("plant")
    monkeypatch.setattr(mod, "_CONTEXT_READER", _reader(chat_id="111", sender="222"))
    saved = decode(mod.document_save({
        "path": str(src),
        "title": "Planted",
        "visibility": "private",
        "sender_id": "999999", "source_chat_id": "-888888", "source_scope": "evil:dm:0",
    }))
    assert saved["success"] is True
    metadata = json.loads((Path(saved["stored_path"]).parent / "metadata.json").read_text())
    assert metadata["source"]["chat_mac"] == mod._auth_id("chat", "111")
    assert metadata["source"]["sender_mac"] == mod._auth_id("sender", "222")
    assert metadata["source"]["scope_mac"] == mod._auth_id("scope", "max:group:111")


def test_save_without_live_context_fails_closed(store, monkeypatch):
    cache, _ = store
    src = cache / "orphan.txt"; src.write_text("orphan")
    monkeypatch.setattr(mod, "_CONTEXT_READER", None)
    result = decode(mod.document_save({"path": str(src), "title": "Orphan"}))
    assert result["success"] is False
    assert result["error_code"] == "live_context_unavailable"


def test_private_operations_fail_closed_without_actor_or_complete_metadata(store, monkeypatch):
    cache, _ = store
    src=cache/"missing-actor.txt";src.write_text("private")
    monkeypatch.setattr(mod,"_CONTEXT_READER",_reader(sender=""))
    assert decode(mod.document_save({"path":str(src),"title":"Private","visibility":"private"}))["error_code"]=="actor_unavailable"

    monkeypatch.setattr(mod,"_CONTEXT_READER",_reader())
    saved=decode(mod.document_save({"path":str(src),"title":"Private","visibility":"private"}))
    metadata_path=Path(saved["stored_path"]).parent/"metadata.json"
    metadata=json.loads(metadata_path.read_text());metadata["source"].pop("sender_mac");metadata_path.write_text(json.dumps(metadata))
    assert decode(mod.document_get({"document_id":saved["document_id"]}))["error_code"]=="access_denied"
    metadata["source"]={"sender_hash":mod._hash_id(SENDER)};metadata_path.write_text(json.dumps(metadata))
    assert decode(mod.document_get({"document_id":saved["document_id"]}))["error_code"]=="access_denied"


def test_unknown_or_missing_visibility_is_hidden_and_immutable(store):
    cache, _=store
    src=cache/"visibility.txt";src.write_text("visibility")
    saved=decode(mod.document_save({"path":str(src),"title":"Visibility","visibility":"team"}))
    metadata_path=Path(saved["stored_path"]).parent/"metadata.json"
    original=json.loads(metadata_path.read_text())
    for bad in ("public",None):
        tampered=dict(original)
        if bad is None:tampered.pop("visibility",None)
        else:tampered["visibility"]=bad
        metadata_path.write_text(json.dumps(tampered))
        assert mod._read_metadata(metadata_path.parent) is None
        assert decode(mod.document_get({"document_id":saved["document_id"]}))["error_code"] in {"access_denied","document_not_found"}
        assert decode(mod.document_list({"limit":10}))["count"]==0
        duplicate=decode(mod.document_save({"path":str(src),"title":"Visibility","visibility":"team"}))
        assert duplicate["success"] is False
        assert json.loads(metadata_path.read_text())==tampered


def test_save_is_idempotent_for_same_bytes(store):
    cache, _ = store
    src = cache / "brief.txt"
    src.write_text("same", encoding="utf-8")
    first = decode(mod.document_save({"path": str(src), "title": "Brief"}))
    second = decode(mod.document_save({"path": str(src), "title": "Other title"}))
    assert first["success"] is True
    assert second["success"] is True
    assert second["duplicate"] is True
    assert second["document_id"] == first["document_id"]
    assert second["stored_path"] == first["stored_path"]


def test_private_document_cannot_be_resaved_by_another_conversation(store, monkeypatch):
    cache, _ = store
    src = cache / "private.pdf"; src.write_bytes(b"%PDF-1.5\nprivate")
    first = decode(mod.document_save({"path": str(src), "title": "Private", "visibility": "private"}))
    assert first["success"] is True
    monkeypatch.setattr(mod, "_CONTEXT_READER", _reader(chat_id="other-chat", sender="someone-else"))
    second = decode(mod.document_save({"path": str(src), "title": "Private", "visibility": "private"}))
    assert second["success"] is False
    assert second["error_code"] == "access_denied"
    downgrade = decode(mod.document_save({"path": str(src), "title": "Private", "visibility": "team"}))
    assert downgrade["success"] is False
    assert downgrade["error_code"] == "access_denied"


def test_authorized_legacy_v1_duplicate_migrates_to_hmac_v2(store):
    cache, _ = store
    src = cache / "legacy.txt"; src.write_text("legacy")
    digest=hashlib.sha256(src.read_bytes()).hexdigest(); document_id=f"doc-{digest[:16]}"
    _, documents, _=mod._roots(); doc_dir=documents/document_id; doc_dir.mkdir(parents=True)
    stored=doc_dir/"legacy.txt"; stored.write_bytes(src.read_bytes())
    (doc_dir/"metadata.json").write_text(json.dumps({
        "schema_version":1,"document_id":document_id,"title":"Legacy","original_filename":"legacy.txt",
        "stored_filename":"legacy.txt","stored_path":str(stored),"sha256":digest,"size":stored.stat().st_size,
        "status":"inbox","visibility":"private","version":1,"labels":[],"received_at":"2026-01-01T00:00:00Z",
        "source":{"sender_hash":mod._hash_id(SENDER),"chat_hash":mod._hash_id(CHAT_ID)},
    }))
    migrated=decode(mod.document_save({"path":str(src),"title":"Legacy","visibility":"private"}))
    assert migrated["success"] is True and migrated["duplicate"] is True
    metadata=json.loads((doc_dir/"metadata.json").read_text())
    assert metadata["source"]["schema"]==2
    assert "sender_hash" not in metadata["source"]
    assert metadata["source"]["sender_mac"]==mod._auth_id("sender",SENDER)


def test_duplicate_resave_cannot_refresh_authorization_from_another_context(store, monkeypatch):
    cache, _ = store
    src = cache / "refresh.txt"; src.write_text("refresh")
    first = decode(mod.document_save({"path": str(src), "title": "Refresh", "visibility": "team"}))
    assert first["success"] is True
    first_meta=json.loads((Path(first["stored_path"]).parent/"metadata.json").read_text())
    monkeypatch.setattr(mod, "_CONTEXT_READER", _reader(chat_id="new-chat", sender="same-sender"))
    second = decode(mod.document_save({"path": str(src), "title": "Refresh", "visibility": "team", "labels": ["автосохранение"]}))
    assert second["success"] is False and second["error_code"] == "access_denied"
    metadata = json.loads((Path(first["stored_path"]).parent / "metadata.json").read_text())
    assert metadata == first_meta


@pytest.mark.parametrize("kind", ["outside", "symlink", "unsupported", "oversize"])
def test_save_rejects_unsafe_source(store, kind):
    cache, workspace = store
    if kind == "outside":
        src = workspace.parent / "secret.txt"
        src.write_text("secret")
    elif kind == "symlink":
        target = cache / "target.txt"; target.write_text("x")
        src = cache / "link.txt"; src.symlink_to(target)
    elif kind == "unsupported":
        src = cache / "run.sh"; src.write_text("#!/bin/sh")
    else:
        src = cache / "huge.pdf"
        with src.open("wb") as f: f.truncate(mod.MAX_DOCUMENT_BYTES + 1)
    result = decode(mod.document_save({"path": str(src), "title": "Unsafe"}))
    assert result["success"] is False
    assert result["error_code"] in {"path_not_allowed", "symlink_rejected", "unsupported_type", "file_too_large"}


def test_save_accepts_existing_durable_file_without_recopy(store):
    cache, workspace = store
    src = cache / "notes.md"; src.write_text("durable")
    first = decode(mod.document_save({"path": str(src), "title": "Notes"}))
    second = decode(mod.document_save({"path": first["stored_path"], "title": "Notes"}))
    assert second["success"] is True
    assert second["duplicate"] is True


def test_list_and_get_do_not_expose_raw_source_ids(store, monkeypatch):
    cache, _ = store
    src = cache / "base.pdf"; src.write_bytes(b"%PDF-1.5\nfixture")
    saved = decode(mod.document_save({"path": str(src), "title": "Базовый документ", "visibility": "restricted"}))
    listed = decode(mod.document_list({"query": "базовый", "limit": 10}))
    assert listed["success"] is True and listed["count"] == 1
    assert listed["documents"][0]["document_id"] == saved["document_id"]
    assert "stored_path" not in listed["documents"][0]
    got = decode(mod.document_get({"document_id": saved["document_id"]}))
    assert got["success"] is True
    assert "stored_path" not in got
    blob = json.dumps(got, ensure_ascii=False)
    assert CHAT_ID not in blob and SENDER not in blob

    # Another conversation cannot enumerate or resolve this record.
    monkeypatch.setattr(mod, "_CONTEXT_READER", _reader(chat_id="other", sender="other"))
    hidden = decode(mod.document_list({"limit": 10}))
    assert hidden["success"] is True and hidden["count"] == 0
    denied = decode(mod.document_get({"document_id": saved["document_id"]}))
    assert denied["error_code"] == "access_denied"


def test_list_filters_autosaved_inbox_by_label(store):
    cache, _ = store
    auto = cache / "auto.pdf"; auto.write_bytes(b"%PDF-1.5\nauto")
    manual = cache / "manual.pdf"; manual.write_bytes(b"%PDF-1.5\nmanual")
    decode(mod.document_save({"path": str(auto), "title": "Auto", "labels": ["автосохранение"]}))
    decode(mod.document_save({"path": str(manual), "title": "Manual"}))

    listed = decode(mod.document_list({"label": "автосохранение", "status": "inbox", "limit": 10}))

    assert listed["success"] is True
    assert listed["count"] == 1
    assert listed["documents"][0]["title"] == "Auto"
    assert listed["documents"][0]["labels"] == ["автосохранение"]


def test_title_and_visibility_validation(store):
    cache, _ = store
    src = cache / "x.txt"; src.write_text("x")
    assert decode(mod.document_save({"path": str(src), "title": ""}))["error_code"] == "invalid_title"
    assert decode(mod.document_save({"path": str(src), "title": "x", "visibility": "public"}))["error_code"] == "invalid_visibility"


def test_autosave_mode_is_persistent_and_scoped(store):
    _, workspace = store
    assert mod.autosave_status("max:group:900")["enabled"] is False

    enabled = mod.autosave_set("max:group:900", True)
    assert enabled == {"success": True, "scope": "max:group:900", "enabled": True}
    assert mod.autosave_status("max:group:900")["enabled"] is True
    assert mod.autosave_status("max:dm:42")["enabled"] is False

    state = json.loads((workspace / "knowledge" / "autosave-scopes.json").read_text())
    assert state == {"schema_version": 1, "scopes": {"max:group:900": True}}
    assert oct((workspace / "knowledge" / "autosave-scopes.json").stat().st_mode & 0o777) == "0o600"

    disabled = mod.autosave_set("max:group:900", False)
    assert disabled["enabled"] is False
    assert mod.autosave_status("max:group:900")["enabled"] is False


def test_autosave_scope_rejects_untrusted_shape(store):
    result = mod.autosave_set("../../etc/passwd", True)
    assert result["success"] is False
    assert result["error_code"] == "invalid_scope"


def test_autosaved_document_has_label_and_scope_hash(store):
    cache, _ = store
    src = cache / "agenda.pdf"; src.write_bytes(b"%PDF-1.5\nautosave")
    saved = decode(mod.document_save({"path": str(src), "title": "Agenda", "labels": ["автосохранение"]}))
    assert saved["success"] is True
    assert saved["labels"] == ["автосохранение"]
    metadata = json.loads((Path(saved["stored_path"]).parent / "metadata.json").read_text())
    assert metadata["labels"] == ["автосохранение"]
    assert metadata["source"]["scope_mac"] == mod._auth_id("scope", SCOPE)
    assert SCOPE not in json.dumps(metadata)


def test_autosave_duplicate_adds_label_to_existing_record(store):
    cache, _ = store
    src = cache / "same.pdf"; src.write_bytes(b"%PDF-1.5\nsame")
    first = decode(mod.document_save({"path": str(src), "title": "Manual"}))
    assert first["labels"] == []

    second = decode(mod.document_save({"path": str(src), "title": "Manual", "labels": ["автосохранение"]}))

    assert second["duplicate"] is True
    assert second["labels"] == ["автосохранение"]
    metadata = json.loads((Path(second["stored_path"]).parent / "metadata.json").read_text())
    assert metadata["labels"] == ["автосохранение"]


def test_registration_exposes_three_documents_tools():
    init_path = MODULE_PATH.parent / "__init__.py"
    spec = importlib.util.spec_from_file_location(
        "omisa_document_store_package", init_path,
        submodule_search_locations=[str(MODULE_PATH.parent)],
    )
    package = importlib.util.module_from_spec(spec)
    import sys
    sys.modules[spec.name] = package
    spec.loader.exec_module(package)

    registered = []
    class Ctx:
        def register_tool(self, **kwargs):
            registered.append(kwargs)
    package.register(Ctx())
    assert {row["name"] for row in registered} == {"document_save", "document_list", "document_get"}
    assert all(row["toolset"] == "documents" for row in registered)
    assert all(row["schema"]["description"] for row in registered)
    save_schema = next(row["schema"] for row in registered if row["name"] == "document_save")
    assert "sender_id" not in save_schema["parameters"]["properties"]
    assert save_schema["parameters"]["additionalProperties"] is False
