"""Profile-scoped durable document inbox and registry for Omisa."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import shutil
import tempfile
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MAX_DOCUMENT_BYTES = 20 * 1024 * 1024
ALLOWED_SUFFIXES = {
    ".txt", ".md", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".csv",
    ".ppt", ".pptx", ".rtf", ".odt", ".ods", ".odp", ".json", ".xml",
}
VISIBILITIES = {"team", "restricted", "private"}
AUTOSAVE_LABEL = "автосохранение"
_SCOPE_RE = re.compile(r"^(?:max|telegram):(group|dm):[-A-Za-z0-9_.:@]{1,160}$")


def _autosave_state_path() -> Path:
    _, _, workspace = _roots()
    return workspace / "knowledge" / "autosave-scopes.json"


def _valid_scope(scope: str) -> bool:
    return isinstance(scope, str) and bool(_SCOPE_RE.fullmatch(scope.strip()))


def _load_autosave_state() -> dict[str, Any]:
    path = _autosave_state_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"schema_version": 1, "scopes": {}}
    except (OSError, ValueError, TypeError):
        return {"schema_version": 1, "scopes": {}}
    scopes = data.get("scopes") if isinstance(data, dict) else None
    if not isinstance(scopes, dict):
        scopes = {}
    return {
        "schema_version": 1,
        "scopes": {str(k): True for k, v in scopes.items() if _valid_scope(str(k)) and v is True},
    }


def _save_autosave_state(state: dict[str, Any]) -> None:
    path = _autosave_state_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    fd, temp_name = tempfile.mkstemp(prefix=".autosave-scopes-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(state, handle, ensure_ascii=False, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_name, 0o600)
        os.replace(temp_name, path)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def autosave_status(scope: str) -> dict[str, Any]:
    if not _valid_scope(scope):
        return {"success": False, "error_code": "invalid_scope", "message": "Invalid autosave scope."}
    state = _load_autosave_state()
    return {"success": True, "scope": scope, "enabled": state["scopes"].get(scope) is True}


def autosave_set(scope: str, enabled: bool) -> dict[str, Any]:
    if not _valid_scope(scope):
        return {"success": False, "error_code": "invalid_scope", "message": "Invalid autosave scope."}
    state = _load_autosave_state()
    if enabled:
        state["scopes"][scope] = True
    else:
        state["scopes"].pop(scope, None)
    _save_autosave_state(state)
    return {"success": True, "scope": scope, "enabled": bool(enabled)}


def _json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True)


def _error(code: str, message: str) -> str:
    return _json({"success": False, "error_code": code, "message": message})


def _roots() -> tuple[Path, Path, Path]:
    home = Path(os.environ.get("HERMES_HOME", "~/.hermes")).expanduser().resolve()
    workspace = Path(os.environ.get("OMISA_WORKSPACE", "~/workspace")).expanduser().resolve()
    cache = (home / "cache" / "documents").resolve()
    documents = (workspace / "knowledge" / "documents").resolve()
    return cache, documents, workspace


def _sanitize_filename(name: str, suffix: str) -> str:
    value = unicodedata.normalize("NFKC", name or "document")
    value = value.replace("/", "_").replace("\\", "_").replace("\x00", "")
    value = re.sub(r"[\x00-\x1f\x7f]+", " ", value)
    value = re.sub(r"\s+", " ", value).strip(" ._")
    value = re.sub(r"[^\w .()\[\]{}№+\-=,@а-яА-ЯёЁ]+", "_", value)
    value = value[:140].strip(" ._") or "document"
    if not value.lower().endswith(suffix.lower()):
        value += suffix
    return value


def _hash_id(value: Any) -> str | None:
    """Legacy v1 hash retained only for reading/migrating existing metadata."""
    text = str(value or "").strip()
    if not text:
        return None
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def _authorization_key() -> bytes:
    """Shared profile-local key also used by history-plugin capabilities."""
    root = Path(os.environ.get("HERMES_HOME", "~/.hermes")).expanduser().resolve() / "omisa-history"
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    path = root / "audit.key"
    if not path.exists():
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(os.urandom(32))
        except FileExistsError:
            pass
    os.chmod(path, 0o600)
    key = path.read_bytes()
    if len(key) < 32:
        raise OSError("invalid authorization key")
    return key


def _auth_id(kind: str, value: Any) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    return hmac.new(_authorization_key(), f"durable-auth-v2:{kind}:{text}".encode(), hashlib.sha256).hexdigest()


def _validate_source(raw_path: str) -> tuple[Path | None, str | None, str | None]:
    if not isinstance(raw_path, str) or not raw_path.strip():
        return None, "invalid_path", "A non-empty local file path is required."
    literal = Path(raw_path).expanduser()
    if literal.is_symlink():
        return None, "symlink_rejected", "Symbolic links are not accepted."
    try:
        source = literal.resolve(strict=True)
    except (OSError, RuntimeError):
        return None, "file_not_found", "The source file is unavailable."
    if not source.is_file():
        return None, "invalid_path", "The source must be a regular file."
    cache, durable, _ = _roots()
    if not (source.is_relative_to(cache) or source.is_relative_to(durable)):
        return None, "path_not_allowed", "Source must be in the profile document cache or durable document store."
    suffix = source.suffix.lower()
    if suffix not in ALLOWED_SUFFIXES:
        return None, "unsupported_type", f"Unsupported document type: {suffix or '(none)'}"
    size = source.stat().st_size
    if size > MAX_DOCUMENT_BYTES:
        return None, "file_too_large", f"Document exceeds the {MAX_DOCUMENT_BYTES}-byte durable-store limit."
    return source, None, None


def _read_metadata(doc_dir: Path) -> dict[str, Any] | None:
    path = doc_dir / "metadata.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None
    if not isinstance(data, dict) or str(data.get("visibility") or "") not in VISIBILITIES:
        return None
    return data


def _public(meta: dict[str, Any], *, include_path: bool = True) -> dict[str, Any]:
    keys = ["document_id", "title", "original_filename", "stored_filename",
            "sha256", "size", "status", "visibility", "version", "received_at", "labels"]
    if include_path:
        keys.append("stored_path")
    return {k: meta.get(k) for k in keys}


def _authorized(meta: dict, provenance: dict) -> bool:
    source = meta.get("source") if isinstance(meta.get("source"), dict) else {}
    visibility = str(meta.get("visibility") or "")
    if visibility not in VISIBILITIES:
        return False
    if source.get("schema") == 2:
        if visibility == "private":
            sender_mac,chat_mac=source.get("sender_mac"),source.get("chat_mac")
            expected_sender,expected_chat=_auth_id("sender", provenance["sender"]),_auth_id("chat", provenance["chat_id"])
            if not all(isinstance(x,str) and len(x)==64 for x in (sender_mac,chat_mac,expected_sender,expected_chat)):return False
            return hmac.compare_digest(sender_mac,expected_sender) and hmac.compare_digest(chat_mac,expected_chat)
        scope_mac,expected_scope=source.get("scope_mac"),_auth_id("scope", provenance["scope"])
        return isinstance(scope_mac,str) and isinstance(expected_scope,str) and len(scope_mac)==64 and hmac.compare_digest(scope_mac,expected_scope)
    if visibility == "private":
        sender_hash,chat_hash=source.get("sender_hash"),source.get("chat_hash")
        return all(isinstance(x,str) and len(x)==16 for x in (sender_hash,chat_hash)) and sender_hash == _hash_id(provenance["sender"]) and chat_hash == _hash_id(provenance["chat_id"])
    return source.get("scope_hash") == _hash_id(provenance["scope"])


# Injectable live-context reader for hermetic tests; production resolves the
# gateway ContextVar reader automatically inside _live_provenance.
_CONTEXT_READER = None


def _live_provenance(context_reader=None) -> tuple[dict | None, str | None]:
    """Derive durable-store provenance from live gateway context, never from tool args.

    Authorization hashes are computed from the actual gateway session identity so
    a model turn cannot plant another actor's or chat's IDs to re-grant access.
    """
    reader = context_reader if context_reader is not None else _CONTEXT_READER
    if reader is None:
        try:
            from gateway.session_context import get_session_env
            reader = get_session_env
        except Exception:
            reader = None
    if reader is None:
        return None, "live_context_unavailable"
    try:
        platform = str(reader("HERMES_SESSION_PLATFORM", "") or "").strip().lower()
        chat_type = str(reader("HERMES_SESSION_CHAT_TYPE", "") or "").strip().lower()
        chat_id = str(reader("HERMES_SESSION_CHAT_ID", "") or "").strip()
        sender = str(reader("HERMES_SESSION_USER_ID", "") or "").strip()
    except Exception:
        return None, "live_context_unavailable"
    if not platform or not chat_id:
        return None, "live_context_unavailable"
    if not sender:
        return None, "actor_unavailable"
    scope = f"{platform}:{chat_type or 'dm'}:{chat_id}"
    return {"platform": platform, "chat_type": chat_type, "chat_id": chat_id, "sender": sender, "scope": scope}, None


def _authorization_hashes(provenance: dict) -> dict:
    return {
        "schema": 2,
        "platform": provenance["platform"],
        "chat_type": provenance["chat_type"],
        "scope_mac": _auth_id("scope", provenance["scope"]),
        "chat_mac": _auth_id("chat", provenance["chat_id"]),
        "sender_mac": _auth_id("sender", provenance["sender"]),
    }


def document_save(args: dict[str, Any], **kwargs: Any) -> str:
    """Promote an explicitly significant cached document into durable storage.

    Provenance and authorization metadata are derived exclusively from the live
    gateway session (ContextVar), never from model-supplied arguments.
    """
    del kwargs
    try:
        title = str(args.get("title") or "").strip()
        if not title or len(title) > 300:
            return _error("invalid_title", "Title must contain 1-300 characters.")
        visibility = str(args.get("visibility") or "team").strip().lower()
        if visibility not in VISIBILITIES:
            return _error("invalid_visibility", "Visibility must be team, restricted, or private.")
        provenance, context_error = _live_provenance()
        if provenance is None:
            return _error(context_error or "live_context_unavailable", "A live gateway session is required to save documents durably.")
        labels = []
        for raw_label in args.get("labels") or []:
            label = str(raw_label or "").strip().casefold()
            if label == AUTOSAVE_LABEL and label not in labels:
                labels.append(label)
        source, code, message = _validate_source(str(args.get("path") or ""))
        if source is None:
            return _error(code or "invalid_path", message or "Invalid path.")

        digest = hashlib.sha256()
        with source.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        sha256 = digest.hexdigest()
        document_id = f"doc-{sha256[:16]}"
        _, documents, _ = _roots()
        doc_dir = documents / document_id
        existing = _read_metadata(doc_dir)
        authorization = _authorization_hashes(provenance)
        if existing and existing.get("sha256") == sha256:
            existing_source = existing.get("source") if isinstance(existing.get("source"), dict) else {}
            existing_visibility = str(existing.get("visibility") or "")
            if existing_visibility not in VISIBILITIES:
                return _error("access_denied", "Existing document metadata is not authorized.")
            existing_meta = dict(existing)
            existing_meta["visibility"] = existing_visibility
            if not _authorized(existing_meta, provenance):
                return _error("access_denied", "An existing document can only be modified by its authorized conversation.")
            # Duplicate save never transfers ownership or changes visibility.
            # It may only migrate this already-authorized record to v2 and add
            # the bounded autosave label.
            changed = False
            if labels and AUTOSAVE_LABEL not in (existing.get("labels") or []):
                existing["labels"] = sorted(set(existing.get("labels") or []) | set(labels))
                changed = True
            if existing_source != authorization:
                existing["source"] = authorization
                changed = True
            if changed:
                metadata_path = doc_dir / "metadata.json"
                temp_metadata = doc_dir / ".metadata.json.tmp"
                temp_metadata.write_text(
                    json.dumps(existing, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
                    encoding="utf-8",
                )
                os.chmod(temp_metadata, 0o640)
                os.replace(temp_metadata, metadata_path)
            payload = _public(existing)
            payload.update({"success": True, "duplicate": True})
            return _json(payload)

        suffix = source.suffix.lower()
        safe_name = _sanitize_filename(source.name, suffix)
        documents.mkdir(parents=True, exist_ok=True, mode=0o750)
        temp_dir = Path(tempfile.mkdtemp(prefix=f".{document_id}-", dir=documents))
        os.chmod(temp_dir, 0o750)
        target = temp_dir / safe_name
        with source.open("rb") as src, target.open("xb") as dst:
            shutil.copyfileobj(src, dst, length=1024 * 1024)
            dst.flush()
            os.fsync(dst.fileno())
        os.chmod(target, 0o640)
        if hashlib.sha256(target.read_bytes()).hexdigest() != sha256:
            raise OSError("post-copy checksum mismatch")
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        final_path = doc_dir / safe_name
        meta = {
            "schema_version": 1,
            "document_id": document_id,
            "title": title,
            "original_filename": source.name,
            "stored_filename": safe_name,
            "stored_path": str(final_path),
            "sha256": sha256,
            "size": source.stat().st_size,
            "status": "inbox",
            "visibility": visibility,
            "version": 1,
            "labels": labels,
            "received_at": now,
            "source": authorization,
        }
        (temp_dir / "metadata.json").write_text(
            json.dumps(meta, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
        os.chmod(temp_dir / "metadata.json", 0o640)
        os.rename(temp_dir, doc_dir)
        payload = _public(meta)
        payload.update({"success": True, "duplicate": False})
        return _json(payload)
    except FileExistsError:
        return _error("document_conflict", "A conflicting document record already exists.")
    except Exception:
        return _error("storage_failure", "The document could not be saved safely.")


def _iter_metadata() -> list[dict[str, Any]]:
    _, documents, _ = _roots()
    if not documents.exists():
        return []
    rows = []
    for child in documents.iterdir():
        if child.is_dir() and not child.is_symlink() and child.name.startswith("doc-"):
            meta = _read_metadata(child)
            if meta:
                rows.append(meta)
    rows.sort(key=lambda m: str(m.get("received_at") or ""), reverse=True)
    return rows


def document_list(args: dict[str, Any], **kwargs: Any) -> str:
    del kwargs
    try:
        provenance, context_error = _live_provenance()
        if provenance is None:
            return _error(context_error or "live_context_unavailable", "A live gateway session is required.")
        query = str(args.get("query") or "").strip().casefold()
        label = str(args.get("label") or "").strip().casefold()
        status = str(args.get("status") or "").strip().casefold()
        limit = max(1, min(50, int(args.get("limit") or 20)))
        rows = []
        for meta in _iter_metadata():
            if not _authorized(meta, provenance):
                continue
            haystack = " ".join(str(meta.get(k) or "") for k in ("document_id", "title", "original_filename", "sha256")).casefold()
            if query and query not in haystack:
                continue
            labels = [str(item).casefold() for item in (meta.get("labels") or [])]
            if label and label not in labels:
                continue
            if status and str(meta.get("status") or "").casefold() != status:
                continue
            rows.append(_public(meta, include_path=False))
            if len(rows) >= limit:
                break
        return _json({"success": True, "count": len(rows), "documents": rows})
    except Exception:
        return _error("registry_failure", "The document registry could not be read safely.")


def document_get(args: dict[str, Any], **kwargs: Any) -> str:
    del kwargs
    try:
        provenance, context_error = _live_provenance()
        if provenance is None:
            return _error(context_error or "live_context_unavailable", "A live gateway session is required.")
        document_id = str(args.get("document_id") or "").strip()
        if not re.fullmatch(r"doc-[0-9a-f]{16}", document_id):
            return _error("invalid_document_id", "Invalid document ID.")
        _, documents, _ = _roots()
        meta = _read_metadata(documents / document_id)
        if not meta:
            return _error("document_not_found", "Document was not found.")
        if not _authorized(meta, provenance):
            return _error("access_denied", "The document is not available in this conversation.")
        stored_name=meta.get("stored_filename")
        if not isinstance(stored_name,str) or Path(stored_name).name!=stored_name:
            return _error("document_unavailable", "The registered document file is unavailable.")
        stored=(documents/document_id/stored_name).resolve()
        if stored.parent!=(documents/document_id).resolve() or not stored.is_file() or stored.is_symlink():
            return _error("document_unavailable", "The registered document file is unavailable.")
        payload = _public(meta, include_path=False)
        payload.update({"success": True})
        return _json(payload)
    except Exception:
        return _error("registry_failure", "The document record could not be read safely.")
