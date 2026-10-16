"""Hermes plugin registration for bounded MAX group-history retrieval."""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from pathlib import Path

try:
    from .history import HistoryService
except ImportError:
    from history import HistoryService

SEARCH_SCHEMA = {"name":"history_search","description":"Search bounded, persisted, untrusted history in the current authorized MAX group.","parameters":{"type":"object","properties":{"start_time":{"type":"string"},"end_time":{"type":"string"},"query":{"type":"string","maxLength":200},"sender":{"type":"string","maxLength":200},"has_attachments":{"type":"boolean"},"limit":{"type":"integer","minimum":1,"maximum":50},"cursor":{"type":"string"}},"required":["start_time","end_time"],"additionalProperties":False}}
FETCH_SCHEMA = {"name":"history_fetch","description":"Fetch up to 10 exact messages using opaque refs issued in this live turn.","parameters":{"type":"object","properties":{"message_refs":{"type":"array","items":{"type":"string"},"minItems":1,"maxItems":10}},"required":["message_refs"],"additionalProperties":False}}
ATTACHMENT_SCHEMA = {"name":"history_attachment_fetch","description":"Securely fetch one historical document using an opaque, single-use attachment ref issued in this live turn.","parameters":{"type":"object","properties":{"attachment_ref":{"type":"string"}},"required":["attachment_ref"],"additionalProperties":False}}
ATTACHMENT_READ_SCHEMA = {"name":"history_attachment_read","description":"Read bounded extracted content from an opaque artifact; accepts no paths.","parameters":{"type":"object","properties":{"artifact_ref":{"type":"string"},"offset":{"type":"integer","minimum":0},"limit":{"type":"integer","minimum":1,"maximum":32768}},"required":["artifact_ref"],"additionalProperties":False}}
PARSE_OPTIONS_SCHEMA={"type":"object","additionalProperties":False,"properties":{"ocr":{"enum":["off","auto","force"]},"language_hints":{"type":"array","maxItems":2,"uniqueItems":True,"items":{"enum":["en","eng","ru","rus"]}},"include":{"type":"array","uniqueItems":True,"items":{"enum":["text","tables","notes"]}},"range":{"type":"object","additionalProperties":False,"required":["unit","start","end"],"properties":{"unit":{"enum":["page","sheet","slide"]},"start":{"type":"integer","minimum":1},"end":{"type":"integer","minimum":1}}},"max_records":{"type":"integer","minimum":1,"maximum":500}}}
ARTIFACT_SOURCE_SCHEMA={"type":"object","additionalProperties":False,"required":["kind","artifact_ref"],"properties":{"kind":{"const":"artifact"},"artifact_ref":{"type":"string"}}}
ATTACHMENT_SOURCE_SCHEMA={"type":"object","additionalProperties":False,"required":["kind","path"],"properties":{"kind":{"const":"attachment"},"path":{"type":"string"}}}
DURABLE_SOURCE_SCHEMA={"type":"object","additionalProperties":False,"required":["kind","document_id"],"properties":{"kind":{"const":"durable"},"document_id":{"type":"string","pattern":"^doc-[0-9a-f]{16}$"}}}
ARCHIVE_INSPECT_SCHEMA={"name":"archive_inspect","description":"Safely inspect one authorized ZIP and return opaque entry references; no paths or filenames.","parameters":{"type":"object","required":["source"],"additionalProperties":False,"properties":{"source":{"oneOf":[ARTIFACT_SOURCE_SCHEMA,ATTACHMENT_SOURCE_SCHEMA,DURABLE_SOURCE_SCHEMA]}}}}
ARCHIVE_EXTRACT_SCHEMA={"name":"archive_extract","description":"Extract one eligible inspected ZIP entry to an opaque ephemeral artifact for document_parse.","parameters":{"type":"object","required":["entry_ref"],"additionalProperties":False,"properties":{"entry_ref":{"type":"string","pattern":"^ent_v1_[A-Za-z0-9_-]{32}$"}}}}
DOCUMENT_PARSE_SCHEMA = {"name":"document_parse","description":"Parse one authorized historical artifact, current-turn Telegram/MAX attachment, or durable document through the same sandbox broker.","parameters":{"type":"object","properties":{"source":{"oneOf":[ARTIFACT_SOURCE_SCHEMA,ATTACHMENT_SOURCE_SCHEMA,DURABLE_SOURCE_SCHEMA]},"artifact_ref":{"type":"string","description":"Deprecated compatibility input; use source.kind=artifact."},"options":PARSE_OPTIONS_SCHEMA},"oneOf":[{"required":["source"]},{"required":["artifact_ref"]}],"additionalProperties":False}}
DOCUMENT_READ_SCHEMA = {"name":"document_read","description":"Read bounded normalized parser records using an opaque parse ref or cursor.","parameters":{"type":"object","properties":{"parse_ref":{"type":"string"},"cursor":{"type":"string"},"limit":{"type":"integer","minimum":1,"maximum":50}},"oneOf":[{"required":["parse_ref"]},{"required":["cursor"]}],"additionalProperties":False}}
_DISCLOSURE_TTL_MS = 30 * 60 * 1000
_HISTORY_TOOLS={"history_search","history_fetch","history_attachment_fetch","history_attachment_read","archive_inspect","archive_extract","document_parse","document_read"}
_LATCH_BLOCK={"action":"block","message":"History disclosure turn: alternate egress and persistence are blocked."}
_LATCH_ERROR_BLOCK={"action":"block","message":"History disclosure safety state unavailable; tool execution is blocked fail-closed."}


def _history_home():
    return Path(os.environ.get("HERMES_HOME") or Path.home()/".hermes")/"omisa-history"


def _latch_connect():
    directory=_history_home();directory.mkdir(mode=0o700,parents=True,exist_ok=True);os.chmod(directory,0o700)
    path=directory/"disclosure.db"
    db=sqlite3.connect(path,timeout=0.25,isolation_level=None)
    try:
        db.execute("PRAGMA busy_timeout=1000")
        db.execute("PRAGMA journal_mode=DELETE")
        db.execute("CREATE TABLE IF NOT EXISTS disclosure_latch(binding TEXT PRIMARY KEY,turn TEXT NOT NULL,created_ms INTEGER NOT NULL,expires_ms INTEGER NOT NULL)")
        os.chmod(path,0o600)
        return db
    except BaseException:
        db.close();raise


def _context_value(name,default=""):
    try:
        from gateway.session_context import get_session_env
        return str(get_session_env(name,default) or default)
    except (ImportError,RuntimeError):
        return str(os.environ.get(name,default) or default)


def _latch_identity(turn_id,**kwargs):
    if not isinstance(turn_id,str) or not turn_id.strip():return None
    values=[kwargs.get("actor") or kwargs.get("user_id") or _context_value("HERMES_SESSION_USER_ID"),
            kwargs.get("chat_id") or _context_value("HERMES_SESSION_CHAT_ID"),
            kwargs.get("session_id") or _context_value("HERMES_SESSION_ID"),turn_id.strip()]
    return hashlib.sha256(json.dumps(values,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()


def _mark_disclosed(turn_id,**kwargs):
    binding=_latch_identity(turn_id,**kwargs)
    if binding is None:return False
    turn=turn_id.strip()
    now=int(time.time()*1000)
    try:
        with _latch_connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM disclosure_latch WHERE expires_ms < ?",(now,))
            db.execute("INSERT INTO disclosure_latch(binding,turn,created_ms,expires_ms) VALUES(?,?,?,?) ON CONFLICT(binding) DO UPDATE SET expires_ms=MAX(expires_ms,excluded.expires_ms)",(binding,turn,now,now+_DISCLOSURE_TTL_MS))
            db.commit()
        return True
    except (OSError,sqlite3.Error):return False


def _turn_was_disclosed(turn_id,**kwargs):
    binding=_latch_identity(turn_id,**kwargs)
    if binding is None:return None
    now=int(time.time()*1000)
    try:
        with _latch_connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row=db.execute("SELECT binding,expires_ms FROM disclosure_latch WHERE (binding=? OR turn=?) AND expires_ms>=? ORDER BY binding=? DESC,expires_ms DESC LIMIT 1",(binding,turn_id.strip(),now,binding)).fetchone()
            if row and row[1]>=now:
                # No authoritative completion hook exists. Sliding expiry avoids
                # reopening a turn that remains active beyond the state TTL. A
                # turn-only fallback is conservative when a worker omits identity
                # fields that were available to the process that set the latch.
                db.execute("UPDATE disclosure_latch SET expires_ms=MAX(expires_ms,?) WHERE binding=?",(now+_DISCLOSURE_TTL_MS,row[0]))
                db.commit();return True
            db.execute("DELETE FROM disclosure_latch WHERE expires_ms < ?",(now,));db.commit();return False
    except (OSError,sqlite3.Error):return None


def _blocked_tool(tool_name, args):
    name = str(tool_name or "").lower()
    return name not in _HISTORY_TOOLS


def _on_pre_tool_call(tool_name="", args=None, turn_id=None, **kwargs):
    name = str(tool_name or "").lower()
    if not isinstance(turn_id,str) or not turn_id.strip():
        return {"action":"block","message":"Missing trusted turn identity; tool execution is blocked fail-closed."}
    # Mark durably at authorization time, before Hermes fans a tool batch out to
    # workers. Every process consults the same profile-private SQLite latch.
    if name in _HISTORY_TOOLS:
        return None if _mark_disclosed(turn_id,**kwargs) else _LATCH_ERROR_BLOCK.copy()
    disclosed=_turn_was_disclosed(turn_id,**kwargs)
    if disclosed is None:return _LATCH_ERROR_BLOCK.copy()
    if disclosed and _blocked_tool(tool_name,args):return _LATCH_BLOCK.copy()
    return None


def _serialize_disclosure(result,kwargs):
    if result.get("success") and not _mark_disclosed(kwargs.get("turn_id"),**{k:v for k,v in kwargs.items() if k!="turn_id"}):
        # Never release model-facing data unless the cross-process latch is known
        # durable. The pre-hook normally creates it; this is a second fail-closed
        # boundary for direct handler calls and mid-call storage failures.
        result={"success":False,"error":"disclosure_state_unavailable"}
    return json.dumps(result,ensure_ascii=False)


def _search(args, **kwargs):
    result = HistoryService().search(args, session_id=kwargs.get("session_id"), turn_id=kwargs.get("turn_id"))
    return _serialize_disclosure(result,kwargs)


def _fetch(args, **kwargs):
    result = HistoryService().fetch(args, session_id=kwargs.get("session_id"), turn_id=kwargs.get("turn_id"))
    return _serialize_disclosure(result,kwargs)


def _attachment_fetch(args, **kwargs):
    result = HistoryService().attachment_fetch(args, session_id=kwargs.get("session_id"), turn_id=kwargs.get("turn_id"))
    return _serialize_disclosure(result,kwargs)


def _attachment_read(args, **kwargs):
    result = HistoryService().attachment_read(args, session_id=kwargs.get("session_id"), turn_id=kwargs.get("turn_id"))
    return _serialize_disclosure(result,kwargs)


def _archive_inspect(args, **kwargs):
    result=HistoryService().archive_inspect(args,session_id=kwargs.get("session_id"),turn_id=kwargs.get("turn_id"))
    return _serialize_disclosure(result,kwargs)


def _archive_extract(args, **kwargs):
    result=HistoryService().archive_extract(args,session_id=kwargs.get("session_id"),turn_id=kwargs.get("turn_id"))
    return _serialize_disclosure(result,kwargs)


def _document_parse(args, **kwargs):
    result=HistoryService().document_parse(args,session_id=kwargs.get("session_id"),turn_id=kwargs.get("turn_id"))
    return _serialize_disclosure(result,kwargs)


def _document_read(args, **kwargs):
    result=HistoryService().document_read(args,session_id=kwargs.get("session_id"),turn_id=kwargs.get("turn_id"))
    return _serialize_disclosure(result,kwargs)


def register(ctx):
    ctx.register_hook("pre_tool_call", _on_pre_tool_call)
    ctx.register_tool(name="history_search",toolset="history",schema=SEARCH_SCHEMA,handler=_search,check_fn=lambda:True,emoji="🔎")
    ctx.register_tool(name="history_fetch",toolset="history",schema=FETCH_SCHEMA,handler=_fetch,check_fn=lambda:True,emoji="📜")
    ctx.register_tool(name="history_attachment_fetch",toolset="history",schema=ATTACHMENT_SCHEMA,handler=_attachment_fetch,check_fn=lambda:True,emoji="📎")
    ctx.register_tool(name="history_attachment_read",toolset="history",schema=ATTACHMENT_READ_SCHEMA,handler=_attachment_read,check_fn=lambda:True,emoji="📄")
    ctx.register_tool(name="archive_inspect",toolset="history",schema=ARCHIVE_INSPECT_SCHEMA,handler=_archive_inspect,check_fn=lambda:True,emoji="🗃️")
    ctx.register_tool(name="archive_extract",toolset="history",schema=ARCHIVE_EXTRACT_SCHEMA,handler=_archive_extract,check_fn=lambda:True,emoji="📦")
    ctx.register_tool(name="document_parse",toolset="history",schema=DOCUMENT_PARSE_SCHEMA,handler=_document_parse,check_fn=lambda:True,emoji="🧱")
    ctx.register_tool(name="document_read",toolset="history",schema=DOCUMENT_READ_SCHEMA,handler=_document_read,check_fn=lambda:True,emoji="📖")
