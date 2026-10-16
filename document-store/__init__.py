"""Omisa durable document storage plugin."""
from __future__ import annotations

try:
    from .document_store import document_get, document_list, document_save
except ImportError:  # Direct source-tree import used by the isolated test harness.
    from document_store import document_get, document_list, document_save

SAVE_SCHEMA = {
    "name": "document_save",
    "description": (
        "Permanently save a significant user document from the profile document cache "
        "into Omisa's durable workspace. Use only when the user explicitly asks to "
        "save/remember a document, expects future work on it, calls it a base/project "
        "document, or asks to add it to the knowledge base. Do not save credentials, "
        "secrets, or incidental attachments. Provenance and access metadata are derived "
        "automatically from the live gateway session; do not supply sender or chat IDs."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Canonical local path from the attachment context."},
            "title": {"type": "string", "description": "Human-readable document title."},
            "visibility": {"type": "string", "enum": ["team", "restricted", "private"], "default": "team"},
            "labels": {"type": "array", "items": {"type": "string", "enum": ["автосохранение"]}, "maxItems": 1},
        },
        "required": ["path", "title"],
        "additionalProperties": False,
    },
}

LIST_SCHEMA = {
    "name": "document_list",
    "description": "List durable Omisa documents visible to the current conversation, optionally filtering by title, filename, ID, or SHA-256.",
    "parameters": {
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "Optional case-insensitive substring filter."},
            "label": {"type": "string", "description": "Optional exact label filter, e.g. автосохранение."},
            "status": {"type": "string", "description": "Optional exact status filter, e.g. inbox."},
            "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 20},
        },
        "additionalProperties": False,
    },
}

GET_SCHEMA = {
    "name": "document_get",
    "description": "Return metadata for one durable document visible to the current conversation, by opaque document ID. Host paths are never returned.",
    "parameters": {
        "type": "object",
        "properties": {
            "document_id": {"type": "string", "pattern": r"^doc-[0-9a-f]{16}$"},
        },
        "required": ["document_id"],
        "additionalProperties": False,
    },
}
def register(ctx) -> None:
    for name, schema, handler, emoji in (
        ("document_save", SAVE_SCHEMA, document_save, "📥"),
        ("document_list", LIST_SCHEMA, document_list, "📚"),
        ("document_get", GET_SCHEMA, document_get, "📄"),
    ):
        ctx.register_tool(name=name, toolset="documents", schema=schema, handler=handler, emoji=emoji)
