from __future__ import annotations

import array
import base64
import fcntl
import hashlib
import hmac
import json
import os
import re
import socket
import stat
import struct
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Iterable
from pathlib import Path
from jsonschema import Draft202012Validator

PROTOCOL = "omisa.parse/1"
MAX_HEADER = 8192
MAX_LINE = 256 * 1024
MAX_RESPONSE = 8 * 1024 * 1024
_RESPONSE_SCHEMA = Path(__file__).with_name("schemas") / "document-jsonl-record-v1.schema.json"
_RESPONSE_VALIDATOR = Draft202012Validator(json.loads(_RESPONSE_SCHEMA.read_text(encoding='utf-8')))
ALLOWED_OPTIONS = {"ocr", "language_hints", "include", "range", "max_records", "record_offset", "unit_offset"}
ALLOWED_INCLUDES = {"text", "tables", "notes"}
ALLOWED_LANGUAGES = {"en", "eng", "ru", "rus"}
PATH_KEYS = {"path", "filename", "file", "url", "input", "output"}


class ProtocolError(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass
class ReplayCache:
    ttl: float = 300
    maximum: int = 4096

    def __post_init__(self):
        self._seen: OrderedDict[str, float] = OrderedDict()

    def add(self, request_id: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        while self._seen and next(iter(self._seen.values())) <= now - self.ttl:
            self._seen.popitem(last=False)
        if request_id in self._seen:
            return False
        self._seen[request_id] = now
        while len(self._seen) > self.maximum:
            self._seen.popitem(last=False)
        return True


def _reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError("invalid_request")
        result[key] = value
    return result


def _validate_options(options):
    if not isinstance(options, dict) or set(options) - ALLOWED_OPTIONS:
        raise ProtocolError("invalid_request")
    ocr = options.get("ocr", "auto")
    if ocr not in {"off", "auto", "force"}:
        raise ProtocolError("invalid_request")
    hints = options.get("language_hints", [])
    if not isinstance(hints, list) or len(hints) > 2 or len(set(hints)) != len(hints) or any(not isinstance(x, str) or x.lower() not in ALLOWED_LANGUAGES for x in hints):
        raise ProtocolError("invalid_request")
    include = options.get("include", ["text", "tables", "notes"])
    if not isinstance(include, list) or len(set(include)) != len(include) or any(x not in ALLOWED_INCLUDES for x in include):
        raise ProtocolError("invalid_request")
    maximum = options.get("max_records", 200)
    offset = options.get("record_offset", 0)
    unit_offset = options.get("unit_offset", 0)
    if type(maximum) is not int or not 1 <= maximum <= 500 or type(offset) is not int or not 0 <= offset <= 1000000 or type(unit_offset) is not int or not 0 <= unit_offset <= 1000000:
        raise ProtocolError("invalid_request")
    if "range" in options:
        value = options["range"]
        if not isinstance(value, dict) or set(value) != {"unit", "start", "end"} or value["unit"] not in {"page", "sheet", "slide"}:
            raise ProtocolError("invalid_request")
        start, end = value["start"], value["end"]
        if type(start) is not int or type(end) is not int or start < 1 or end < start or end - start + 1 > 50:
            raise ProtocolError("invalid_request")


def validate_header(value, require_attestation=False):
    required = {"protocol", "request_id", "artifact_ref", "artifact_generation", "expected_size", "options"}
    allowed = required | {"attestation"}
    if not isinstance(value, dict) or set(value) - allowed or not required <= set(value):
        raise ProtocolError("invalid_request")
    if value["protocol"] != PROTOCOL or not isinstance(value["request_id"], str) or not re.fullmatch(r"[a-f0-9]{32}", value["request_id"]):
        raise ProtocolError("invalid_request")
    if not isinstance(value["artifact_ref"], str) or not re.fullmatch(r"art_v1_[A-Za-z0-9_-]{22,128}", value["artifact_ref"]):
        raise ProtocolError("invalid_request")
    if type(value["artifact_generation"]) is not int or value["artifact_generation"] < 0:
        raise ProtocolError("invalid_request")
    if type(value["expected_size"]) is not int or not 1 <= value["expected_size"] <= 20 * 1024 * 1024:
        raise ProtocolError("invalid_request")
    _validate_options(value["options"])
    if require_attestation and not isinstance(value.get("attestation"), str):
        raise ProtocolError("unauthorized")
    return value


def canonical_header(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _attestation(value, key):
    unsigned = dict(value)
    unsigned.pop("attestation", None)
    digest = hmac.new(key, canonical_header(unsigned), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def encode_request(value, key):
    value = dict(value)
    validate_header(value)
    if key is not None:
        value["attestation"] = _attestation(value, key)
    raw = canonical_header(value)
    if len(raw) > MAX_HEADER:
        raise ProtocolError("invalid_request")
    return struct.pack("!I", len(raw)) + raw


def _close_all(fds):
    for fd in fds:
        try: os.close(fd)
        except OSError: pass


def receive_request(sock, *, allowed_uid, hmac_key, replay_cache):
    pid, uid, gid = struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
    if uid != allowed_uid:
        raise ProtocolError("unauthorized")
    # Stream sockets may split the 4-byte prefix from the SCM_RIGHTS-bearing
    # payload. Read only the prefix in recvmsg so ancillary data is captured
    # deterministically, then read the exact JSON body with recv().
    ancbuf = socket.CMSG_SPACE(array.array("i", [0, 0]).itemsize * 2)
    data, ancillary, flags, _ = sock.recvmsg(4, ancbuf)
    fds = []
    for level, typ, payload in ancillary:
        if level == socket.SOL_SOCKET and typ == socket.SCM_RIGHTS:
            values = array.array("i")
            values.frombytes(payload[: len(payload) - len(payload) % values.itemsize])
            fds.extend(values)
    if flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC) or len(fds) != 1:
        _close_all(fds)
        raise ProtocolError("invalid_request")
    fd = fds[0]
    try:
        while len(data) < 4:
            more = sock.recv(4 - len(data))
            if not more: raise ProtocolError("invalid_request")
            data += more
        length = struct.unpack("!I", data[:4])[0]
        if not 1 <= length <= MAX_HEADER:
            raise ProtocolError("invalid_request")
        raw = data[4:]
        while len(raw) < length:
            more = sock.recv(length - len(raw))
            if not more: raise ProtocolError("invalid_request")
            raw += more
        if len(raw) != length:
            raise ProtocolError("invalid_request")
        try:
            value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicates, parse_constant=lambda _: (_ for _ in ()).throw(ProtocolError("invalid_request")))
        except ProtocolError: raise
        except Exception: raise ProtocolError("invalid_request")
        validate_header(value, require_attestation=hmac_key is not None)
        if canonical_header(value) != raw:
            raise ProtocolError("invalid_request")
        if hmac_key is not None and not hmac.compare_digest(value["attestation"], _attestation(value, hmac_key)):
            raise ProtocolError("unauthorized")
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size != value["expected_size"]:
            raise ProtocolError("artifact_changed" if stat.S_ISREG(st.st_mode) else "invalid_request")
        if fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY:
            raise ProtocolError("invalid_request")
        if not replay_cache.add(value["request_id"]):
            raise ProtocolError("unauthorized")
        os.lseek(fd, 0, os.SEEK_SET)
        return value, fd
    except Exception:
        _close_all([fd])
        raise


def _contains_path_key(value):
    """Reject structural path/provenance fields, not path-like document text.

    Extracted untrusted content may legitimately quote commands such as
    ``zpool ... /dev/sda``. Blocking arbitrary string values misclassifies that
    user content as host-path disclosure; the positive response schema already
    confines where content strings may occur.
    """
    if isinstance(value, dict):
        return any(str(k).lower() in PATH_KEYS or _contains_path_key(v) for k, v in value.items())
    if isinstance(value, list):
        return any(_contains_path_key(v) for v in value)
    return False


def validate_response_stream(chunks: Iterable[bytes], *, request_id: str):
    total = 0
    buffer = b""
    emitted = 0
    terminal = False
    document = False
    ids = set()
    units = set()
    orders = {}
    counts = {"units_emitted": 0, "records_emitted": 0, "text_chars": 0, "tables": 0, "cells": 0}
    warnings = None
    for chunk in chunks:
        if terminal and chunk:
            raise ProtocolError("parser_failed")
        total += len(chunk)
        if total > MAX_RESPONSE:
            raise ProtocolError("output_limit")
        buffer += chunk
        while b"\n" in buffer:
            if terminal:
                raise ProtocolError("parser_failed")
            line, buffer = buffer.split(b"\n", 1)
            if not line or len(line) > MAX_LINE:
                raise ProtocolError("output_limit")
            try:
                row = json.loads(line.decode("utf-8"), object_pairs_hook=_reject_duplicates, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
            except Exception:
                raise ProtocolError("parser_failed")
            if not isinstance(row, dict) or _contains_path_key(row):
                raise ProtocolError("parser_failed")
            if next(_RESPONSE_VALIDATOR.iter_errors(row), None) is not None:
                raise ProtocolError("parser_failed")
            typ = row.get("type")
            counts["records_emitted"] += 1
            if typ == "document":
                if document or emitted or row.get("request_id") != request_id:
                    raise ProtocolError("parser_failed")
                document = True
                warnings = row["warnings"]
            elif typ in {"end", "error"}:
                if row.get("request_id") != request_id or terminal:
                    raise ProtocolError("parser_failed")
                if typ == "end" and (not document or row["counts"] != counts or row["warnings"] != warnings):
                    raise ProtocolError("parser_failed")
                terminal = True
            else:
                if not document:
                    raise ProtocolError("parser_failed")
                ident = row.get("id")
                if ident in ids:
                    raise ProtocolError("parser_failed")
                ids.add(ident)
                if typ == "unit":
                    if row.get("parent_id") is not None and row["parent_id"] not in units:
                        raise ProtocolError("parser_failed")
                    units.add(ident); counts["units_emitted"] += 1
                else:
                    uid = row.get("unit_id")
                    if uid not in units or row.get("order", 0) <= orders.get(uid, 0):
                        raise ProtocolError("parser_failed")
                    orders[uid] = row["order"]
                    if typ in {"text", "note"}: counts["text_chars"] += len(row["text"])
                    elif typ == "table": counts["tables"] += 1; counts["cells"] += len(row["cells"])
            emitted += 1
            yield line + b"\n"
    if buffer or not terminal:
        raise ProtocolError("parser_failed")
    # End.counts includes the end record itself, but validation compared it
    # before incrementing the running count above. Account for that terminal
    # record explicitly when the stream is otherwise complete.
