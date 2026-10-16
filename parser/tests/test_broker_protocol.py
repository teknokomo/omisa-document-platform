from __future__ import annotations

import array
import base64
import fcntl
import json
import os
import socket
import struct
import threading
from pathlib import Path

import pytest

from omisa_parser.protocol import (
    ProtocolError,
    ReplayCache,
    canonical_header,
    encode_request,
    receive_request,
    validate_response_stream,
)

RID = "1" * 32
REF = "art_v1_" + "A" * 22


def header(**changes):
    value = {
        "protocol": "omisa.parse/1",
        "request_id": RID,
        "artifact_ref": REF,
        "artifact_generation": 7,
        "expected_size": 4,
        "options": {"ocr": "off", "include": ["text"], "max_records": 20},
    }
    value.update(changes)
    return value


def send_with_fds(sock, payload, fds):
    ancillary = []
    if fds:
        ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", fds))]
    sock.sendmsg([payload], ancillary)


def test_receive_exact_fd_canonical_hmac_and_replay(tmp_path):
    key = b"stage-secret"
    p = tmp_path / "input"
    p.write_bytes(b"safe")
    fd = os.open(p, os.O_RDONLY | os.O_CLOEXEC)
    left, right = socket.socketpair()
    try:
        payload = encode_request(header(), key)
        send_with_fds(left, payload, [fd])
        got, received = receive_request(right, allowed_uid=os.getuid(), hmac_key=key, replay_cache=ReplayCache())
        assert got["request_id"] == RID
        assert fcntl.fcntl(received, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY
        os.close(received)
    finally:
        os.close(fd)
        left.close()
        right.close()


def test_receive_rejects_duplicate_keys_noncanonical_and_extra_fd(tmp_path):
    p = tmp_path / "input"
    p.write_bytes(b"safe")
    fds = [os.open(p, os.O_RDONLY) for _ in range(2)]
    left, right = socket.socketpair()
    try:
        duplicate = b'{"protocol":"omisa.parse/1","protocol":"omisa.parse/1"}'
        send_with_fds(left, struct.pack("!I", len(duplicate)) + duplicate, fds)
        with pytest.raises(ProtocolError) as exc:
            receive_request(right, allowed_uid=os.getuid(), hmac_key=None, replay_cache=ReplayCache())
        assert exc.value.code == "invalid_request"
    finally:
        for fd in fds:
            os.close(fd)
        left.close()
        right.close()


def test_receive_rejects_writable_nonregular_size_mismatch_bad_hmac_and_replay(tmp_path):
    key = b"stage-secret"
    cache = ReplayCache()
    p = tmp_path / "input"
    p.write_bytes(b"safe")

    def attempt(hdr, open_flags=os.O_RDONLY, use_key=key):
        fd = os.open(p, open_flags)
        left, right = socket.socketpair()
        try:
            send_with_fds(left, encode_request(hdr, use_key), [fd])
            return receive_request(right, allowed_uid=os.getuid(), hmac_key=key, replay_cache=cache)
        finally:
            os.close(fd); left.close(); right.close()

    with pytest.raises(ProtocolError) as exc:
        attempt(header(), os.O_RDWR)
    assert exc.value.code == "invalid_request"
    with pytest.raises(ProtocolError) as exc:
        attempt(header(expected_size=3))
    assert exc.value.code == "artifact_changed"
    with pytest.raises(ProtocolError) as exc:
        attempt(header(), use_key=b"wrong")
    assert exc.value.code == "unauthorized"
    got, received = attempt(header(request_id="2" * 32)); os.close(received)
    with pytest.raises(ProtocolError) as exc:
        attempt(header(request_id="2" * 32))
    assert exc.value.code == "unauthorized"


def test_header_cap_peer_uid_and_strict_shape(tmp_path):
    p = tmp_path / "input"; p.write_bytes(b"safe")
    fd = os.open(p, os.O_RDONLY)
    left, right = socket.socketpair()
    try:
        send_with_fds(left, encode_request(header(), None), [fd])
        with pytest.raises(ProtocolError) as exc:
            receive_request(right, allowed_uid=os.getuid() + 1, hmac_key=None, replay_cache=ReplayCache())
        assert exc.value.code == "unauthorized"
    finally:
        os.close(fd); left.close(); right.close()
    assert len(canonical_header(header(options={"junk": True}))) < 8192
    with pytest.raises(ProtocolError):
        encode_request(header(options={"junk": True}), None)
    with pytest.raises(ProtocolError):
        encode_request(header(artifact_ref="/tmp/leak"), None)


def test_response_jsonl_is_bounded_terminal_and_path_free():
    end = {"schema":"omisa.document/1","type":"end","request_id":RID,"status":"ok","counts":{"units_emitted":0,"records_emitted":1,"text_chars":0,"tables":0,"cells":0},"truncated":False,"limit_reason":None,"warnings":[]}
    raw = (json.dumps(end, separators=(",", ":")) + "\n").encode()
    with pytest.raises(ProtocolError):
        list(validate_response_stream([raw], request_id=RID))
    with pytest.raises(ProtocolError):
        list(validate_response_stream([raw, b"{}\n"], request_id=RID))
    with pytest.raises(ProtocolError):
        list(validate_response_stream([b'{"type":"text","path":"/tmp/canary"}\n', raw], request_id=RID))
    # Path-like strings in a positive-schema content field are document data,
    # not broker provenance; covered separately below.
    with pytest.raises(ProtocolError):
        list(validate_response_stream([b"{" + b"x" * (256 * 1024) + b"}\n"], request_id=RID))


def _terminal(kind="end"):
    if kind == "error":
        return {"schema":"omisa.document/1","type":"error","request_id":RID,"status":"error","code":"parser_failed","retryable":False,"stage":"output"}
    return {"schema":"omisa.document/1","type":"end","request_id":RID,"status":"ok","counts":{"units_emitted":0,"records_emitted":1,"text_chars":0,"tables":0,"cells":0},"truncated":False,"limit_reason":None,"warnings":[]}


def test_response_allows_path_like_strings_only_inside_positive_schema_content():
    rows = [
        {"schema":"omisa.document/1","type":"document","request_id":RID,
         "document":{"detected_format":"txt","media_type":"text/plain","size_bytes":10,"title":None,"language":None},
         "parser":{"bundle_version":"test","registry_version":1},
         "structure":{"unit":"page","unit_count":1,"pagination":"logical"},"warnings":[]},
        {"schema":"omisa.document/1","type":"unit","id":"u1","unit_kind":"page","index":1,"label":"1","parent_id":None},
        {"schema":"omisa.document/1","type":"text","id":"b1","unit_id":"u1","order":1,
         "text":"zpool create data mirror /dev/sda /dev/sdb","source":"native","truncated":False},
    ]
    counts={"units_emitted":1,"records_emitted":4,"text_chars":len(rows[-1]["text"]),"tables":0,"cells":0}
    rows.append({"schema":"omisa.document/1","type":"end","request_id":RID,"status":"ok","counts":counts,"truncated":False,"limit_reason":None,"warnings":[]})
    raw=b"".join((json.dumps(row,separators=(",",":"))+"\n").encode() for row in rows)
    assert len(list(validate_response_stream([raw],request_id=RID)))==4


def test_response_rejects_terminal_and_trailing_data_in_same_chunk():
    terminal = (json.dumps(_terminal("error"), separators=(",", ":")) + "\n").encode()
    for trailing in (b"{}\n", b"not-yet-a-line"):
        with pytest.raises(ProtocolError) as exc:
            list(validate_response_stream([terminal + trailing], request_id=RID))
        assert exc.value.code == "parser_failed"


def test_response_end_requires_document_but_error_may_be_the_only_record():
    end = (json.dumps(_terminal(), separators=(",", ":")) + "\n").encode()
    error = (json.dumps(_terminal("error"), separators=(",", ":")) + "\n").encode()
    with pytest.raises(ProtocolError):
        list(validate_response_stream([end], request_id=RID))
    assert list(validate_response_stream([error], request_id=RID)) == [error]


def test_response_allows_exactly_one_terminal_record():
    error = (json.dumps(_terminal("error"), separators=(",", ":")) + "\n").encode()
    with pytest.raises(ProtocolError):
        list(validate_response_stream([error + error], request_id=RID))


def test_response_validator_yields_before_reading_later_chunks():
    error = (json.dumps(_terminal("error"), separators=(",", ":")) + "\n").encode()
    consumed = []
    def chunks():
        consumed.append("first")
        yield error
        consumed.append("second")
        yield b""
    stream = validate_response_stream(chunks(), request_id=RID)
    assert iter(stream) is stream
    assert next(stream) == error
    assert consumed == ["first"]
