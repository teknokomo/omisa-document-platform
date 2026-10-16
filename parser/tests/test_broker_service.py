from __future__ import annotations

import array
import json
import os
import socket
import threading
from pathlib import Path

from omisa_parser.service import BrokerConfig, BrokerService, LocalLauncher
from omisa_parser.protocol import encode_request

RID = "3" * 32
REF = "art_v1_" + "B" * 22
FIX = Path(__file__).resolve().parents[1] / "fixtures/sample.txt"


def request(size):
    return {
        "protocol": "omisa.parse/1",
        "request_id": RID,
        "artifact_ref": REF,
        "artifact_generation": 1,
        "expected_size": size,
        "options": {"ocr": "off", "include": ["text"], "max_records": 20},
    }


def test_socketpair_fd_to_private_copy_to_bounded_response(tmp_path):
    key = b"root-managed-test-key"
    client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    config = BrokerConfig(allowed_uid=os.getuid(), credential=key, runtime_dir=tmp_path)
    broker = BrokerService(config, LocalLauncher())
    thread = threading.Thread(target=broker.handle, args=(server,))
    thread.start()
    fd = os.open(FIX, os.O_RDONLY | os.O_CLOEXEC)
    try:
        payload = encode_request(request(FIX.stat().st_size), key)
        client.sendmsg([payload], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd]))])
        client.shutdown(socket.SHUT_WR)
        raw = bytearray()
        while True:
            chunk = client.recv(65536)
            if not chunk:
                break
            raw.extend(chunk)
    finally:
        os.close(fd); client.close(); thread.join(10)
    rows = [json.loads(line) for line in raw.splitlines()]
    assert rows[0]["type"] == "document"
    assert rows[-1]["type"] == "end"
    assert all(row.get("request_id", RID) == RID for row in rows)
    assert b"/home/" not in raw and REF.encode() not in raw
    assert not list(tmp_path.iterdir()), "private job directory must be removed"


def test_protocol_failure_is_one_categorical_terminal_record(tmp_path):
    client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    broker = BrokerService(BrokerConfig(os.getuid(), b"right", tmp_path), LocalLauncher())
    thread = threading.Thread(target=broker.handle, args=(server,)); thread.start()
    fd = os.open(FIX, os.O_RDONLY)
    try:
        client.sendmsg([encode_request(request(FIX.stat().st_size), b"wrong")], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd]))])
        client.shutdown(socket.SHUT_WR)
        raw = client.recv(65536)
    finally:
        os.close(fd); client.close(); thread.join(10)
    rows = [json.loads(x) for x in raw.splitlines()]
    assert len(rows) == 1 and rows[0]["type"] == "error"
    assert rows[0]["code"] == "unauthorized"
    assert set(rows[0]) == {"schema", "type", "request_id", "status", "code", "retryable", "stage"}
