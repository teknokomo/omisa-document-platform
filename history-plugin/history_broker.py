"""Minimal AF_UNIX/SCM_RIGHTS client for the sandbox parser broker."""
from __future__ import annotations

import array
import hashlib
import hmac
import json
import os
import secrets
import socket
from pathlib import Path

try:
    # Plugin-local, release-pinned protocol: never resolve an unrelated global
    # omisa_parser installation when validating broker traffic.
    from ._vendor.omisa_parser.protocol import ProtocolError, encode_request, validate_response_stream
except ImportError:  # direct module execution in the plugin test harness
    from _vendor.omisa_parser.protocol import ProtocolError, encode_request, validate_response_stream


class BrokerClientError(Exception):
    pass


class UnixBrokerClient:
    def __init__(self, socket_path: Path | str, credential: bytes | None, timeout: float = 90):
        self.socket_path = str(socket_path)
        self.credential = credential
        self.timeout = timeout

    def parse_fd(self, fd: int, *, artifact_ref: str, expected_size: int, options: dict):
        # Broker sees only a keyed, protocol-shaped alias, never the history token.
        alias = hmac.new(self.credential or b"omisa-peer-uid-artifact-alias-v1", b"artifact:" + artifact_ref.encode(), hashlib.sha256).digest()
        import base64
        opaque = "art_v1_" + base64.urlsafe_b64encode(alias).rstrip(b"=").decode()
        request_id = secrets.token_hex(16)
        request = {"protocol":"omisa.parse/1", "request_id":request_id,
                   "artifact_ref":opaque, "artifact_generation":0,
                   "expected_size":expected_size, "options":options}
        wire = encode_request(request, self.credential)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(self.socket_path)
            rights = array.array("i", [fd])
            # One sendmsg and one SCM_RIGHTS control message by contract.
            sent = sock.sendmsg([wire], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)])
            if sent != len(wire):
                raise BrokerClientError("broker_disconnect")
            sock.shutdown(socket.SHUT_WR)
            def chunks():
                while True:
                    data=sock.recv(65536)
                    if not data:return
                    yield data
            rows=[json.loads(line) for line in validate_response_stream(chunks(),request_id=request_id)]
            if rows[-1].get("type")=="error":
                raise BrokerClientError(rows[-1].get("code","parser_failed"))
            return rows
        except (OSError, socket.timeout) as exc:
            raise BrokerClientError("broker_disconnect") from exc
        except ProtocolError as exc:
            raise BrokerClientError("malformed_response") from exc
        finally:
            sock.close()


def configured_client():
    path=os.environ.get("OMISA_PARSER_SOCKET","/run/omisa-parser/parser.sock")
    configured=os.environ.get("OMISA_PARSER_CREDENTIAL")
    key=None
    if configured:
        try:key=Path(configured).read_bytes()
        except OSError as exc:raise BrokerClientError("broker_unavailable") from exc
        if not 32<=len(key)<=4096:raise BrokerClientError("broker_unavailable")
    return UnixBrokerClient(path,key)