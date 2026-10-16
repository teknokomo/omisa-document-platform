#!/usr/bin/python3
"""Send one canonical SCM_RIGHTS request to the staging socket."""
import array, json, os, socket, sys, tempfile
sys.path.insert(0, "/usr/lib/omisa-parser/app")
from omisa_parser.protocol import encode_request

socket_path, request_id = sys.argv[1:]
body = b"parser staging canary\n"
request = {
    "protocol": "omisa.parse/1", "request_id": request_id,
    "artifact_ref": "art_v1_" + "a" * 64, "artifact_generation": 1,
    "expected_size": len(body),
    "options": {"ocr": "off", "include": ["text"], "max_records": 20},
}
wire = encode_request(request, None)
fd, name = tempfile.mkstemp()
try:
    os.write(fd, body); os.close(fd)
    fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC)
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); client.connect(socket_path)
    client.sendmsg([wire],
                   [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd]))])
    client.shutdown(socket.SHUT_WR)
    response = client.makefile("rb").read()
    records = [json.loads(line) for line in response.splitlines()]
    if not records or records[-1].get("type") != "end": raise SystemExit(response.decode(errors="replace"))
finally:
    os.close(fd); os.unlink(name)