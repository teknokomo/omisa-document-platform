import hashlib, json, os, socket, sys, threading
from pathlib import Path

ROOT=Path(__file__).parents[1];sys.path.insert(0,str(ROOT))
from history_broker import UnixBrokerClient
from omisa_parser.service import BrokerConfig, BrokerService


class Launcher:
    def run(self,input_path,output_path,request,timeout):
        size=input_path.stat().st_size; rid=request["request_id"]
        rows=[
          {"schema":"omisa.document/1","type":"document","request_id":rid,"document":{"detected_format":"txt","media_type":"text/plain","size_bytes":size,"title":None,"language":None},"parser":{"bundle_version":"test","registry_version":1},"structure":{"unit":"page","unit_count":0},"warnings":[]},
          {"schema":"omisa.document/1","type":"end","request_id":rid,"status":"ok","counts":{"units_emitted":0,"records_emitted":2,"text_chars":0,"tables":0,"cells":0},"truncated":False,"limit_reason":None,"warnings":[]},
        ]
        output_path.write_text("".join(json.dumps(x,separators=(",",":"))+"\n" for x in rows))


def test_real_socketpair_sends_one_fd_to_broker_service(tmp_path):
    left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM); key=b"k"*32
    service=BrokerService(BrokerConfig(os.getuid(),key,tmp_path/"runtime"),Launcher())
    thread=threading.Thread(target=service.handle,args=(right,));thread.start()
    class PairClient(UnixBrokerClient):
        def parse_fd(self,fd,**kwargs):
            original=socket.socket
            class Wrapper:
                def __init__(self,*a,**k): self.s=left
                def __getattr__(self,n): return getattr(self.s,n)
                def connect(self,p): pass
            socket.socket=Wrapper
            try:return super().parse_fd(fd,**kwargs)
            finally:socket.socket=original
    document=tmp_path/"doc";document.write_bytes(b"hello")
    fd=os.open(document,os.O_RDONLY)
    try: rows=PairClient("unused",key).parse_fd(fd,artifact_ref="legacyToken",expected_size=5,options={})
    finally:os.close(fd)
    thread.join(2)
    assert [r["type"] for r in rows]==["document","end"] and not thread.is_alive()


def test_history_client_vendors_exact_release_parser_protocol():
    vendored = ROOT / "_vendor/omisa_parser/protocol.py"
    authoritative = ROOT.parent / "parser/omisa_parser/protocol.py"
    assert vendored.is_file()
    assert hashlib.sha256(vendored.read_bytes()).digest() == hashlib.sha256(authoritative.read_bytes()).digest()
    source = (ROOT / "history_broker.py").read_text()
    assert "_vendor.omisa_parser.protocol" in source
def test_configured_client_uses_canonical_parser_socket(monkeypatch, tmp_path):
    from history_plugin.history_broker import configured_client
    key = tmp_path / "key"; key.write_bytes(b"x" * 32)
    monkeypatch.delenv("OMISA_PARSER_SOCKET", raising=False)
    monkeypatch.setenv("OMISA_PARSER_CREDENTIAL", str(key))
    assert configured_client().socket_path == "/run/omisa-parser/parser.sock"
