import hashlib
import json
from pathlib import Path

import pytest

from omisa_parser.adapters import AdapterConfig, ExternalToolError, OcrAdapter, TikaAdapter, load_tika_checksum
from omisa_parser.core import Limits, ParseError, _detect, parse_document
from omisa_parser.protocol import ProtocolError, _validate_options

RID = "e" * 32


def blank_pdf(path: Path, pages: int = 3):
    import pymupdf
    document = pymupdf.open()
    for _ in range(pages):
        document.new_page()
    document.save(path)


def executable(tmp_path: Path, name: str, body: str) -> str:
    path = tmp_path / name
    path.write_text("#!/usr/bin/env python3\n" + body)
    path.chmod(0o755)
    return str(path)


def test_ocr_range_is_pushed_into_adapter_and_preserves_page_indices(tmp_path):
    class Fake:
        def __init__(self): self.call = None
        def extract_pdf(self, path, languages, page_range=None):
            self.call = (languages, page_range)
            return [("page", "2", [("ocrtext", "selected")], None, 2)]
    pdf = tmp_path / "scan.pdf"
    blank_pdf(pdf)
    fake = Fake()
    records = parse_document(pdf, RID, {"ocr":"force", "range":{"unit":"page", "start":2, "end":2}}, ocr_adapter=fake)
    assert fake.call == ([], (2, 2))
    unit = next(row for row in records if row["type"] == "unit")
    assert (unit["index"], unit["id"]) == (2, "u2")
    assert next(row for row in records if row["type"] == "text")["source"] == "ocr"


def test_ocr_renderer_receives_only_requested_range(tmp_path, monkeypatch):
    calls = tmp_path / "calls"
    pdfinfo = executable(tmp_path, "pdfinfo", "print('Pages: 100'); print('Page size: 72 x 72 pts')")
    pdftoppm = executable(tmp_path, "pdftoppm", """
import json,os,sys
open(os.environ['CALLS'],'a').write(json.dumps(sys.argv)+'\\n')
for page in range(int(sys.argv[sys.argv.index('-f')+1]), int(sys.argv[sys.argv.index('-l')+1])+1):
 open(sys.argv[-1]+f'-{page}.ppm','wb').write(b'P6\\n200 200\\n255\\n'+b'0'*(200*200*3))
""")
    tesseract = executable(tmp_path, "tesseract", "print('ocr')")
    monkeypatch.setenv("CALLS", str(calls))
    adapter = OcrAdapter(AdapterConfig(pdfinfo=pdfinfo, pdftoppm=pdftoppm, tesseract=tesseract, max_ocr_pages=2))
    units = adapter.extract_pdf(tmp_path / "x.pdf", ["eng"], (9, 10))
    argv = [json.loads(line) for line in calls.read_text().splitlines()]
    renders = [call for call in argv if call[0] == pdftoppm]
    assert [call[call.index("-f")+1] for call in renders] == ["9", "10"]
    assert [call[call.index("-l")+1] for call in renders] == ["9", "10"]
    assert [unit[4] for unit in units] == [9, 10]


def test_option_language_allowlist_and_no_comments_or_metadata():
    for hints in (["eng"], ["rus"], ["eng", "rus"], ["en", "ru"]):
        _validate_options({"language_hints": hints})
    for hints in (["de"], ["eng", "de"], "eng"):
        with pytest.raises(ProtocolError): _validate_options({"language_hints": hints})
    for include in (["comments"], ["metadata"]):
        with pytest.raises(ProtocolError): _validate_options({"include": include})


def test_external_tool_errors_map_to_schema_enums(tmp_path):
    pdf = tmp_path / "x.pdf"
    blank_pdf(pdf, 1)
    class BadOcr:
        def __init__(self, code): self.code = code
        def extract_pdf(self, *args, **kwargs): raise ExternalToolError(self.code)
    expected = {
        "ocr_timeout":"timeout", "ocr_output_limit":"output_limit",
        "ocr_page_limit":"resource_limit", "ocr_pixel_limit":"resource_limit",
        "unsupported_ocr_language":"invalid_request", "ocr_failed":"parser_failed",
    }
    for adapter_code, schema_code in expected.items():
        with pytest.raises(ParseError) as exc:
            parse_document(pdf, RID, {"ocr":"force"}, ocr_adapter=BadOcr(adapter_code))
        assert (exc.value.code, exc.value.stage) == (schema_code, "ocr")


def test_ole_detection_never_uses_unbounded_read(monkeypatch, tmp_path):
    path = tmp_path / "legacy.bin"
    path.write_bytes(bytes.fromhex("D0CF11E0A1B11AE1") + b"0" * 1024)
    seen = []
    real = Path.open
    class Guard:
        def __init__(self, stream): self.stream = stream
        def read(self, size=-1):
            seen.append(size)
            assert size != -1
            return self.stream.read(size)
        def __enter__(self): return self
        def __exit__(self, *args): return self.stream.__exit__(*args)
        def __getattr__(self, name): return getattr(self.stream, name)
    def guarded(self, *args, **kwargs):
        stream = real(self, *args, **kwargs)
        return Guard(stream) if self == path else stream
    monkeypatch.setattr(Path, "open", guarded)
    assert _detect(path, Limits())[0] == "ole"
    assert max(seen) <= Limits().max_input_bytes + 1


def test_tika_checksum_manifest_parser_is_strict_and_usable(tmp_path):
    digest = hashlib.sha256(b"jar").hexdigest()
    manifest = tmp_path / "manifest"
    manifest.write_text("# pinned\nTIKA_APP_3_3_2_SHA256=" + digest + "\n")
    assert load_tika_checksum(manifest) == digest
    jar = tmp_path / "tika-app-3.3.2.jar"; jar.write_bytes(b"jar")
    config = Path(__file__).resolve().parents[1] / "packaging/tika-config.xml"
    java = executable(tmp_path, "java", "print('legacy')")
    adapter = TikaAdapter(AdapterConfig(java=java, tika_jar=str(jar), tika_config=str(config), tika_sha256_manifest=str(manifest)))
    assert adapter.extract(tmp_path / "old.doc") == "legacy\n"
    manifest.write_text("TIKA_APP_3_3_2_SHA256=not-a-digest\n")
    with pytest.raises(ExternalToolError) as exc:
        load_tika_checksum(manifest)
    assert exc.value.code == "tika_integrity"


def test_rootfs_manifest_pins_external_and_python_dependencies():
    root = Path(__file__).resolve().parents[1]
    manifest = (root / "packaging/rootfs-manifest.txt").read_text()
    required = ["tika-app==3.3.2", "tesseract-ocr-eng==", "tesseract-ocr-rus==", "poppler-utils==", "default-jre-headless==", "libreoffice-core==", "PyMuPDF==1.28.2", "pytest==8.4.2"]
    assert all(item in manifest for item in required)
