import json
import os
from pathlib import Path

import pytest

from omisa_parser.adapters import (
    AdapterConfig,
    ExternalToolError,
    LibreOfficeAdapter,
    OcrAdapter,
    TikaAdapter,
)
from omisa_parser.core import ParseError, parse_document


def executable(tmp_path: Path, name: str, body: str) -> str:
    path = tmp_path / name
    path.write_text("#!/usr/bin/env python3\n" + body)
    path.chmod(0o755)
    return str(path)


def read_calls(path: Path):
    return [json.loads(x) for x in path.read_text().splitlines()]


def blank_pdf(path: Path):
    import pymupdf
    document = pymupdf.open()
    document.new_page()
    document.save(path)




def test_pdfinfo_numbered_page_size_is_accepted(monkeypatch, tmp_path):
    pdf = tmp_path / "scan.pdf"
    blank_pdf(pdf)
    responses = iter([b"Pages: 1\n", b"Page    1 size:  595.276 x 841.89 pts (A4)\n"])

    def fake_run(argv, *args, **kwargs):
        if argv[0].endswith("pdfinfo"):
            return next(responses)
        if argv[0].endswith("pdftoppm"):
            prefix = Path(argv[-1])
            (prefix.parent / f"{prefix.name}-1.ppm").write_bytes(b"P6\n9 12\n255\n" + b"\0" * (9 * 12 * 3))
            return b""
        return b"scanned text\n"

    monkeypatch.setattr("omisa_parser.adapters._run", fake_run)
    adapter = OcrAdapter(AdapterConfig(dpi=1))
    units = adapter.extract_pdf(pdf, ["eng"], (1, 1))
    assert units[0][0] == "page"

def mixed_three_page_pdf(path: Path):
    """Build a real PDF with native text, a synthetic scan, and short native text."""
    import pymupdf
    document = pymupdf.open()
    scan = document.new_page()
    scan.draw_rect((72, 72, 300, 180), color=(0, 0, 0), fill=(0.9, 0.9, 0.9))
    scan.draw_line((90, 110), (280, 110), color=(0, 0, 0), width=3)
    second = document.new_page()
    second.insert_text((72, 72), "adequate native text on page two")
    third = document.new_page()
    third.insert_text((72, 72), "tiny")
    document.save(path)


def test_ocr_exact_argv_and_force_integration(tmp_path, monkeypatch):
    calls = tmp_path / "calls"
    pdfinfo = executable(tmp_path, "pdfinfo", """
import json,os,sys
open(os.environ['CALLS'],'a').write(json.dumps(sys.argv)+'\\n')
print('Pages: 1')
print('Page size: 0.72 x 0.72 pts')
""")
    pdftoppm = executable(tmp_path, "pdftoppm", """
import json,os,sys
open(os.environ['CALLS'],'a').write(json.dumps(sys.argv)+'\\n')
open(sys.argv[-1]+'-1.ppm','wb').write(b'P6\\n2 2\\n255\\n'+b'0'*12)
""")
    tesseract = executable(tmp_path, "tesseract", """
import json,os,sys
open(os.environ['CALLS'],'a').write(json.dumps(sys.argv)+'\\n')
print('OCR text')
""")
    monkeypatch.setenv("CALLS", str(calls))
    pdf = tmp_path / "scan.pdf"
    blank_pdf(pdf)
    adapter = OcrAdapter(AdapterConfig(pdfinfo=pdfinfo, pdftoppm=pdftoppm, tesseract=tesseract))
    records = parse_document(pdf, "a"*32, {"ocr":"force", "language_hints":["ru","en"]}, ocr_adapter=adapter)
    assert next(r for r in records if r["type"] == "text")["source"] == "ocr"
    assert "OCR text" in json.dumps(records)
    argv = read_calls(calls)
    assert argv[0] == [pdfinfo, str(pdf)]
    assert argv[1] == [pdfinfo, "-f", "1", "-l", "1", str(pdf)]
    # Poppler 24.02 renders PPM by default and no longer accepts a -ppm flag.
    assert argv[2][0:7] == [pdftoppm, "-f", "1", "-l", "1", "-r", "200"]
    assert argv[2][7] == str(pdf)
    assert argv[3][0:5] == [tesseract, argv[2][-1] + "-1.ppm", "stdout", "-l", "rus+eng"]
    assert argv[3][5:] == ["--psm", "3"]


def test_ocr_off_never_invokes_adapter(tmp_path):
    class Bomb:
        def extract_pdf(self, *args, **kwargs):
            raise AssertionError("OCR invoked")
    pdf = tmp_path / "x.pdf"
    blank_pdf(pdf)
    parse_document(pdf, "b"*32, {"ocr":"off"}, ocr_adapter=Bomb())


def test_ocr_auto_only_runs_for_textless_pdf(tmp_path, monkeypatch):
    class Fake:
        def __init__(self): self.calls = 0
        def extract_pdf(self, path, languages, page_range=None):
            self.calls += 1
            return [("page", "1", [("ocrtext", "seen")])]
    pdf = tmp_path / "x.pdf"; blank_pdf(pdf)
    fake = Fake()
    records = parse_document(pdf, "c"*32, {"ocr":"auto"}, ocr_adapter=fake)
    assert fake.calls == 1 and any(r.get("source") == "ocr" for r in records)


def test_ocr_auto_is_page_selective_and_merges_mixed_pdf_in_page_order(tmp_path):
    class Fake:
        def __init__(self): self.ranges = []
        def extract_pdf(self, path, languages, page_range=None):
            self.ranges.append(page_range)
            first, last = page_range
            return [("page", str(page), [("ocrtext", f"OCR page {page}")], None, page)
                    for page in range(first, last + 1)]

    pdf = tmp_path / "mixed.pdf"
    mixed_three_page_pdf(pdf)
    fake = Fake()
    records = parse_document(pdf, "d" * 32, {"ocr": "auto"}, ocr_adapter=fake)

    assert fake.ranges == [(1, 1), (3, 3)]
    units = [record for record in records if record["type"] == "unit"]
    assert [record["index"] for record in units] == [1, 2, 3]
    text = [record for record in records if record["type"] == "text"]
    assert [(record["unit_id"], record["source"]) for record in text] == [
        ("u1", "ocr"), ("u2", "native"), ("u3", "ocr")]
    assert "tiny" not in [record["text"] for record in text]
    assert records[0]["structure"]["unit_count"] == 3
    assert records[0]["warnings"] == records[-1]["warnings"]
    assert records[-1]["counts"]["units_emitted"] == 3
    assert records[-1]["counts"]["text_chars"] == sum(len(record["text"]) for record in text)


def test_ocr_auto_pushes_requested_range_and_skips_adequate_pages(tmp_path):
    class Fake:
        def __init__(self): self.ranges = []
        def extract_pdf(self, path, languages, page_range=None):
            self.ranges.append(page_range)
            page = page_range[0]
            return [("page", str(page), [("ocrtext", f"OCR page {page}")], None, page)]

    pdf = tmp_path / "mixed.pdf"
    mixed_three_page_pdf(pdf)
    fake = Fake()
    records = parse_document(pdf, "e" * 32, {
        "ocr": "auto", "range": {"unit": "page", "start": 1, "end": 2}},
        ocr_adapter=fake)

    assert fake.ranges == [(1, 1)]
    assert [r["index"] for r in records if r["type"] == "unit"] == [1, 2]
    assert [r["source"] for r in records if r["type"] == "text"] == ["ocr", "native"]


def test_ocr_language_allowlist_and_page_limit(tmp_path):
    pdf = tmp_path / "x.pdf"; pdf.write_bytes(b"x")
    adapter = OcrAdapter(AdapterConfig())
    with pytest.raises(ExternalToolError) as e:
        adapter.extract_pdf(pdf, ["de"])
    assert e.value.code == "unsupported_ocr_language"


def test_pdfinfo_page_and_pixel_policy(tmp_path, monkeypatch):
    pdfinfo = executable(tmp_path, "pdfinfo", "print('Pages: 21'); print('Page size: 612 x 792 pts')")
    adapter = OcrAdapter(AdapterConfig(pdfinfo=pdfinfo))
    with pytest.raises(ExternalToolError) as e:
        adapter.extract_pdf(tmp_path / "x", ["en"])
    assert e.value.code == "ocr_page_limit"

    huge = executable(tmp_path, "huge", "print('Pages: 1'); print('Page size: 20000 x 20000 pts')")
    adapter = OcrAdapter(AdapterConfig(pdfinfo=huge))
    with pytest.raises(ExternalToolError) as e:
        adapter.extract_pdf(tmp_path / "x", ["en"])
    assert e.value.code == "ocr_pixel_limit"


def test_ocr_checks_each_page_geometry_and_processes_one_raster_at_a_time(tmp_path, monkeypatch):
    calls = tmp_path / "calls"
    pdfinfo = executable(tmp_path, "pdfinfo-pages", """
import json,os,sys
open(os.environ['CALLS'],'a').write(json.dumps(sys.argv)+'\\n')
print('Pages: 2')
page = int(sys.argv[sys.argv.index('-f')+1]) if '-f' in sys.argv else 1
print('Page size: %s x 72 pts' % (72 if page == 1 else 144))
""")
    pdftoppm = executable(tmp_path, "render-pages", """
import glob,json,os,sys
open(os.environ['CALLS'],'a').write(json.dumps(sys.argv)+'\\n')
assert not glob.glob(os.path.join(os.path.dirname(sys.argv[-1]), '*.ppm'))
page=int(sys.argv[sys.argv.index('-f')+1])
w=200 if page == 1 else 400
open(sys.argv[-1]+'-'+str(page)+'.ppm','wb').write(('P6\\n%d 200\\n255\\n'%w).encode()+b'0'*(w*200*3))
""")
    tesseract = executable(tmp_path, "ocr-pages", """
import json,os,sys
open(os.environ['CALLS'],'a').write(json.dumps(sys.argv)+'\\n')
print('page text')
""")
    monkeypatch.setenv("CALLS", str(calls))
    pdf = tmp_path / "x.pdf"; pdf.write_bytes(b"pdf")
    config = AdapterConfig(pdfinfo=pdfinfo, pdftoppm=pdftoppm, tesseract=tesseract,
                           dpi=200, max_total_pixels=200_000)
    units = OcrAdapter(config).extract_pdf(pdf, ["eng"])
    assert [unit[1] for unit in units] == ["1", "2"]
    calls_seen = read_calls(calls)
    assert [call[0] for call in calls_seen] == [pdfinfo, pdfinfo, pdftoppm, tesseract,
                                                pdfinfo, pdftoppm, tesseract]
    for page in (1, 2):
        page_info = calls_seen[1 + (page - 1) * 3]
        assert page_info[page_info.index('-f')+1:page_info.index('-l')+2] == [str(page), '-l', str(page)]
        render = calls_seen[2 + (page - 1) * 3]
        assert render[render.index('-f')+1:render.index('-l')+2] == [str(page), '-l', str(page)]


def test_ocr_raster_bytes_include_input_output_and_headroom_budget(tmp_path):
    pdfinfo = executable(tmp_path, "pdfinfo-budget", "print('Pages: 1'); print('Page size: 72 x 72 pts')")
    renderer = executable(tmp_path, "render-budget", """
import sys
open(sys.argv[-1]+'-1.ppm','wb').write(b'P6\\n200 200\\n255\\n'+b'0'*120000)
""")
    pdf = tmp_path / "x.pdf"; pdf.write_bytes(b"x" * 1000)
    config = AdapterConfig(pdfinfo=pdfinfo, pdftoppm=renderer,
                           work_disk_cap=130_000, work_disk_headroom=8_000,
                           ocr_output_cap=2_000)
    with pytest.raises(ExternalToolError) as exc:
        OcrAdapter(config).extract_pdf(pdf, ["eng"])
    assert exc.value.code == "ocr_resource_limit"


def test_ocr_renderer_enospc_is_categorical_and_partial_raster_is_removed(tmp_path, monkeypatch):
    pdfinfo = executable(tmp_path, "pdfinfo-enospc", "print('Pages: 1'); print('Page size: 72 x 72 pts')")
    seen = []
    def no_space(argv, timeout, cap, prefix, **kwargs):
        if argv[0] == pdfinfo:
            return b"Pages: 1\nPage size: 72 x 72 pts\n"
        raster = Path(argv[-1] + "-1.ppm")
        raster.write_bytes(b"partial")
        seen.append(raster)
        raise OSError(28, "No space left on device")
    monkeypatch.setattr("omisa_parser.adapters._run", no_space)
    pdf = tmp_path / "x.pdf"; pdf.write_bytes(b"pdf")
    config = AdapterConfig(pdfinfo=pdfinfo, pdftoppm="render")
    with pytest.raises(ExternalToolError) as exc:
        OcrAdapter(config).extract_pdf(pdf, ["eng"])
    assert exc.value.code == "ocr_resource_limit"
    assert seen and not seen[0].exists()


@pytest.mark.parametrize("body", [
    b"P6\n199 200\n255\n" + b"0" * (199 * 200 * 3),
    b"P6\n200 200\n255\n" + b"0" * (200 * 200 * 3 - 1),
    b"P6\n200 200\n255\n" + b"0" * (200 * 200 * 3 + 1),
    b"P3\n200 200\n255\n0 0 0\n",
])
def test_ocr_rejects_mismatched_truncated_oversized_or_short_ascii_raster(tmp_path, body):
    image = tmp_path / "page.ppm"; image.write_bytes(body)
    with pytest.raises(ExternalToolError) as exc:
        OcrAdapter(AdapterConfig())._preflight_image(image, 200, 200)
    assert exc.value.code == "ocr_image_invalid"


def test_ocr_accepts_exact_p6_and_p3_rasters(tmp_path):
    p6 = tmp_path / "p6.ppm"; p6.write_bytes(b"P6\n2 1\n255\n" + bytes(range(6)))
    p3 = tmp_path / "p3.ppm"; p3.write_bytes(b"P3\n2 1\n255\n0 1 2 253 254 255\n")
    adapter = OcrAdapter(AdapterConfig())
    adapter._preflight_image(p6, 2, 1)
    adapter._preflight_image(p3, 2, 1)


def test_adapter_timeout_and_output_are_categorical(tmp_path):
    slow = executable(tmp_path, "slow", "import time; time.sleep(2)")
    cfg = AdapterConfig(pdfinfo=slow, preflight_timeout=0.05)
    with pytest.raises(ExternalToolError) as e:
        OcrAdapter(cfg).extract_pdf(tmp_path / "x", ["en"])
    assert e.value.code == "ocr_timeout"
    noisy = executable(tmp_path, "noisy", "print('x'*10000)")
    cfg = AdapterConfig(pdfinfo=noisy, preflight_output_cap=100)
    with pytest.raises(ExternalToolError) as e:
        OcrAdapter(cfg).extract_pdf(tmp_path / "x", ["en"])
    assert e.value.code == "ocr_output_limit"


def test_tika_one_shot_exact_java_contract(tmp_path, monkeypatch):
    calls = tmp_path / "calls"
    java = executable(tmp_path, "java", """
import json,os,sys
open(os.environ['CALLS'],'a').write(json.dumps(sys.argv)+'\\n')
print('legacy text')
""")
    monkeypatch.setenv("CALLS", str(calls))
    jar = tmp_path / "tika-app-3.3.2.jar"; jar.write_bytes(b"jar")
    config = Path(__file__).resolve().parents[1] / "packaging/tika-config.xml"
    import hashlib
    adapter = TikaAdapter(AdapterConfig(java=java, tika_jar=str(jar), tika_config=str(config), tika_sha256=hashlib.sha256(b"jar").hexdigest()))
    assert adapter.extract(tmp_path / "old.doc") == "legacy text\n"
    assert read_calls(calls)[0] == [java, "-Xint", "-Xmx256m", "-Djava.awt.headless=true", "-jar", str(jar), f"--config={config}", "--text", str(tmp_path / "old.doc")]


def test_tika_refuses_unpinned_or_wrong_jar(tmp_path):
    jar = tmp_path / "tika.jar"; jar.write_bytes(b"wrong")
    with pytest.raises(ExternalToolError) as e:
        TikaAdapter(AdapterConfig(tika_jar=str(jar), tika_sha256="0"*64)).extract(tmp_path / "x.doc")
    assert e.value.code == "tika_integrity"


def test_tika_config_explicitly_disables_ocr_and_recursive_parsing():
    import xml.etree.ElementTree as ET
    config = Path(__file__).resolve().parents[1] / "packaging/tika-config.xml"
    root = ET.parse(config).getroot()
    excluded = {node.attrib.get("class") for node in root.findall(".//parser-exclude")}
    assert "org.apache.tika.parser.ocr.TesseractOCRParser" in excluded
    assert "org.apache.tika.parser.pkg.PackageParser" in excluded
    assert "org.apache.tika.parser.microsoft.MSOwnerFileParser" in excluded
    loader = root.find("./service-loader")
    assert loader.attrib["initializableProblemHandler"] == "THROW"


def test_tika_rejects_config_without_provable_inert_legacy_policy(tmp_path):
    jar = tmp_path / "tika.jar"; jar.write_bytes(b"jar")
    config = tmp_path / "unsafe.xml"; config.write_text("<properties/>")
    import hashlib
    adapter = TikaAdapter(AdapterConfig(tika_jar=str(jar), tika_config=str(config),
                                        tika_sha256=hashlib.sha256(b"jar").hexdigest()))
    with pytest.raises(ExternalToolError) as exc:
        adapter.extract(tmp_path / "old.doc")
    assert exc.value.code == "tika_config_invalid"


def test_legacy_ole_is_detected_and_uses_tika(tmp_path):
    class FakeTika:
        def extract(self, path): return "old office text"
    old = tmp_path / "renamed.bin"
    old.write_bytes(bytes.fromhex("D0CF11E0A1B11AE1") + b"0"*512)
    records = parse_document(old, "d"*32, {"ocr":"off"}, tika_adapter=FakeTika())
    assert records[0]["document"]["detected_format"] == "ole"
    assert "old office text" in json.dumps(records)


def test_libreoffice_exact_fixed_filter_and_disposable_profile(tmp_path, monkeypatch):
    calls = tmp_path / "calls"
    lo = executable(tmp_path, "soffice", """
import json,os,sys
open(os.environ['CALLS'],'a').write(json.dumps(sys.argv)+'\\n')
open(os.path.join(sys.argv[-2], 'old.docx'),'wb').write(b'converted')
""")
    monkeypatch.setenv("CALLS", str(calls))
    source = tmp_path / "old.doc"; source.write_bytes(b"old")
    adapter = LibreOfficeAdapter(AdapterConfig(libreoffice=lo))
    result = adapter.convert(source, "docx")
    argv = read_calls(calls)[0]
    assert argv[0] == lo
    assert argv[1].startswith("-env:UserInstallation=file://")
    assert argv[2:8] == ["--headless", "--nologo", "--nodefault", "--nolockcheck", "--norestore", "--convert-to"]
    assert argv[8] == "docx:Office Open XML Text"
    assert result.read_bytes() == b"converted"
    adapter.cleanup(result)
