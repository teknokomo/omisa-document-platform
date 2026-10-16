"""Bounded, argv-only adapters for optional staging extraction tools."""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import resource
import shutil
import signal
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from .processes import run_in_process_group


class ExternalToolError(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class AdapterConfig:
    pdfinfo: str = "/usr/bin/pdfinfo"
    pdftoppm: str = "/usr/bin/pdftoppm"
    tesseract: str = "/usr/bin/tesseract"
    java: str = "/usr/bin/java"
    tika_jar: str = "/app/tika-app-3.3.2.jar"
    tika_sha256: str = ""
    tika_sha256_manifest: str = "/app/tika-app-3.3.2.sha256"
    tika_config: str = "/app/tika-config.xml"
    libreoffice: str = "/usr/bin/libreoffice"
    preflight_timeout: float = 5.0
    render_timeout: float = 30.0
    ocr_timeout: float = 30.0
    tika_timeout: float = 45.0
    libreoffice_timeout: float = 45.0
    preflight_output_cap: int = 64 * 1024
    render_output_cap: int = 256 * 1024 * 1024
    ocr_output_cap: int = 2 * 1024 * 1024
    tika_output_cap: int = 2 * 1024 * 1024
    max_ocr_pages: int = 20
    dpi: int = 200
    max_pixels_per_page: int = 40_000_000
    max_total_pixels: int = 200_000_000
    # Must equal BwrapLauncher's /work tmpfs size.
    work_disk_cap: int = 224 * 1024 * 1024
    work_disk_headroom: int = 16 * 1024 * 1024
    work_inode_cap: int = 16


def _run(argv: list[str], timeout: float, cap: int, prefix: str, *, stdout_path: Path | None = None) -> bytes:
    """Run without a shell or inherited input; bound persisted stdout before reading."""
    try:
        if stdout_path is None:
            fd, name = tempfile.mkstemp(prefix="omisa-output-")
            os.close(fd)
            output = Path(name)
            remove = True
        else:
            output = stdout_path
            remove = False
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
        if "CALLS" in os.environ: env["CALLS"] = os.environ["CALLS"]
        def output_limit():
            resource.setrlimit(resource.RLIMIT_FSIZE, (cap, cap))
        with output.open("wb") as stream:
            result = run_in_process_group(argv, stdin=subprocess.DEVNULL, stdout=stream,
                                          stderr=subprocess.DEVNULL, timeout=timeout,
                                          shell=False, close_fds=True, env=env,
                                          preexec_fn=output_limit)
        if output.stat().st_size >= cap or result.returncode == -signal.SIGXFSZ:
            raise ExternalToolError(f"{prefix}_output_limit")
        data = output.read_bytes()
        if result.returncode:
            raise ExternalToolError(f"{prefix}_failed")
        return data
    except subprocess.TimeoutExpired:
        raise ExternalToolError(f"{prefix}_timeout")
    except FileNotFoundError:
        raise ExternalToolError(f"{prefix}_unavailable")
    finally:
        if "remove" in locals() and remove:
            output.unlink(missing_ok=True)


_LANGUAGE = {"en": "eng", "eng": "eng", "ru": "rus", "rus": "rus"}


def load_tika_checksum(path: Path | str) -> str:
    """Read the single pinned assignment used by rootfs assembly."""
    try:
        assignments = [line.strip() for line in Path(path).read_text("ascii").splitlines()
                       if line.strip() and not line.lstrip().startswith("#")]
    except OSError:
        raise ExternalToolError("tika_integrity")
    if len(assignments) != 1:
        raise ExternalToolError("tika_integrity")
    match = re.fullmatch(r"TIKA_APP_3_3_2_SHA256=([a-fA-F0-9]{64})", assignments[0])
    if not match:
        raise ExternalToolError("tika_integrity")
    return match.group(1).lower()


class OcrAdapter:
    def __init__(self, config: AdapterConfig = AdapterConfig()):
        self.config = config

    def extract_pdf(self, path: Path, languages: list[str] | None = None,
                    page_range: tuple[int, int] | None = None):
        return self._extract_pdf(path, languages, page_range=page_range)

    def extract_pdf_pages(self, path: Path, languages: list[str] | None,
                          pages: list[int]):
        """OCR exactly the selected pages, preserving one document-wide budget."""
        return self._extract_pdf(path, languages, page_numbers=pages)

    def _extract_pdf(self, path: Path, languages: list[str] | None = None,
                     page_range: tuple[int, int] | None = None,
                     page_numbers: list[int] | None = None):
        languages = languages or ["eng", "rus"]
        try:
            mapped = [_LANGUAGE[x.lower()] for x in languages]
        except (KeyError, AttributeError):
            raise ExternalToolError("unsupported_ocr_language")
        mapped = list(dict.fromkeys(mapped))
        info = _run([self.config.pdfinfo, str(path)], self.config.preflight_timeout,
                    self.config.preflight_output_cap, "ocr").decode("utf-8", "replace")
        pages_match = re.search(r"(?m)^Pages:\s*(\d+)\s*$", info)
        if not pages_match:
            raise ExternalToolError("ocr_preflight_failed")
        total_pages = int(pages_match.group(1))
        first, last = page_range or (1, total_pages)
        selected = list(range(first, last + 1)) if page_numbers is None else list(page_numbers)
        if (total_pages < 1 or first < 1 or last < first or last > total_pages
                or not selected or selected != sorted(set(selected))
                or selected[0] < 1 or selected[-1] > total_pages):
            raise ExternalToolError("ocr_preflight_failed")
        if len(selected) > self.config.max_ocr_pages:
            raise ExternalToolError("ocr_page_limit")
        units = []
        total_pixels = 0
        available = (self.config.work_disk_cap - self.config.work_disk_headroom
                     - self.config.ocr_output_cap)
        if available <= 0 or self.config.work_inode_cap < 2:
            raise ExternalToolError("ocr_resource_limit")
        with tempfile.TemporaryDirectory(prefix="omisa-ocr-") as directory:
            for number in selected:
                page_info = _run([self.config.pdfinfo, "-f", str(number), "-l", str(number),
                                  str(path)], self.config.preflight_timeout,
                                 self.config.preflight_output_cap, "ocr").decode("utf-8", "replace")
                size = re.search(r"(?m)^Page(?:\s+\d+)? size:\s*([0-9.]+)\s+x\s+([0-9.]+)\s+pts", page_info)
                if not size:
                    raise ExternalToolError("ocr_preflight_failed")
                width = int(float(size.group(1)) * self.config.dpi / 72 + .999)
                height = int(float(size.group(2)) * self.config.dpi / 72 + .999)
                pixels = width * height
                total_pixels += pixels
                if pixels > self.config.max_pixels_per_page or total_pixels > self.config.max_total_pixels:
                    raise ExternalToolError("ocr_pixel_limit")
                # P6 PPM is RGB plus a small header. Reject before rendering if
                # even the declared geometry cannot fit with reserved headroom.
                if pixels * 3 + 256 > available:
                    raise ExternalToolError("ocr_resource_limit")
                prefix = str(Path(directory) / "page")
                image = Path(f"{prefix}-{number}.ppm")
                try:
                    try:
                        _run([self.config.pdftoppm, "-f", str(number), "-l", str(number), "-r",
                              str(self.config.dpi), str(path), prefix],
                             self.config.render_timeout, min(self.config.render_output_cap, available), "ocr")
                    except ExternalToolError as exc:
                        if exc.code == "ocr_output_limit":
                            raise ExternalToolError("ocr_resource_limit")
                        raise
                    if not image.is_file():
                        raise ExternalToolError("ocr_render_failed")
                    self._preflight_image(image, width, height)
                    if image.stat().st_size > available:
                        raise ExternalToolError("ocr_resource_limit")
                    text = _run([self.config.tesseract, str(image), "stdout", "-l",
                                 "+".join(mapped), "--psm", "3"],
                                self.config.ocr_timeout, self.config.ocr_output_cap,
                                "ocr").decode("utf-8", "replace")
                    units.append(("page", str(number), [("ocrtext", text)], None, number))
                except OSError as exc:
                    if exc.errno in {28, 122}:  # ENOSPC, EDQUOT
                        raise ExternalToolError("ocr_resource_limit")
                    raise
                finally:
                    image.unlink(missing_ok=True)
        return units

    def _preflight_image(self, path: Path, expected_width: int, expected_height: int):
        """Validate geometry and exact P3/P6 payload before invoking OCR."""
        try:
            data = path.read_bytes()
            tokens = []
            positions = []
            cursor = 0
            while len(tokens) < 4:
                while cursor < len(data) and data[cursor] in b" \t\r\n": cursor += 1
                if cursor < len(data) and data[cursor] == 35:
                    cursor = data.find(b"\n", cursor)
                    if cursor < 0: raise ValueError
                    continue
                start = cursor
                while cursor < len(data) and data[cursor] not in b" \t\r\n#": cursor += 1
                if start == cursor: raise ValueError
                tokens.append(data[start:cursor]); positions.append(cursor)
            magic, width_raw, height_raw, maximum = tokens
            width, height = int(width_raw), int(height_raw)
            if (magic not in {b"P3", b"P6"} or maximum != b"255" or width <= 0 or height <= 0
                    or (width, height) != (expected_width, expected_height)):
                raise ValueError
            samples = width * height * 3
            if width * height > self.config.max_pixels_per_page: raise ExternalToolError("ocr_pixel_limit")
            if magic == b"P6":
                # Netpbm requires exactly one whitespace separator before raw bytes.
                if cursor >= len(data) or data[cursor] not in b" \t\r\n": raise ValueError
                if len(data) - (cursor + 1) != samples: raise ValueError
            else:
                body = re.sub(br"#[^\r\n]*", b" ", data[cursor:])
                values = body.split()
                if len(values) != samples or any(not x.isdigit() or int(x) > 255 for x in values):
                    raise ValueError
        except ExternalToolError:
            raise
        except (OSError, ValueError, OverflowError):
            raise ExternalToolError("ocr_image_invalid")


class TikaAdapter:
    def __init__(self, config: AdapterConfig = AdapterConfig()): self.config = config

    def extract(self, path: Path) -> str:
        jar = Path(self.config.tika_jar)
        digest_expected = self.config.tika_sha256
        if not digest_expected:
            digest_expected = load_tika_checksum(self.config.tika_sha256_manifest)
        if not jar.is_file():
            raise ExternalToolError("tika_integrity")
        digest = hashlib.sha256(jar.read_bytes()).hexdigest()
        if not hmac.compare_digest(digest, digest_expected.lower()):
            raise ExternalToolError("tika_integrity")
        config = Path(self.config.tika_config)
        if not config.is_file():
            raise ExternalToolError("tika_config_missing")
        self._validate_config(config)
        argv = [self.config.java, "-Xint", "-Xmx256m", "-Djava.awt.headless=true", "-jar",
                str(jar), f"--config={config}", "--text", str(path)]
        return _run(argv, self.config.tika_timeout, self.config.tika_output_cap,
                    "tika").decode("utf-8", "replace")

    @staticmethod
    def _validate_config(config: Path) -> None:
        required = {
            "org.apache.tika.parser.ocr.TesseractOCRParser",
            "org.apache.tika.parser.pkg.PackageParser",
            "org.apache.tika.parser.microsoft.MSOwnerFileParser",
        }
        try:
            root = ET.parse(config).getroot()
            default = root.find("./parsers/parser[@class='org.apache.tika.parser.DefaultParser']")
            excluded = ({node.attrib.get("class") for node in default.findall("parser-exclude")}
                        if default is not None else set())
            loader = root.find("./service-loader")
            fetcher = root.find("./fetchers/fetcher[@class='org.apache.tika.fetcher.http.HttpFetcher']")
            if (not required <= excluded or loader is None
                    or loader.attrib.get("loadErrorHandler") != "THROW"
                    or loader.attrib.get("initializableProblemHandler") != "THROW"
                    or fetcher is None or fetcher.attrib.get("exclude") != "true"):
                raise ValueError
        except (ET.ParseError, OSError, ValueError):
            raise ExternalToolError("tika_config_invalid")


_FILTERS = {
    "docx": "docx:Office Open XML Text",
    "xlsx": "xlsx:Calc MS Excel 2007 XML",
    "pptx": "pptx:Impress MS PowerPoint 2007 XML",
}


class LibreOfficeAdapter:
    """Exceptional conversion only; caller must explicitly select a fixed filter."""
    def __init__(self, config: AdapterConfig = AdapterConfig()): self.config = config

    def convert(self, path: Path, target: str) -> Path:
        if target not in _FILTERS:
            raise ExternalToolError("libreoffice_filter_denied")
        directory = Path(tempfile.mkdtemp(prefix="omisa-lo-"))
        profile = directory / "profile"; output = directory / "output"
        profile.mkdir(); output.mkdir()
        argv = [self.config.libreoffice, f"-env:UserInstallation=file://{profile}",
                "--headless", "--nologo", "--nodefault", "--nolockcheck", "--norestore",
                "--convert-to", _FILTERS[target], "--outdir", str(output), str(path)]
        try:
            _run(argv, self.config.libreoffice_timeout, 64 * 1024, "libreoffice")
            result = output / f"{path.stem}.{target}"
            if not result.is_file(): raise ExternalToolError("libreoffice_failed")
            return result
        except Exception:
            shutil.rmtree(directory, ignore_errors=True)
            raise

    @staticmethod
    def cleanup(result: Path):
        shutil.rmtree(result.parent.parent, ignore_errors=True)
