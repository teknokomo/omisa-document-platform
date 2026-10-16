from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .protocol import ProtocolError, ReplayCache, receive_request, validate_response_stream
from .processes import run_in_process_group


@dataclass(frozen=True)
class BrokerConfig:
    allowed_uid: int
    credential: bytes | None
    runtime_dir: Path
    copy_cap: int = 20 * 1024 * 1024
    timeout: float = 90


class Launcher(Protocol):
    def run(self, input_path: Path, output_path: Path, request: dict, timeout: float) -> None: ...


class LocalLauncher:
    """Integration-test launcher only. It is not a security boundary."""
    def run(self, input_path, output_path, request, timeout):
        root = Path(__file__).resolve().parents[1]
        bundled_python = root / ".venv/bin/python"
        python = bundled_python if bundled_python.is_file() else Path(sys.executable)
        command = [
            str(python), str(root / "worker.py"),
            "--input", str(input_path), "--output", str(output_path),
            "--request-id", request["request_id"], "--options-json",
            json.dumps(request["options"], separators=(",", ":")),
        ]
        completed = run_in_process_group(command, cwd=input_path.parent, env={}, stdin=subprocess.DEVNULL,
                                         stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                         timeout=timeout, close_fds=True)
        if completed.returncode:
            raise ProtocolError("parser_failed")


class BwrapLauncher:
    """Launch a worker with a validated, format-appropriate seccomp program."""
    def __init__(self, bwrap="/usr/bin/bwrap", runtime_root="/usr/lib/omisa-parser/rootfs",
                 policy_root="/usr/lib/omisa-parser/policy"):
        self.bwrap = bwrap
        self.runtime_root = runtime_root
        self.policy_root = Path(policy_root)

    @staticmethod
    def stage(input_path, request):
        # Policy selection is a trusted broker decision. Never honor an
        # unvalidated client "legacy" hint or a filename extension.
        with Path(input_path).open("rb") as stream:
            magic = stream.read(8)
        if magic == bytes.fromhex("D0CF11E0A1B11AE1"):
            return "legacy"
        if magic.startswith(b"%PDF-") and request.get("options", {}).get("ocr") in {"auto", "force"}:
            return "ocr"
        return "native"

    def command(self, input_path, output_path, request, seccomp_fd=None):
        # No shell. The packaged immutable rootfs is bound read-only as the whole
        # namespace root (its usr-merge symlinks bin/lib/lib64/sbin resolve the
        # ELF interpreter and shared libraries). Only /tmp, /work, /input, /output
        # are writable; network and all host state are unshared away.
        return [
            self.bwrap, "--die-with-parent", "--new-session", "--unshare-all", "--share-net",
            "--cap-drop", "ALL", "--clearenv", "--tmpfs", "/",
            "--dir", "/usr", "--dir", "/etc", "--dir", "/app",
            "--dir", "/input", "--dir", "/output", "--dir", "/var",
            "--dir", "/run", "--dir", "/home", "--dir", "/root",
            "--ro-bind", f"{self.runtime_root}/usr", "/usr",
            "--ro-bind", f"{self.runtime_root}/etc", "/etc",
            "--ro-bind", f"{self.runtime_root}/app", "/app",
            # Reconstruct Ubuntu's usr-merge links inside the empty root.
            "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib",
            "--symlink", "usr/lib64", "/lib64", "--symlink", "usr/sbin", "/sbin",
            "--proc", "/proc", "--dev", "/dev",
            "--perms", "0700", "--size", str(64 * 1024 * 1024), "--tmpfs", "/tmp",
            "--perms", "0700", "--size", str(224 * 1024 * 1024), "--tmpfs", "/work",
            "--ro-bind", str(input_path), "/input/document",
            "--bind", str(output_path.parent), "/output",
            "--chdir", "/work", "--setenv", "PATH", "/usr/bin:/bin",
            "--setenv", "HOME", "/work", "--setenv", "TMPDIR", "/work",
            "--setenv", "PYTHONPATH", "/app:/app/vendor", "--setenv", "LANG", "C.UTF-8",
            "--setenv", "TZ", "UTC",
            *(["--seccomp", str(seccomp_fd)] if seccomp_fd is not None else []), "--",
            "/usr/bin/python3", "/app/worker.py", "--input", "/input/document",
            "--output", "/output/result.jsonl", "--request-id", request["request_id"],
            "--options-json", json.dumps(request["options"], separators=(",", ":")),
        ]

    def run(self, input_path, output_path, request, timeout):
        policy = self.policy_root / f"{self.stage(input_path, request)}.bpf"
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(policy, flags)
        except OSError as exc:
            raise ProtocolError("parser_failed") from exc
        try:
            metadata = os.fstat(fd)
            # Production packaging guarantees these policy files are root-owned
            # and not writable by group/other. Tests may inject an equivalent
            # sealed policy owned by the test user.
            expected_uid = 0 if str(self.policy_root).startswith("/usr/lib/omisa-parser/") else os.getuid()
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != expected_uid
                    or metadata.st_mode & 0o022):
                raise ProtocolError("parser_failed")
            completed = run_in_process_group(self.command(input_path, output_path, request, fd), env={},
                                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                             stderr=subprocess.PIPE, timeout=timeout, close_fds=True,
                                             pass_fds=(fd,))
        finally:
            os.close(fd)
        if completed.returncode:
            try:
                import logging
                detail = (completed.stderr or b"")[-2048:].decode("utf-8", "replace") if isinstance(completed.stderr, bytes) else str(completed.stderr or "")[-2048:]
                logging.getLogger("omisa_parser.broker").error("sandbox worker failed rc=%s stderr=%s", completed.returncode, detail)
            except Exception:
                pass
            raise ProtocolError("parser_failed")


class BrokerService:
    def __init__(self, config: BrokerConfig, launcher: Launcher, replay_cache=None):
        self.config = config
        self.launcher = launcher
        self.replay_cache = replay_cache or ReplayCache()

    @staticmethod
    def _error(request_id, code):
        if code not in {"invalid_request", "unauthorized", "artifact_changed", "input_too_large", "timeout", "busy", "parser_failed", "output_limit", "resource_limit"}:
            code = "parser_failed"
        return {"schema":"omisa.document/1", "type":"error", "request_id":request_id,
                "status":"error", "code":code, "retryable":code in {"timeout", "busy"}, "stage":"broker"}

    def _copy(self, source_fd, destination, expected_size):
        copied = 0
        with os.fdopen(os.dup(source_fd), "rb", closefd=True) as source, destination.open("xb") as target:
            while True:
                chunk = source.read(min(1024 * 1024, self.config.copy_cap + 1 - copied))
                if not chunk:
                    break
                copied += len(chunk)
                if copied > self.config.copy_cap:
                    raise ProtocolError("input_too_large")
                target.write(chunk)
            target.flush()
            os.fsync(target.fileno())
        if copied != expected_size:
            raise ProtocolError("artifact_changed")

    def handle(self, connection):
        request_id = "0" * 32
        fd = None
        job = None
        try:
            request, fd = receive_request(connection, allowed_uid=self.config.allowed_uid,
                                          hmac_key=self.config.credential, replay_cache=self.replay_cache)
            request_id = request["request_id"]
            self.config.runtime_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            job = Path(tempfile.mkdtemp(prefix="job-", dir=self.config.runtime_dir))
            os.chmod(job, 0o700)
            input_dir, output_dir = job / "in", job / "out"
            input_dir.mkdir(mode=0o700); output_dir.mkdir(mode=0o700)
            input_path, output_path = input_dir / "document", output_dir / "result.jsonl"
            self._copy(fd, input_path, request["expected_size"])
            os.chmod(input_path, 0o400)
            self.launcher.run(input_path, output_path, request, self.config.timeout)
            with output_path.open("rb") as stream:
                def chunks():
                    while data := stream.read(65536):
                        yield data
                for line in validate_response_stream(chunks(), request_id=request_id):
                    connection.sendall(line)
        except subprocess.TimeoutExpired:
            connection.sendall((json.dumps(self._error(request_id, "timeout"), separators=(",", ":")) + "\n").encode())
        except ProtocolError as exc:
            try:
                import logging
                logging.getLogger("omisa_parser.broker").warning("broker protocol error code=%s request=%s", exc.code, request_id)
            except Exception:
                pass
            connection.sendall((json.dumps(self._error(request_id, exc.code), separators=(",", ":")) + "\n").encode())
        except Exception as exc:
            try:
                import logging
                logging.getLogger("omisa_parser.broker").exception("broker request failed")
            except Exception:
                pass
            connection.sendall((json.dumps(self._error(request_id, "parser_failed"), separators=(",", ":")) + "\n").encode())
        finally:
            if fd is not None:
                try: os.close(fd)
                except OSError: pass
            if job is not None:
                shutil.rmtree(job, ignore_errors=True)
            try: connection.close()
            except OSError: pass


def load_credential(path):
    data = Path(path).read_bytes()
    if not 32 <= len(data) <= 4096:
        raise SystemExit("invalid credential")
    return data


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--systemd-stdio", action="store_true", required=True)
    parser.add_argument("--allowed-uid", type=int, required=True)
    parser.add_argument("--runtime-dir", type=Path, required=True)
    parser.add_argument("--credential", type=Path)
    parser.add_argument("--local-launcher", action="store_true")
    args = parser.parse_args()
    connection = socket.socket(fileno=os.dup(0))
    launcher = LocalLauncher() if args.local_launcher else BwrapLauncher()
    credential = load_credential(args.credential) if args.credential else None
    BrokerService(BrokerConfig(args.allowed_uid, credential, args.runtime_dir), launcher).handle(connection)


if __name__ == "__main__":
    main()
