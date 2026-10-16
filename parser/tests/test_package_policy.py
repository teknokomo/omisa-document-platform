import os
import hashlib
import stat
import subprocess
import sys
import socket as socket_module
from types import SimpleNamespace
from pathlib import Path

from omisa_parser.service import BwrapLauncher

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "packaging"


def test_bwrap_command_has_namespace_minimal_mount_and_no_shell(tmp_path):
    command = BwrapLauncher().command(tmp_path / "input", tmp_path / "result.jsonl", {
        "request_id": "4" * 32, "options": {"ocr": "off"}
    })
    assert command[0] == "/usr/bin/bwrap"
    assert "--unshare-all" in command and "--die-with-parent" in command and "--new-session" in command
    assert ["--ro-bind", "/usr/lib/omisa-parser/rootfs/usr", "/usr"] == command[command.index("/usr/lib/omisa-parser/rootfs/usr")-1:command.index("/usr/lib/omisa-parser/rootfs/usr")+2]
    assert ["--ro-bind", "/usr/lib/omisa-parser/rootfs/etc", "/etc"] == command[command.index("/usr/lib/omisa-parser/rootfs/etc")-1:command.index("/usr/lib/omisa-parser/rootfs/etc")+2]
    assert ["--ro-bind", "/usr/lib/omisa-parser/rootfs/app", "/app"] == command[command.index("/usr/lib/omisa-parser/rootfs/app")-1:command.index("/usr/lib/omisa-parser/rootfs/app")+2]
    input_index = command.index(str(tmp_path / "input"))
    assert ["--ro-bind", str(tmp_path / "input"), "/input/document"] == command[input_index-1:input_index+2]
    assert "sh" not in command and "bash" not in command
    # Empty synthetic mountpoints may exist, but no host /home or /run is bound.
    for host_path in ("/home", "/run"):
        assert not any(command[i] in {"--bind", "--ro-bind"} and command[i + 1] == host_path
                       for i in range(len(command) - 2))
    assert ["--ro-bind", "/usr/lib/omisa-parser/rootfs/etc", "/etc"] in [command[i:i+3] for i in range(len(command)-2)]
    assert "--uid" not in command and "--gid" not in command
    assert ["--cap-drop", "ALL"] == command[command.index("--cap-drop"):command.index("--cap-drop")+2]


def test_bwrap_stage_comes_from_input_magic_and_ocr_selection(tmp_path):
    launcher = BwrapLauncher()
    ole = tmp_path / "renamed.bin"; ole.write_bytes(bytes.fromhex("D0CF11E0A1B11AE1") + b"x")
    pdf = tmp_path / "renamed.bin.pdf"; pdf.write_bytes(b"%PDF-1.7\n%%EOF\n")
    text = tmp_path / "old.doc"; text.write_bytes(b"plain")
    assert launcher.stage(ole, {"options": {"ocr": "off"}}) == "legacy"
    assert launcher.stage(pdf, {"options": {"ocr": "force"}}) == "ocr"
    assert launcher.stage(pdf, {"options": {"ocr": "off", "legacy": True}}) == "native"
    assert launcher.stage(text, {"options": {"ocr": "force", "legacy": True}}) == "native"


def test_bwrap_opens_validated_policy_fd_and_passes_it(monkeypatch, tmp_path):
    policy = tmp_path / "policy"; policy.mkdir()
    native = policy / "native.bpf"; native.write_bytes(b"filter"); native.chmod(0o600)
    source = tmp_path / "input"; source.write_bytes(b"plain")
    captured = {}
    real_fstat = os.fstat
    def root_fstat(fd):
        value = real_fstat(fd)
        return SimpleNamespace(st_mode=value.st_mode, st_uid=os.getuid())
    def fake_run(argv, **kwargs):
        captured.update(argv=argv, kwargs=kwargs)
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr("omisa_parser.service.os.fstat", root_fstat)
    monkeypatch.setattr("omisa_parser.service.run_in_process_group", fake_run)
    BwrapLauncher(policy_root=policy).run(source, tmp_path / "out/result.jsonl",
                                           {"request_id":"4"*32,"options":{"ocr":"off"}}, 1)
    fd = captured["kwargs"]["pass_fds"][0]
    assert captured["argv"][captured["argv"].index("--seccomp")+1] == str(fd)
    assert captured["kwargs"]["close_fds"] is True


def test_bwrap_rejects_nonregular_nonroot_or_writable_policy(monkeypatch, tmp_path):
    import pytest
    from omisa_parser.protocol import ProtocolError
    policy = tmp_path / "policy"; policy.mkdir()
    (policy / "native.bpf").write_bytes(b"filter")
    source = tmp_path / "input"; source.write_bytes(b"plain")
    launcher = BwrapLauncher(policy_root=policy)
    for mode, uid in [(stat.S_IFDIR | 0o755, 0), (stat.S_IFREG | 0o644, 123),
                      (stat.S_IFREG | 0o666, 0)]:
        monkeypatch.setattr("omisa_parser.service.os.fstat",
                            lambda fd, m=mode, u=uid: SimpleNamespace(st_mode=m, st_uid=u))
        with pytest.raises(ProtocolError):
            launcher.run(source, tmp_path / "out/result.jsonl",
                         {"request_id":"4"*32,"options":{"ocr":"off"}}, 1)


def test_systemd_package_declares_socket_job_slice_and_hardening():
    socket = (PKG / "systemd/omisa-parser.socket").read_text()
    service = (PKG / "systemd/omisa-parser@.service").read_text()
    slice_unit = (PKG / "systemd/omisa-parser.slice").read_text()
    assert all(x in socket for x in ["Accept=yes", "SocketMode=0600", "MaxConnections=1", "Backlog=4"])
    required = [
        "DynamicUser=yes", "StandardInput=socket", "PrivateNetwork=yes", "ProtectSystem=strict",
        "ProtectHome=yes", "NoNewPrivileges=yes", "RestrictAddressFamilies=AF_UNIX",
        "MemoryMax=1G", "MemorySwapMax=0", "TasksMax=32", "RuntimeMaxSec=95s",
        "ExecStart=/usr/lib/omisa-parser/bin/omisa-parser-broker",
        "TemporaryFileSystem=/run/omisa-parser-jobs:rw,nosuid,nodev,noexec,size=256M,nr_inodes=4096",
    ]
    assert all(x in service for x in required)
    assert all(x in slice_unit for x in ["MemoryMax=1280M", "MemorySwapMax=0", "TasksMax=40", "CPUQuota=150%"])
    assert "ListenStream=/run/omisa-parser/parser.sock" in socket
    assert "TemporaryFileSystem=/work:rw,nosuid,nodev,noexec,size=224M" in service


def test_tmpfiles_socket_directory_is_traversable_by_gateway():
    rule = (PKG / "tmpfiles/omisa-parser.conf").read_text()
    assert "d /run/omisa-parser 0711 root root -" in rule


def test_seccomp_policy_is_explicitly_not_claimed_enforced_until_compiled():
    policy = (PKG / "seccomp-denylist.json").read_text()
    assert '"status": "source-policy-not-compiled"' in policy
    assert all(name in policy for name in ["connect", "mount", "unshare", "ptrace", "bpf", "io_uring_setup"])


def test_install_script_is_staging_root_parameterized_and_no_production_default():
    script = (PKG / "install-staging.sh").read_text()
    assert "DESTDIR" in script and "install -D" in script
    assert "systemctl enable" not in script and "systemctl start" not in script
    assert "probe-bwrap.sh" in script and "tika-canary.sh" in script


def test_target_probe_has_real_authenticated_requests_not_placeholder_comments():
    probe = (PKG / "tests/target-systemd.sh").read_text()
    assert "Site harness must" not in probe
    assert "OMISA_GATEWAY_USER" in probe
    assert "probe-client.py" in probe


def test_package_has_no_absolute_home_imports_and_installs_self_contained_runtime(tmp_path):
    for source in (ROOT / "omisa_parser").glob("*.py"):
        assert "/home/avathar" not in source.read_text()
    destination = tmp_path / "empty-root"
    artifact = tmp_path / "rootfs-artifact"
    (artifact / "rootfs/usr").mkdir(parents=True)
    (artifact / "rootfs/app").mkdir(parents=True)
    (artifact / "rootfs/usr/.artifact-sentinel").write_text("minimal test rootfs\n")
    (artifact / "manifests").mkdir()
    relative = "rootfs/usr/.artifact-sentinel"
    digest = hashlib.sha256((artifact / relative).read_bytes()).hexdigest()
    (artifact / "manifests/rootfs.sha256").write_text(f"{digest}  {relative}\n")
    env = {"DESTDIR": str(destination), "ROOTFS_ARTIFACT": str(artifact),
           "PATH": os.environ["PATH"]}
    subprocess.run([str(PKG / "install-staging.sh")], env=env, check=True)
    app = destination / "usr/lib/omisa-parser/app"
    assert (app / "omisa_parser/schemas/document-jsonl-record-v1.schema.json").is_file()
    assert (app / "omisa_parser/schemas/document-parse-request-v1.schema.json").is_file()
    assert (app / "worker.py").is_file()
    subprocess.run([sys.executable, "-I", "-c",
                    "import sys;sys.path.insert(0,sys.argv[1]);"
                    "import omisa_parser.protocol,omisa_parser.broker,omisa_parser.api",
                    str(app)], cwd=tmp_path, env={"PATH": os.environ["PATH"]}, check=True)


def test_install_script_uses_authoritative_schema_names_and_installs_parser_sources():
    script = (PKG / "install-staging.sh").read_text()
    launcher = (PKG / "omisa-parser-broker").read_text()
    assert "omisa-document-jsonl" not in script
    assert "omisa-document-parse-request" not in script
    assert 'cp -a "$SRC/omisa_parser"' in script
    assert (ROOT / "omisa_parser/schemas/document-jsonl-record-v1.schema.json").is_file()
    assert (ROOT / "omisa_parser/schemas/document-parse-request-v1.schema.json").is_file()
    assert "PYTHONPATH=/usr/lib/omisa-parser/app" in launcher
    assert "/opt/omisa-venv/bin/python3" in launcher


def test_busy_error_code_is_preserved_and_retryable():
    from omisa_parser.service import BrokerService
    error = BrokerService._error("0" * 32, "busy")
    assert error["code"] == "busy" and error["retryable"] is True


def test_release_layout_auth_tmpfs_and_wx_policy_are_coherent():
    service = (PKG / "systemd/omisa-parser@.service").read_text()
    install = (PKG / "install-staging.sh").read_text()
    probe = (PKG / "tests/probe-client.py").read_text()
    command = BwrapLauncher().command(Path("in"), Path("out/result.jsonl"), {"request_id":"4"*32,"options":{"ocr":"off"}})
    assert command[command.index("PYTHONPATH") + 1] == "/app:/app/vendor"
    assert "MemoryDenyWriteExecute=yes" in service
    assert "LoadCredential=" not in service and "--credential=" not in service
    assert "TemporaryFileSystem=/run/omisa-parser-jobs:" in service
    assert "--runtime-dir=/run/omisa-parser-jobs/%i" in service
    assert "ROOTFS_ARTIFACT" in install and "rootfs.sha256" in install
    assert "encode_request" in probe and '"art_v1_"' in probe


def _artifact(tmp_path, files):
    artifact = tmp_path / "artifact"
    (artifact / "rootfs/usr").mkdir(parents=True)
    (artifact / "rootfs/app").mkdir(parents=True)
    (artifact / "manifests").mkdir()
    lines = []
    for relative, content in files.items():
        target = artifact / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        lines.append(f"{hashlib.sha256(content).hexdigest()}  {relative}\n")
    (artifact / "manifests/rootfs.sha256").write_text("".join(sorted(lines)))
    return artifact


def _verify(artifact, destination):
    return subprocess.run(
        [sys.executable, str(PKG / "verify-rootfs.py"), str(artifact), str(destination)],
        text=True, capture_output=True,
    )


def test_rootfs_verifier_copies_exact_manifest_with_sanitized_metadata(tmp_path):
    artifact = _artifact(tmp_path, {
        "rootfs/usr/bin/tool": b"tool\n",
        "rootfs/app/module.py": b"answer = 42\n",
    })
    os.chmod(artifact / "rootfs/usr/bin/tool", 0o751)
    os.chmod(artifact / "rootfs/app/module.py", 0o666)
    destination = tmp_path / "installed"
    result = _verify(artifact, destination)
    assert result.returncode == 0, result.stderr
    assert (destination / "usr/bin/tool").read_bytes() == b"tool\n"
    assert stat.S_IMODE((destination / "usr/bin/tool").stat().st_mode) == 0o755
    assert stat.S_IMODE((destination / "app/module.py").stat().st_mode) == 0o644


def test_rootfs_verifier_rejects_unmanifested_file(tmp_path):
    artifact = _artifact(tmp_path, {"rootfs/app/good": b"good"})
    (artifact / "rootfs/app/extra").write_bytes(b"unchecked")
    result = _verify(artifact, tmp_path / "installed")
    assert result.returncode != 0 and "coverage" in result.stderr


def test_rootfs_verifier_rejects_manifest_escape(tmp_path):
    artifact = _artifact(tmp_path, {"rootfs/app/good": b"good"})
    digest = hashlib.sha256(b"outside").hexdigest()
    (artifact / "outside").write_bytes(b"outside")
    (artifact / "manifests/rootfs.sha256").write_text(f"{digest}  rootfs/../outside\n")
    result = _verify(artifact, tmp_path / "installed")
    assert result.returncode != 0 and "canonical" in result.stderr


def test_rootfs_verifier_rejects_special_files_but_allows_symlinks(tmp_path):
    def make_socket(path, artifact):
        sock = socket_module.socket(socket_module.AF_UNIX)
        try:
            sock.bind(str(path))
        finally:
            sock.close()
    # FIFO and socket are rejected as unsafe special files.
    for name, make in (("fifo", lambda p, a: os.mkfifo(p)), ("socket", make_socket)):
        case = tmp_path / name
        case.mkdir()
        artifact = _artifact(case, {"rootfs/app/good": b"good"})
        make(artifact / "rootfs/app/bad", artifact)
        result = _verify(artifact, case / "installed")
        assert result.returncode != 0 and "entry type" in result.stderr, (name, result.stderr)
    # A relative symlink is structural and is re-created (never followed) in the
    # immutable read-only rootfs.
    case = tmp_path / "symlink"
    case.mkdir()
    artifact = _artifact(case, {"rootfs/app/good": b"good"})
    (artifact / "rootfs/app/bad").symlink_to("good")
    result = _verify(artifact, case / "installed")
    assert result.returncode == 0, result.stderr
    assert (case / "installed/app/bad").is_symlink()
    assert (case / "installed/app/bad").read_bytes() == b"good"


def test_rootfs_build_and_canary_use_strict_assignment_digest_and_rootfs_app_paths():
    build = (PKG / "rootfs/in-container.sh").read_text()
    canary = (PKG / "tests/tika-canary.sh").read_text()
    assert "sha256sum -c /src/packaging/tika-app-3.3.2.sha256" not in build
    assert "TIKA_APP_3_3_2_SHA256=" in build and "sha256sum" in build
    assert "JAR=$ROOT/app/tika-app-3.3.2.jar" in canary
    assert "MANIFEST=$ROOT/app/tika-app-3.3.2.sha256" in canary
    assert "CONFIG=$ROOT/app/tika-config.xml" in canary
    assert "-Xint" in canary


def test_java_is_interpreted_under_memory_deny_write_execute():
    adapter = (ROOT / "omisa_parser/adapters.py").read_text()
    service = (PKG / "systemd/omisa-parser@.service").read_text()
    assert "MemoryDenyWriteExecute=yes" in service
    assert '"-Xint"' in adapter


def test_rootfs_assembly_uses_container_cleanup_and_returns_output_ownership():
    script = (PKG / "rootfs/assemble.sh").read_text()
    assert "rm -rf \"$OUT\"" not in script
    assert "OUTPUT_UID" in script and "OUTPUT_GID" in script
    assert "chown" in script
    assert "set -eu" in script
    container = (PKG / "rootfs/in-container.sh").read_text()
    assert "apt-get install -y --no-install-recommends python3-venv curl" in container
    assert "SOURCE_DATE_EPOCH=0" in container
