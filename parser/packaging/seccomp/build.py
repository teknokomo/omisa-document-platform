#!/usr/bin/env python3
"""Build cBPF files accepted by bubblewrap --seccomp FD.

Uses libseccomp's stable ABI and seccomp_export_bpf(). The output is native-arch
specific and must be built and probed on the Ubuntu 24.04/amd64 build image.
"""
import ctypes, errno, json, os, pathlib, sys

LIB = ctypes.CDLL("libseccomp.so.2", use_errno=True)
LIB.seccomp_init.argtypes = [ctypes.c_uint32]
LIB.seccomp_init.restype = ctypes.c_void_p
LIB.seccomp_release.argtypes = [ctypes.c_void_p]
LIB.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
LIB.seccomp_syscall_resolve_name.restype = ctypes.c_int
LIB.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
LIB.seccomp_rule_add.restype = ctypes.c_int
LIB.seccomp_export_bpf.argtypes = [ctypes.c_void_p, ctypes.c_int]
LIB.seccomp_export_bpf.restype = ctypes.c_int
ALLOW = 0x7FFF0000
ERRNO = 0x00050000 | errno.EPERM
BASELINE = [
    "socket", "socketpair", "connect", "bind", "listen", "accept", "accept4",
    "mount", "umount2", "pivot_root", "chroot", "unshare", "setns",
    "bpf", "perf_event_open", "ptrace", "process_vm_readv", "process_vm_writev",
    "kexec_load", "kexec_file_load", "reboot", "add_key", "request_key", "keyctl",
    "open_by_handle_at", "name_to_handle_at", "fanotify_init", "io_uring_setup",
    "io_uring_enter", "io_uring_register", "userfaultfd", "fsopen", "fsconfig",
    "fsmount", "move_mount", "open_tree", "mount_setattr", "mknod", "mknodat",
    "init_module", "finit_module", "delete_module", "swapon", "swapoff",
]
# Separate artifacts make stage selection fail closed and allow later tightening.
# These are intentionally equal until syscall traces justify stage-specific denial;
# denying fork/exec would break Poppler/Tesseract/Java/LibreOffice subprocesses.
POLICIES = {"native": BASELINE, "ocr": BASELINE, "legacy": BASELINE}

def check(rc, operation):
    if rc < 0:
        raise OSError(-rc, operation)

def build(path, syscalls):
    ctx = LIB.seccomp_init(ALLOW)
    if not ctx:
        raise RuntimeError("seccomp_init failed")
    resolved = []
    try:
        for name in sorted(set(syscalls)):
            nr = LIB.seccomp_syscall_resolve_name(name.encode())
            if nr < 0:
                raise RuntimeError(f"unknown syscall on build architecture: {name}")
            check(LIB.seccomp_rule_add(ctx, ERRNO, nr, 0), f"rule {name}")
            resolved.append({"name": name, "number": nr, "action": "ERRNO(EPERM)"})
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        fd = os.open(path, flags, 0o644)
        try:
            check(LIB.seccomp_export_bpf(ctx, fd), "seccomp_export_bpf")
        finally:
            os.close(fd)
    finally:
        LIB.seccomp_release(ctx)
    return resolved

def main():
    out = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    out.mkdir(parents=True, exist_ok=True)
    manifest = {"format": "libseccomp-export-bpf", "architecture": os.uname().machine, "policies": {}}
    for stage, calls in POLICIES.items():
        target = out / f"{stage}.bpf"
        target.unlink(missing_ok=True)
        rules = build(target, calls)
        manifest["policies"][stage] = {"file": target.name, "rules": rules}
    (out / "seccomp-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

if __name__ == "__main__":
    main()
