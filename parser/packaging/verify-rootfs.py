#!/usr/bin/env python3
"""Verify an assembled rootfs and copy its authenticated content.

The manifest covers regular files only (sha256 of each). Symlinks and empty
directories are structural and are re-created (never followed); a symlink can
only alias an already-hash-verified regular file inside the tree, or dangle,
which is harmless in the read-only sandbox. Special files (FIFO/socket/device)
are rejected outright.
"""
import hashlib
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import sys


def fail(message):
    raise ValueError(message)


def parse_manifest(path):
    entries = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        fail(f"manifest unreadable: {exc}")
    for number, line in enumerate(lines, 1):
        if len(line) < 67 or line[64:66] not in ("  ", " *"):
            fail(f"manifest line {number} is malformed")
        digest, name = line[:64], line[66:]
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            fail(f"manifest line {number} has invalid digest")
        pure = PurePosixPath(name)
        if (not name.startswith("rootfs/") or pure.is_absolute() or ".." in pure.parts
                or "." in pure.parts or str(pure) != name):
            fail(f"manifest path is not canonical rootfs descendant: {name!r}")
        if name in entries:
            fail(f"duplicate manifest path: {name}")
        entries[name] = digest
    if not entries:
        fail("manifest is empty")
    return entries


def classify(artifact, root):
    """Return (regular_files: dict[relpath, Path], symlinks: dict[relpath, target])."""
    regular = {}
    symlinks = {}
    for directory, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        for name in dirnames + filenames:
            path = Path(directory) / name
            mode = path.lstat().st_mode
            relative = path.relative_to(artifact).as_posix()
            if stat.S_ISDIR(mode):
                continue
            if stat.S_ISREG(mode):
                regular[relative] = path
            elif stat.S_ISLNK(mode):
                symlinks[relative] = os.readlink(path)
            else:
                fail(f"unsupported entry type: {relative}")
    return regular, symlinks


def verify_and_copy(artifact, destination):
    artifact = artifact.resolve(strict=True)
    entries = parse_manifest(artifact / "manifests/rootfs.sha256")
    root = artifact / "rootfs"
    regular, symlinks = classify(artifact, root)

    if set(entries) != set(regular):
        missing = sorted(set(regular) - set(entries))
        extra = sorted(set(entries) - set(regular))
        fail(f"manifest coverage mismatch: unlisted={missing!r} missing={extra!r}")

    for relative, expected in entries.items():
        with regular[relative].open("rb") as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
        if actual != expected:
            fail(f"checksum mismatch: {relative}")

    if destination.exists():
        shutil.rmtree(destination)

    # Re-create directories, then regular files (hash-verified, sanitized mode),
    # then symlinks (re-created, never followed).
    for relative in sorted(regular) + sorted(symlinks):
        parent = destination / PurePosixPath(relative).relative_to("rootfs").parent
        parent.mkdir(parents=True, exist_ok=True, mode=0o755)

    for relative in sorted(regular):
        source = regular[relative]
        target = destination / PurePosixPath(relative).relative_to("rootfs")
        with source.open("rb") as reader, target.open("xb") as writer:
            shutil.copyfileobj(reader, writer)
        os.chmod(target, 0o755 if source.stat().st_mode & 0o111 else 0o644)

    for relative in sorted(symlinks):
        target = destination / PurePosixPath(relative).relative_to("rootfs")
        os.symlink(symlinks[relative], target)


if __name__ == "__main__":
    try:
        if len(sys.argv) != 3:
            fail("usage: verify-rootfs.py ARTIFACT DESTINATION")
        verify_and_copy(Path(sys.argv[1]), Path(sys.argv[2]))
    except (OSError, ValueError) as exc:
        print(f"rootfs verification failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
