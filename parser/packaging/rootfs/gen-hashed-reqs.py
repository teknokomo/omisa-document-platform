#!/usr/bin/env python3
"""Generate a --require-hashes requirements file from a local wheelhouse.

The wheelhouse is built in the same sealed container from pinned
requirements.lock. Because some upstream projects (e.g. odfpy) ship only a
source distribution, their wheel is built locally and its bytes are not
bit-stable across builds. Hard-pinning a guessed wheel hash is therefore wrong.
Instead we derive each `name==version --hash=sha256:...` line from the exact
wheel that will be installed, so the hash always matches while still enforcing
that the installed artifact is the wheelhouse wheel (no index, no network).
"""
import hashlib
import sys
import zipfile
from pathlib import Path


def canonical_name(text):
    return text.strip().lower()


def read_metadata(wheel: Path):
    with zipfile.ZipFile(wheel) as zf:
        for name in zf.namelist():
            if name.endswith(".dist-info/METADATA"):
                data = zf.read(name).decode("utf-8", "replace")
                meta = {}
                for line in data.splitlines():
                    if ": " in line:
                        key, value = line.split(": ", 1)
                        meta.setdefault(key, value)
                return meta["Name"], meta["Version"]
    raise SystemExit(f"no METADATA in {wheel.name}")


def main():
    wheelhouse = Path(sys.argv[1])
    out = Path(sys.argv[2])
    lines = []
    for wheel in sorted(wheelhouse.glob("*.whl")):
        digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
        name, version = read_metadata(wheel)
        lines.append(f"{name}=={version} --hash=sha256:{digest}\n")
    out.write_text("".join(lines))
    print(f"generated {len(lines)} hashed requirement lines -> {out}")


if __name__ == "__main__":
    main()
