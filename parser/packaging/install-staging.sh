#!/bin/sh
set -eu
: "${DESTDIR:?set DESTDIR to a staging root; direct production install is intentionally refused}"
SRC=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
: "${ROOTFS_ARTIFACT:?set ROOTFS_ARTIFACT to an assembled rootfs directory containing manifests/rootfs.sha256}"
test -d "$ROOTFS_ARTIFACT/rootfs/usr" -a -d "$ROOTFS_ARTIFACT/rootfs/app"
install -D -m 0644 "$SRC/packaging/systemd/omisa-parser.socket" "$DESTDIR/usr/lib/systemd/system/omisa-parser.socket"
install -D -m 0644 "$SRC/packaging/systemd/omisa-parser@.service" "$DESTDIR/usr/lib/systemd/system/omisa-parser@.service"
install -D -m 0644 "$SRC/packaging/systemd/omisa-parser.slice" "$DESTDIR/usr/lib/systemd/system/omisa-parser.slice"
# Break-glass units contain deployment identity placeholders and are rendered
# only by render-target.sh; never install unresolved templates.

install -D -m 0644 "$SRC/packaging/tmpfiles/omisa-parser.conf" "$DESTDIR/usr/lib/tmpfiles.d/omisa-parser.conf"
install -D -m 0755 "$SRC/packaging/omisa-parser-broker" "$DESTDIR/usr/lib/omisa-parser/bin/omisa-parser-broker"
install -D -m 0755 "$SRC/packaging/omisa-archive-broker" "$DESTDIR/usr/lib/omisa-parser/bin/omisa-archive-broker"
install -D -m 0644 "$SRC/packaging/seccomp-denylist.json" "$DESTDIR/usr/lib/omisa-parser/policy/seccomp-denylist.json"
install -D -m 0644 "$SRC/packaging/tika-config.xml" "$DESTDIR/usr/lib/omisa-parser/tika-config.xml"
install -D -m 0644 "$SRC/packaging/tika-app-3.3.2.sha256" "$DESTDIR/usr/lib/omisa-parser/tika-app-3.3.2.sha256"
install -D -m 0644 "$SRC/packaging/rootfs-manifest.txt" "$DESTDIR/usr/lib/omisa-parser/rootfs-manifest.txt"
install -D -m 0755 "$SRC/packaging/verify-rootfs.py" "$DESTDIR/usr/lib/omisa-parser/bin/verify-rootfs.py"
for policy in native ocr legacy; do
  install -D -m 0644 "$SRC/packaging/seccomp/out/$policy.bpf" "$DESTDIR/usr/lib/omisa-parser/policy/$policy.bpf"
done
install -D -m 0644 "$SRC/packaging/seccomp/out/seccomp-manifest.json" "$DESTDIR/usr/lib/omisa-parser/policy/seccomp-manifest.json"
# Install the authoritative parser package as one coherent subtree.  The
# target-package fixture used obsolete schema basenames and omitted the Python
# sources, producing a root that could not import its own broker.
mkdir -p "$DESTDIR/usr/lib/omisa-parser/app"
cp -a "$SRC/omisa_parser" "$DESTDIR/usr/lib/omisa-parser/app/"
install -D -m 0644 "$SRC/worker.py" "$DESTDIR/usr/lib/omisa-parser/app/worker.py"
install -D -m 0755 "$SRC/packaging/omisa-document-breakglass" "$DESTDIR/usr/local/bin/omisa-document-breakglass"
install -D -m 0755 "$SRC/packaging/omisa-archive-breakglass" "$DESTDIR/usr/local/bin/omisa-archive-breakglass"
python3 "$SRC/packaging/verify-rootfs.py" "$ROOTFS_ARTIFACT" "$DESTDIR/usr/lib/omisa-parser/rootfs"
mkdir -p "$DESTDIR/usr/lib/omisa-parser/rootfs-manifests"
install -m 0644 "$ROOTFS_ARTIFACT"/manifests/* "$DESTDIR/usr/lib/omisa-parser/rootfs-manifests/"
install -D -m 0755 "$SRC/packaging/seccomp/probe-bwrap.sh" "$DESTDIR/usr/lib/omisa-parser/tests/probe-bwrap.sh"
install -D -m 0755 "$SRC/packaging/tests/tika-canary.sh" "$DESTDIR/usr/lib/omisa-parser/tests/tika-canary.sh"
install -D -m 0755 "$SRC/packaging/tests/probe-client.py" "$DESTDIR/usr/lib/omisa-parser/tests/probe-client.py"
install -D -m 0755 "$SRC/packaging/tests/target-systemd.sh" "$DESTDIR/usr/lib/omisa-parser/tests/target-systemd.sh"
