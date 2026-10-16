#!/bin/sh
# Online build-time assembly; the resulting runtime performs no downloads.
# Produces a COMPLETE minimal rootfs (base system + pinned packages), not just
# the newly downloaded debs, so the sandbox can actually exec /usr/bin/python3
# and resolve its ELF interpreter and shared libraries.
set -eux
export DEBIAN_FRONTEND=noninteractive
export SOURCE_DATE_EPOCH=0
LOCK=/src/packaging/rootfs/ubuntu-noble-amd64.lock
apt-get update
apt-get install -y --no-install-recommends python3-venv curl ca-certificates

packages='bubblewrap python3 python3-venv poppler-utils tesseract-ocr tesseract-ocr-eng tesseract-ocr-rus openjdk-21-jre-headless libreoffice-core libreoffice-writer libreoffice-calc libreoffice-impress fonts-dejavu-core fonts-liberation fonts-noto-core ca-certificates'
# Enforce every explicitly locked top-level package version.
locked=''
for package in $packages; do
  version=$(sed -n "s/^$package=//p" "$LOCK")
  if test -n "$version"; then locked="$locked $package=$version"; else locked="$locked $package"; fi
done
# Real install (not --download-only) so the container root becomes a complete
# system and package maintainer scripts (ldconfig, etc.) run.
apt-get install -y --no-install-recommends $locked

# Record the .deb files that this build fetched, best-effort (packages already
# present in the base image have no cached .deb).
mkdir -p /build/debs /out/rootfs /out/manifests
cp /var/cache/apt/archives/*.deb /build/debs/ 2>/dev/null || true
set -- /build/debs/*.deb
if [ -e "$1" ]; then
  sha256sum /build/debs/*.deb | sed 's#/build/debs/##' | sort -k2 > /out/manifests/debs.sha256
else
  : > /out/manifests/debs.sha256
fi

# Copy the complete container root, excluding dynamic/mount/build dirs.
tar --exclude='./proc' --exclude='./sys' --exclude='./dev' --exclude='./run' \
    --exclude='./tmp' --exclude='./var' --exclude='./root' --exclude='./home' \
    --exclude='./build' --exclude='./out' --exclude='./src' --exclude='./output' \
    --exclude='./etc/apt' --exclude='./var/lib/apt' --exclude='./var/lib/dpkg' \
    --exclude='./var/cache/apt' \
    -C / -cf - . | tar -C /out/rootfs -xf -

# Empty mountpoint dirs for the bwrap namespace.
mkdir -p /out/rootfs/app /out/rootfs/input /out/rootfs/output \
         /out/rootfs/tmp /out/rootfs/work \
         /out/rootfs/proc /out/rootfs/sys /out/rootfs/dev /out/rootfs/run \
         /out/rootfs/var /out/rootfs/root /out/rootfs/home

# Application code, config, and pinned Tika.
cp -a /src/worker.py /src/omisa_parser /out/rootfs/app/
cp -a /src/packaging/tika-config.xml /out/rootfs/app/
cp -a /src/packaging/tika-app-3.3.2.sha256 /out/rootfs/app/

# update-alternatives is not run in a bare root; create the standard java
# symlink so AdapterConfig's /usr/bin/java default resolves.
JAVA_BIN=/usr/lib/jvm/java-21-openjdk-amd64/bin/java
test -x "$JAVA_BIN"
ln -sf "$JAVA_BIN" /out/rootfs/usr/bin/java

# Build the Python wheelhouse and install into the sandbox /app/vendor.
python3 -m venv /build/venv
/build/venv/bin/pip wheel --wheel-dir /build/wheelhouse -r /src/requirements.lock
sha256sum /build/wheelhouse/* | sed 's#/build/wheelhouse/##' | sort -k2 > /out/manifests/wheels.sha256
python3 /src/packaging/rootfs/gen-hashed-reqs.py /build/wheelhouse /build/requirements-hashed.txt
/build/venv/bin/pip install --no-index --find-links=/build/wheelhouse --require-hashes \
  -r /build/requirements-hashed.txt --target /out/rootfs/app/vendor

# Tika fetched only at build time, checksum-pinned, placed in immutable app.
curl --fail --location --proto '=https' --tlsv1.2 \
  -o /out/rootfs/app/tika-app-3.3.2.jar \
  https://repo1.maven.org/maven2/org/apache/tika/tika-app/3.3.2/tika-app-3.3.2.jar
expected=$(sed -n 's/^TIKA_APP_3_3_2_SHA256=\([0-9a-f]\{64\}\)$/\1/p' /src/packaging/tika-app-3.3.2.sha256)
test "$(printf %s "$expected" | wc -c)" -eq 64
actual=$(sha256sum /out/rootfs/app/tika-app-3.3.2.jar | cut -d' ' -f1)
test "$actual" = "$expected"

# Manifests: package list, regular-file hashes, traineddata/fonts inventories, SBOM.
dpkg-query -W -f='${binary:Package}\t${Version}\t${Architecture}\n' | sort > /out/manifests/packages.tsv
find /out/rootfs -xdev -type f -print0 | sort -z | xargs -0 sha256sum | sed 's#/out/##' > /out/manifests/rootfs.sha256
find /out/rootfs/usr/share/tesseract-ocr -type f -print0 | sort -z | xargs -0 sha256sum | sed 's#/out/##' > /out/manifests/traineddata.sha256
find /out/rootfs/usr/share/fonts -type f -print0 | sort -z | xargs -0 sha256sum | sed 's#/out/##' > /out/manifests/fonts.sha256
python3 /src/packaging/rootfs/spdx.py /out/manifests/packages.tsv /out/manifests/debs.sha256 > /out/manifests/sbom.spdx.json
printf '%s\n' 'ubuntu@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517' > /out/manifests/build-image.txt
