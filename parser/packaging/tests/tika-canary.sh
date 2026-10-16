#!/bin/sh
# Exercise the exact pinned JAR and fail-closed config assembled in the rootfs.
set -eu
ROOT=${1:-/usr/lib/omisa-parser/rootfs}
JAR=$ROOT/app/tika-app-3.3.2.jar
MANIFEST=$ROOT/app/tika-app-3.3.2.sha256
CONFIG=$ROOT/app/tika-config.xml
expected=$(sed -n 's/^TIKA_APP_3_3_2_SHA256=//p' "$MANIFEST")
test "$(sha256sum "$JAR" | cut -d' ' -f1)" = "$expected"
input=$(mktemp); trap 'rm -f "$input"' EXIT
printf 'tika pinned canary\n' > "$input"
mkdir -p "$ROOT/tmp"
cp "$input" "$ROOT/tmp/tika-canary-input"
output=$(chroot "$ROOT" /usr/bin/env LD_LIBRARY_PATH=/usr/lib/jvm/java-21-openjdk-amd64/lib /usr/bin/java -Xint -Xmx256m -Djava.awt.headless=true -jar /app/tika-app-3.3.2.jar --config=/app/tika-config.xml --text /tmp/tika-canary-input)
rm -f "$ROOT/tmp/tika-canary-input"
test "$output" = "tika pinned canary"