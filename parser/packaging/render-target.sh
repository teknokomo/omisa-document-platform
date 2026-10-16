#!/bin/sh
set -eu
ROOT=${1:?usage: render-target.sh STAGING_ROOT GATEWAY_USER GATEWAY_GROUP GATEWAY_UID}
USER=${2:?}
GROUP=${3:?}
UIDNUM=${4:?}
case "$ROOT" in /tmp/*|/var/tmp/*) ;; *) echo "staging paths only" >&2; exit 64;; esac
case "$USER$GROUP$UIDNUM" in *[!A-Za-z0-9_.-]*) echo invalid >&2; exit 64;; esac
mkdir -p "$ROOT/usr/lib/systemd/system"
sed -e "s/@GATEWAY_USER@/$USER/g" -e "s/@GATEWAY_GROUP@/$GROUP/g" \
  packaging/systemd/omisa-parser.socket > "$ROOT/usr/lib/systemd/system/omisa-parser.socket"
sed -e "s/@GATEWAY_UID@/$UIDNUM/g" packaging/systemd/omisa-parser@.service \
  > "$ROOT/usr/lib/systemd/system/omisa-parser@.service"
cp packaging/systemd/omisa-parser.slice "$ROOT/usr/lib/systemd/system/"
sed -e "s/@GATEWAY_UID@/$UIDNUM/g" packaging/systemd/omisa-breakglass@.service > "$ROOT/usr/lib/systemd/system/omisa-breakglass@.service"
sed -e "s/@GATEWAY_UID@/$UIDNUM/g" packaging/systemd/omisa-archive-breakglass@.service > "$ROOT/usr/lib/systemd/system/omisa-archive-breakglass@.service"
sed -e "s/@GATEWAY_USER@/$USER/g" -e "s/@GATEWAY_GROUP@/$GROUP/g" packaging/systemd/omisa-archive-breakglass.socket > "$ROOT/usr/lib/systemd/system/omisa-archive-breakglass.socket"
sed -e "s/@GATEWAY_USER@/$USER/g" -e "s/@GATEWAY_GROUP@/$GROUP/g" packaging/systemd/omisa-archive.socket > "$ROOT/usr/lib/systemd/system/omisa-archive.socket"
sed -e "s/@GATEWAY_UID@/$UIDNUM/g" packaging/systemd/omisa-archive@.service > "$ROOT/usr/lib/systemd/system/omisa-archive@.service"
cp packaging/systemd/omisa-breakglass.socket packaging/systemd/omisa-parser-breakglass.socket packaging/systemd/omisa-parser-breakglass@.service "$ROOT/usr/lib/systemd/system/"
cp packaging/systemd/omisa-archive-breakglass-worker.socket packaging/systemd/omisa-archive-breakglass-worker@.service "$ROOT/usr/lib/systemd/system/"
