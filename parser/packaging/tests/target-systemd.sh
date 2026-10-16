#!/bin/sh
# Run as root only on an Ubuntu 24.04/systemd-255 staging VM, never production.
set -eu
test "$(id -u)" = 0
test "${OMISA_STAGING_CONFIRM:-}" = yes
: "${OMISA_GATEWAY_USER:?set the rendered socket owner used for this staging probe}"
systemd --version | grep -q '^systemd 255'
systemd-analyze verify \
  /usr/lib/systemd/system/omisa-parser.socket \
  /usr/lib/systemd/system/omisa-parser@.service \
  /usr/lib/systemd/system/omisa-parser.slice
systemctl daemon-reload
systemctl start omisa-parser.socket
systemctl is-active --quiet omisa-parser.socket
for request in 11111111111111111111111111111111 22222222222222222222222222222222; do
  runuser -u "$OMISA_GATEWAY_USER" -- /usr/lib/omisa-parser/tests/probe-client.py \
    /run/omisa-parser/parser.sock "$request"
done
test "$(journalctl -u 'omisa-parser@*.service' --since '-1 minute' --grep='Started Omisa parser broker connection' -o cat | wc -l)" -ge 2
/usr/lib/omisa-parser/tests/probe-bwrap.sh /usr/lib/omisa-parser/policy
/usr/lib/omisa-parser/tests/tika-canary.sh
