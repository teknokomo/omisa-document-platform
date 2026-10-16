#!/bin/sh
set -eu
POLICY_DIR=${1:-/usr/lib/omisa-parser/policy}
BWRAP=${BWRAP:-/usr/bin/bwrap}
for stage in native ocr legacy; do
  policy="$POLICY_DIR/$stage.bpf"
  test -s "$policy"
  exec 9<"$policy"
  "$BWRAP" --unshare-user --unshare-pid --unshare-net --unshare-ipc --unshare-uts \
    --die-with-parent --new-session --cap-drop ALL --ro-bind /usr /usr --proc /proc \
    --dev /dev --tmpfs /tmp --seccomp 9 -- sh -eu -c '
      test "$(id -u)" = 0
      python3 -c "import socket; socket.socket()" >/dev/null 2>&1 && exit 90 || :
      python3 -c "import os; os.unshare(0)" >/dev/null 2>&1 && exit 91 || :
      test ! -e /home
    '
  exec 9<&-
done
