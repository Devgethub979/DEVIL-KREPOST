#!/usr/bin/env bash
# Run on an existing DEVIL VPS only, as an administrator; preserves all other services.
set -Eeuo pipefail
SOURCE="${1:-}"
TARGET='/opt/devil-intel/dashboard.py'
SERVICE='devil-intel-dashboard'
if [[ -z "$SOURCE" || ! -f "$SOURCE" ]]; then
  echo 'Usage: sudo bash scripts/deploy.sh /path/to/reviewed/dashboard.py' >&2; exit 2
fi
if [[ $(id -u) -ne 0 ]]; then echo 'Run as root (needed for systemd and /opt)' >&2; exit 2; fi
if [[ ! -f "$TARGET" ]]; then echo "Existing installation not found: $TARGET" >&2; exit 2; fi
python3 -m py_compile "$SOURCE"
if ! grep -q "HOST = '127.0.0.1'" "$SOURCE"; then
  echo 'Refusing source without explicitly loopback-bound host' >&2; exit 3
fi
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP="${TARGET}.${STAMP}.backup"
STAGED="${TARGET}.incoming.$$"
cp -p -- "$TARGET" "$BACKUP"
install -m 0644 -- "$SOURCE" "$STAGED"
rollback() {
  local ec=$?
  trap - ERR
  echo "Deploy failed (status $ec). Reverting to $BACKUP" >&2
  if [[ -f "$BACKUP" ]]; then cp -p -- "$BACKUP" "$TARGET"; systemctl restart "$SERVICE" || true; fi
  rm -f -- "$STAGED"
  exit "$ec"
}
trap rollback ERR
mv -f -- "$STAGED" "$TARGET"
systemctl restart "$SERVICE"
# Wait for a real HTTP response and check actual loaded code version, not only systemd active.
python3 - <<'PY'
import json, time, urllib.request
for attempt in range(15):
    try:
        with urllib.request.urlopen('http://127.0.0.1:8765/healthz', timeout=2) as response:
            result=json.load(response)
        if result.get('ok') is True and result.get('version') == '3.1.0':
            print('DEVIL_DEPLOY=SUCCESS; VERSION=3.1.0')
            break
    except Exception:
        pass
    time.sleep(1)
else:
    raise SystemExit('Expected v3.1.0 health check did not succeed')
PY
systemctl is-active --quiet "$SERVICE"
trap - ERR
printf 'Backup saved: %s\n' "$BACKUP"
