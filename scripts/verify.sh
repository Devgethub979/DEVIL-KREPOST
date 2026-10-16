#!/usr/bin/env bash
set -euo pipefail
BASE="${1:-http://127.0.0.1:8765}"
case "$BASE" in
  http://127.0.0.1:*|http://localhost:*) ;;
  *) echo 'Only local HTTP backends are supported by this verifier' >&2; exit 2 ;;
esac
curl --noproxy '*' --fail --silent --show-error --max-time 10 "$BASE/healthz"
echo
