#!/usr/bin/env bash
# Spot-check `has_behavioral_drift` in parity-c-vs-go-diff.json files (committed baseline and/or CI downloads).
set -euo pipefail

usage() {
  cat <<'EOF'
spotcheck_c_backed_drift.sh — grep has_behavioral_drift in parity-c-vs-go-diff JSON file(s).

Usage (from golang/):
  bash ./tools/parity/scripts/spotcheck_c_backed_drift.sh [committed-json] [optional-second-json]
  make parity-c-backed-drift-check   # uses default committed testdata path

Defaults: first path is parity-reports/c_backed_evidence/parity-c-vs-go-diff.json
Fails if any file contains "has_behavioral_drift": true (grep).
With two paths: after both pass, prints whether files are byte-identical (cmp) or differ while both passed the drift gate.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
DEFAULT_JSON="${ROOT}/parity-reports/c_backed_evidence/parity-c-vs-go-diff.json"
JSON1="${1:-$DEFAULT_JSON}"
JSON2="${2:-}"

fail_drift() {
  local f="$1"
  if [[ ! -f "$f" ]]; then
    echo "spotcheck: missing file: $f" >&2
    return 1
  fi
  if grep -q '"has_behavioral_drift"[[:space:]]*:[[:space:]]*true' "$f"; then
    echo "spotcheck: FAIL — has_behavioral_drift is true in $f" >&2
    return 1
  fi
  echo "spotcheck: OK — no behavioral drift in $f"
}

fail_drift "$JSON1"
if [[ -n "$JSON2" ]]; then
  fail_drift "$JSON2"
  if cmp -s "$JSON1" "$JSON2"; then
    echo "spotcheck: committed vs second path are byte-identical"
  else
    echo "spotcheck: paths differ as expected for CI unzip vs testdata layout; both passed drift gate"
  fi
fi
