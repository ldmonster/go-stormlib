#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT_DIR"

if [[ -z "${STORMLIB_PARITY_C_CMD:-}" ]]; then
  echo "STORMLIB_PARITY_C_CMD is required" >&2
  exit 1
fi

export STORMLIB_PARITY_CMD="${STORMLIB_PARITY_C_CMD}"
export STORMLIB_PARITY_STRICT="${STORMLIB_PARITY_STRICT:-true}"

EVIDENCE_DIR="parity-reports/c_backed_evidence"
mkdir -p "$EVIDENCE_DIR"

go test ./tools/parity -run TestParityCommandCapabilityPreflight -count=1 -v | tee "$EVIDENCE_DIR/c-backed-preflight.log"

go test ./tools/parity -count=1 \
  -run 'TestLookupCollisionMatrixParity|TestLookupTieBreakAndOrderParity|TestNormalizationVariantParityFixtures|TestListfileCollisionNamingAndOrderingParity|TestLookupCollisionMatrixParity_NoMatch|TestReadReportParity_NotFound|TestReadReportParity_Unsupported' \
  -json | tee "$EVIDENCE_DIR/c-backed-structured-report.jsonl"

go run ./tools/parity/summary "$EVIDENCE_DIR/c-backed-structured-report.jsonl" > "$EVIDENCE_DIR/c-backed-structured-summary.json"

go run ./tools/parity/summary/diff \
  ./parity-reports/strict_evidence/strict-structured-summary.json \
  "$EVIDENCE_DIR/c-backed-structured-summary.json" > "$EVIDENCE_DIR/parity-c-vs-go-diff.json"

echo "C-backed strict evidence written to $EVIDENCE_DIR"
