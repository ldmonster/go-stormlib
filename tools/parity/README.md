# tools/parity

Go test package that drives parity validation between the in-tree library
(`pkg/storm` + `internal/...`) and an external "parity command" implementing
a small CLI contract. The same suites can be run against the in-repo Go
parity binary or against a StormLib-backed native binary.

## What it tests

The suites under [parity_test.go](parity_test.go) and
[hetbet_parity_test.go](hetbet_parity_test.go) exercise:

- Header detection (force-V1, foreign header precedence, AVI rejection,
  user-data overlays, unknown-version fallback).
- Hash-table lookup ordering, collision handling, and tie-breaking
  (`TestLookupCollisionMatrixParity*`, `TestLookupTieBreakAndOrderParity`).
- Listfile collision/naming/ordering (`TestListfileCollisionNamingAndOrderingParity`).
- Filename normalization variants (`TestNormalizationVariantParityFixtures`).
- Read report contract (`TestReadReportParity_*`).
- HET/BET secondary-table fixture parity.
- Capability preflight against whichever parity command is configured
  (`TestParityCommandCapabilityPreflight`).

## Parity command contract

The package shells out to a binary at `${STORMLIB_PARITY_CMD}`. The binary
must implement:

- Default mode: `<cmd> [--force-v1] <archive>` &rarr; prints
  `open-ok` or `open-fail`.
- Lookup report: `<cmd> --report-lookup <locale> <platform> <archive>`
  &rarr; prints a single JSON object per fixture call.
- Read report: `<cmd> --report-read <hashA> <hashB> <locale> <platform> <archive>`
  &rarr; prints a single JSON object describing the read result.
- `--version` &rarr; prints the contract version
  (currently `v0.1.0-contract1`).

Both [tools/paritycmd](../paritycmd/README.md) (Go) and
[tools/stormlib-parity-c](../stormlib-parity-c/README.md) (native) implement
this contract.

## Environment variables

| Variable                    | Effect                                                                |
| --------------------------- | --------------------------------------------------------------------- |
| `STORMLIB_PARITY_CMD`       | Path to the parity binary. Tests that need it skip if unset.          |
| `STORMLIB_PARITY_STRICT`    | When `true`, capability preflight failures fail the test instead of skipping. Used by the strict-evidence suite. |
| `STORMLIB_PARITY_DISABLE_REPORT` | When `true`, the parity command reports report-modes as unsupported (used to assert fallback behavior). |
| `STORMLIB_PARITY_C_CMD`     | Used by the C-backed scripts to point at the native binary.            |

## Layout

```
parity/
├── parity_test.go             primary parity suite + helpers
├── hetbet_parity_test.go      HET/BET fixture parity
├── doc.go                     package doc
├── testdata/                  binary fixtures
├── scripts/
│   ├── run_c_backed_strict.sh runs strict suite against the C binary and produces evidence artifacts
│   └── spotcheck_c_backed_drift.sh fails if a diff JSON has has_behavioral_drift: true
└── summary/                   command-line tools that consume go test -json output
    ├── main.go                summary aggregator (passed/failed/skipped + reasons)
    └── diff/main.go           drift detector across two summary JSON files
```

## Running

Quick (skips C-backed comparison, uses the Go binary):

```bash
task parity:structured
```

Strict (fails if any test skips):

```bash
task parity:strict-evidence
task parity:strict-no-skips
```

Full C-backed comparison:

```bash
task cparity:build      # build native binary (or fallback)
task parity:c-backed
task parity:c-backed-drift-check
```

Reports land under [parity-reports/](../../parity-reports/).
