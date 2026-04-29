# tools

Out-of-tree binaries and scripts that support development, validation, and
parity testing of `go-stormlib`. None of these packages are imported by the
library itself.

## Layout

```
tools/
├── parity/             Go test suites that compare go-stormlib behavior
│                       against a configurable parity command (Go or C-backed).
│                       See ./parity/README.md.
├── paritycmd/          stormlib-parity: in-repo Go implementation of the
│                       parity contract. See ./paritycmd/README.md.
└── stormlib-parity-c/  stormlib-parity-c: native StormLib-backed binary that
                        implements the same parity contract. See
                        ./stormlib-parity-c/README.md.
```

## Build entry points

The repository [Taskfile](../Taskfile.yml) wraps everything:

| Task                            | Result                                                 |
| ------------------------------- | ------------------------------------------------------ |
| `task parity:build`             | builds `bin/stormlib-parity` (Go).                     |
| `task cparity:build`            | builds `build/stormlib-parity-c` (native, with fallback to a Go copy when the native target isn't available locally). |
| `task parity:structured`        | runs the structured parity suite and produces JSON reports under `parity-reports/`. |
| `task parity:strict-evidence`   | runs the strict subset and writes evidence artifacts.  |
| `task parity:c-backed`          | runs the strict suite twice (Go-backed and C-backed) and produces a behavioral-drift diff. |
| `task parity:c-backed-drift-check` | fails if any prior diff JSON contains `has_behavioral_drift: true`. |

## Parity contract version

Both parity binaries declare and report a contract version
(`v0.1.0-contract1` at time of writing). Drift in the contract requires
matching changes in `tools/parity` and both implementations.
