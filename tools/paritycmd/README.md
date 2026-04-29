# tools/paritycmd

`stormlib-parity`: an in-repo Go implementation of the parity command
contract documented in [../parity/README.md](../parity/README.md).

It is built on top of `pkg/storm` and `internal/...` so that running the
parity suites against this binary exercises the same code paths as the
library itself. It exists so the contract can be validated even on systems
without a usable native StormLib build, and so behavioral drift between Go
and native StormLib can be measured (see
[tools/parity scripts](../parity/scripts/)).

## Build

```bash
task parity:build              # writes bin/stormlib-parity
# or
go build -o bin/stormlib-parity ./tools/paritycmd
```

A scratch-based [Dockerfile](Dockerfile) is provided for reproducible builds:

```bash
task parity:docker-build
task parity:docker-export      # extracts the binary to bin/stormlib-parity
```

## Usage

```
stormlib-parity [flags] <archive>
stormlib-parity --report-lookup <locale> <platform> <archive>
stormlib-parity --report-read   <hashA> <hashB> <locale> <platform> <archive>
stormlib-parity --version
```

Flags:

- `--force-v1`     force MPQ V1 header parsing
- `--marker <str>` synthetic listfile marker injected for parity probes
- `--report-lookup` enable structured lookup report mode
- `--report-read`   enable structured read report mode

Default mode prints `open-ok` or `open-fail`. Report modes print one JSON
object on stdout. Exit codes follow the parity contract; usage errors exit
non-zero with a message to stderr.

## Version

`ParityCmdVersion` in [root.go](root.go) is the source of truth for the
contract version. It must match the value declared by the native binary.
