# go-stormlib

`go-stormlib` is a Go implementation of Blizzard MPQ archive handling, with
behavior aligned to [StormLib] where practical and validated by a parity
harness against the C reference.

[StormLib]: https://github.com/ladislav-zezula/StormLib

## Status

Implemented and usable today:

- Open archives (`storm.Open`)
- List entries (`(*Archive).ListFiles`)
- Read by index / hash / name (`ReadFileByIndex`, `ReadFileByHash`, `ReadFileByName`)
- Extract files to disk (`(*Archive).ExtractFile`, MPQ scope only)
- Create empty archives and write uncompressed single-unit files
  (`Create` &rarr; `CreateFile` &rarr; `WriteFile` &rarr; `FinishFile`)
- Remove and rename files (narrow table-update slice)
- UTF-8 filename conversion helpers (`UTF8ToFileName`, `FileNameToUTF8`)

Known partial / unsupported:

- `Compact`, `SignArchive` return `ErrUnsupportedFeature`
- Patch-chain merge / read semantics
- A subset of compression combinations (unsupported codecs return typed errors)

Intentional behavior deltas vs StormLib are tracked in
`docs/compatibility.md`.

## Installation

```bash
go get github.com/ldmonster/go-stormlib
```

## Quick start (read)

```go
package main

import (
    "fmt"
    "log"

    "github.com/ldmonster/go-stormlib/pkg/storm"
)

func main() {
    a, err := storm.Open("example.mpq", storm.OpenOptions{})
    if err != nil {
        log.Fatal(err)
    }
    defer a.Close()

    files, err := a.ListFiles()
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("files: %d\n", len(files))

    data, err := a.ReadFileByName("units\\human\\footman.blp", 0, 0)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("read bytes: %d\n", len(data))
}
```

## Quick start (create + write)

```go
package main

import (
    "log"

    "github.com/ldmonster/go-stormlib/pkg/storm"
)

func main() {
    a, err := storm.Create("new.mpq", storm.CreateOptions{
        ArchiveVersion: 0, // v1
        MaxFileCount:   8,
    })
    if err != nil {
        log.Fatal(err)
    }
    defer a.Close()

    if err := a.CreateFile("hello.txt", uint32(len("hello")), 0); err != nil {
        log.Fatal(err)
    }
    if err := a.WriteFile([]byte("hello")); err != nil {
        log.Fatal(err)
    }
    if err := a.FinishFile(); err != nil {
        log.Fatal(err)
    }
}
```

## Repository layout

| Path                                                           | Description                                                                        |
| -------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| [pkg/storm](pkg/storm)                                         | Public Go API. Start here for application-level usage.                             |
| [internal](internal/README.md)                                 | Private implementation packages (not importable from outside the module).          |
| [internal/archive](internal/archive/README.md)                 | MPQ open/read/write/create/compact/patch engine.                                   |
| [internal/mpq](internal/mpq/README.md)                         | On-disk header, hash/block/HET/BET tables, file-key derivation.                    |
| [internal/compress](internal/compress/README.md)               | Pure-Go ports of Blizzard codecs (PKWARE explode, Huffman, ADPCM).                 |
| [internal/naming](internal/naming/README.md)                   | UTF-8 ↔ filename helpers (StormLib `SMemUtf8`).                                    |
| [tools](tools/README.md)                                       | Out-of-tree binaries and parity tooling.                                           |
| [tools/parity](tools/parity/README.md)                         | Parity test suites + drift scripts and the parity-command contract.                |
| [tools/paritycmd](tools/paritycmd/README.md)                   | `stormlib-parity`: in-repo Go implementation of the parity contract.               |
| [tools/stormlib-parity-c](tools/stormlib-parity-c/README.md)   | `stormlib-parity-c`: native StormLib-backed implementation of the parity contract. |
| [stormlib](stormlib/)                                          | Vendored upstream StormLib C/C++ source tree.                                      |

## Development

This repository ships a Taskfile for the common workflows:

| Task                          | Description                                                          |
| ----------------------------- | -------------------------------------------------------------------- |
| `task test`                   | Full local CI: unit tests, race tests, structured & C-backed parity. |
| `task go:test`                | Run all Go tests.                                                    |
| `task go:race`                | Run race-enabled tests for core packages.                            |
| `task lint`                   | Run `golangci-lint` with the repo config.                            |
| `task parity:build`           | Build `bin/stormlib-parity` (Go).                                    |
| `task cparity:build`          | Build `build/stormlib-parity-c` (native, with Go fallback).          |
| `task parity:structured`      | Structured parity suite + JSON reports under `parity-reports/`.      |
| `task parity:strict-evidence` | Strict subset + evidence artifacts.                                  |
| `task parity:c-backed`        | Strict suite vs C binary, produce drift diff.                        |
| `task fuzz:mpq`               | Run MPQ fuzz targets for ~20s.                                       |

`task --list` enumerates every task.

## Parity tooling

Validation against StormLib is built around a small CLI contract
(currently `v0.1.0-contract1`). Two implementations of the contract live
in this tree:

- [tools/paritycmd](tools/paritycmd/README.md) — Go (`bin/stormlib-parity`).
- [tools/stormlib-parity-c](tools/stormlib-parity-c/README.md) — native
  C++ against StormLib (`build/stormlib-parity-c`).

The same Go test suite under [tools/parity](tools/parity/README.md) drives
both, and the drift report between them is the source of truth for
behavioral parity.

## License

This repository vendors / includes the upstream `stormlib` source tree.
See the project and upstream repository metadata for licensing details.
