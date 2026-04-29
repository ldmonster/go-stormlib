# go-stormlib

`go-stormlib` is a Go implementation of Blizzard MPQ archive handling with behavior aligned to StormLib where possible.

The project focuses on practical MPQ read support, incremental write/create support, and parity-driven validation against C-backed behavior.

## Status

The library is actively developed and currently implements a subset of StormLib.

Implemented and usable today:

- Open MPQ archives (`storm.Open`)
- List archive entries (`(*Archive).ListFiles`)
- Read by index/hash/name (`ReadFileByIndex`, `ReadFileByHash`, `ReadFileByName`)
- Extract files to disk (`(*Archive).ExtractFile`, MPQ scope only)
- Create empty archives and write uncompressed single-unit files (`CreateFile` -> `WriteFile` -> `FinishFile`)
- Remove and rename files (narrow table-update slice)
- UTF-8 filename conversion helpers (`UTF8ToFileName`, `FileNameToUTF8`)

Known partial/unsupported areas:

- `Compact`, `SignArchive` return `ErrUnsupportedFeature`
- Patch-chain merge/read semantics are not implemented
- Compression support is partial (unsupported codecs return typed errors)
- Some parity differences vs StormLib are intentional and documented in `docs/compatibility.md`

## Installation

```bash
go get github.com/ldmonster/go-stormlib
```

## Quick Start (Read)

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

## Quick Start (Create + Write)

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

## Development

This repository includes a Taskfile for common workflows:

- `task go:test` - run all Go tests
- `task go:race` - run race-enabled tests for core packages
- `task lint` - run golangci-lint
- `task parity:build` - build parity CLI (`bin/stormlib-parity`)
- `task parity:structured` - run structured parity suite and produce reports
- `task parity:c-backed` - run strict parity comparison against C-backed command

Run `task --list` to see all available tasks.

## Parity Tooling

The parity command lives at `tools/paritycmd` and is built as `stormlib-parity`.

It supports:

- default open check mode (`open-ok` / `open-fail`)
- structured lookup report mode (`--report-lookup`)
- structured read report mode (`--report-read`)

Version contract currently tracked in code: `v0.1.0-contract1`.

## Documentation

- Compatibility and known behavior deltas: `docs/compatibility.md`
- C-to-Go domain inventory: `docs/c_to_go_domain_inventory.md`

## License

This repository vendors/includes the upstream `stormlib` source tree. See the project and upstream repository metadata for licensing details.
