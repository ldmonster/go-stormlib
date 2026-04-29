# internal

Implementation packages for `go-stormlib`. Everything in this tree is
private (Go's `internal/` rule) — only the in-repo `pkg/storm` API and the
parity tooling under `tools/` may import these packages. External users
should depend on [pkg/storm](../pkg/storm) instead.

## Layout

```
internal/
├── archive/      MPQ archive read/write/create/compact/patch logic.
│                 Composes mpq + compress codecs. See ./archive/README.md.
├── compress/     Pure-Go ports of Blizzard MPQ codecs (PKWARE explode,
│                 Huffman, ADPCM). See ./compress/README.md.
├── mpq/          On-disk header / hash / block / HET / BET parsing,
│                 file-key derivation, table fuzzing. See ./mpq/README.md.
└── naming/       UTF-8 ↔ filename helpers (StormLib SMemUtf8 contract).
                  See ./naming/README.md.
```

## Dependency graph (within `internal/`)

```
naming      (no internal deps)
compress/*  (no internal deps)
mpq         (no internal deps)
archive     -> mpq, compress/{pkware, huffman, adpcm}
```

`pkg/storm` is the only first-party consumer of `internal/archive` and
`internal/mpq`; `internal/naming` is re-exported by `pkg/storm` for
filename helpers.

## Conventions

- Packages are named after the closest StormLib source file or domain
  concept they port (e.g. `mpq/filekey.go` ≈ `SBaseCommon.cpp`
  `DecryptFileKey`).
- Behavior deltas vs StormLib are documented in the per-package README and
  in [docs/compatibility.md](../docs/compatibility.md).
- Tests prefer deterministic in-memory fixtures. Where parity with a real
  binary matters, the assertion lives under
  [tools/parity](../tools/parity/README.md) instead of in the unit-test
  layer here.
