# internal/mpq

Low-level MPQ on-disk types: header detection, hash/block tables, HET/BET
secondary tables, and file-key derivation. This package contains no I/O
orchestration of its own — it parses bytes, decrypts tables, and produces
typed structures that [internal/archive](../archive/README.md) drives.

## Files

| File                  | Responsibility                                                                        |
| --------------------- | ------------------------------------------------------------------------------------- |
| [header.go](header.go)         | `MPQ\x1A` / `MPQ\x1B` user-data / `MPK\x1A` detection, V1/V2 header decode, candidate-offset scanning. |
| [tables.go](tables.go)         | Hash / block / hi-block table load + decrypt + StormBuffer initialisation, and `HashEntry` / `BlockEntry` types. |
| [hetbet.go](hetbet.go)         | HET (extended hash) and BET (extended block) table parse and integrity (MD5) checks. |
| [filekey.go](filekey.go)       | `DecryptFileKey` matching `SBaseCommon.cpp` (with `MPQ_FILE_KEY_V2`/`FIX_KEY` rules). |
| [newarchive.go](newarchive.go) | Default sizing constants for newly-created archives.                                  |

`tables_fuzz_test.go` and `tables_test.go` exercise the cryptographic
surface; `header_test.go` covers signature dispatch and the ambiguous
header fallbacks. `hetbet_test.go` validates fixture-driven HET/BET decode.

## What this package does *not* do

- It does not open files. Callers pass already-positioned `io.Reader`s or
  raw byte slices.
- It does not own per-file decompression state — that is the archive
  layer's job.
- It does not maintain caches across calls; mutation happens at the
  archive layer.

## Compatibility notes

Several edge cases in StormLib's header detection (force-V1, foreign
header precedence, AVI rejection) have parity tests in
[tools/parity](../../tools/parity/README.md) that lock the Go behavior
against the C reference. Intentional deviations are documented in
[docs/compatibility.md](../../docs/compatibility.md).
