# internal/archive

Mid-level MPQ archive engine. This package owns the open archive object,
the read/write paths, file creation, table mutation, in-place compaction,
and patch-archive support. It is the layer that composes
[internal/mpq](../mpq/README.md) (table parsing) with the codec
implementations in [internal/compress](../compress/README.md).

## Files

| File              | Responsibility                                                                  |
| ----------------- | ------------------------------------------------------------------------------- |
| [archive.go](archive.go)         | `Archive` type, `Open`, locale/platform plumbing, listfile + table caches. |
| [read.go](read.go)               | Decompression pipeline: sector splitting, key decryption, codec dispatch. |
| [write.go](write.go)             | `CreateFile` / `WriteFile` / `FinishFile`: compressed and uncompressed sector emission. |
| [create.go](create.go)           | New empty archive layout (V1/V2 header, hash table sizing, signing slots). |
| [compact.go](compact.go)         | In-place compaction of live blocks (re-emits hash/block/HET/BET if present). |
| [patch.go](patch.go)             | Patch archive open + bsdiff40/COPY/BSD0 application semantics.            |
| [bsdiff40.go](bsdiff40.go)       | BSDIFF40 patch decoding (Blizzard variant of bsdiff).                     |
| [bzip2_encode.go](bzip2_encode.go) | bzip2 sector encode (uses `dsnet/bzip2`).                                |
| [lzma_encode.go](lzma_encode.go) | LZMA1 sector encode (uses `ulikunitz/xz/lzma`).                           |

`*_test.go` files cover round-trip read/write, compact, patch, codec
combinations, and several malformed-archive corner cases.

## Codec coverage (read path)

The dispatch in [read.go](read.go) currently handles:

- store / single-unit
- zlib (`compress/zlib`)
- bzip2 (stdlib `compress/bzip2` for decode)
- LZMA1 (`ulikunitz/xz/lzma`)
- PKWARE explode ([../compress/pkware](../compress/pkware))
- Huffman ([../compress/huffman](../compress/huffman))
- ADPCM mono/stereo ([../compress/adpcm](../compress/adpcm))

Unsupported codec combinations return a typed error rather than panicking;
parity tests under [tools/parity](../../tools/parity/README.md) gate the
strict-no-skips bar.

## What this package does *not* do

- It does not expose the user-facing API surface; that lives in
  [pkg/storm](../../pkg/storm). Imports outside the workspace should target
  `pkg/storm`.
- It does not manage table cryptography directly; key derivation and table
  decode/encode live in [internal/mpq](../mpq/README.md).
- Sign/verify functionality is currently a stub in `pkg/storm` and returns
  `ErrUnsupportedFeature`.
