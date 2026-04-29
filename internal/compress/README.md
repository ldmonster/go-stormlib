# internal/compress

Pure-Go ports of the Blizzard-specific compression codecs that ship inside
MPQ archives. Each subpackage is a self-contained codec with no
dependencies on the rest of `go-stormlib` and is consumed by
[internal/archive](../archive/README.md) when assembling the read pipeline.

Standard codecs (`zlib`, `bzip2`, `lzma`) are *not* implemented here —
those use third-party libraries directly from the archive layer.

## Subpackages

| Package                       | Upstream source                          | Status                                 |
| ----------------------------- | ---------------------------------------- | -------------------------------------- |
| [pkware](pkware/)             | `stormlib/src/pklib/explode.c`           | Decompression only (`Explode`).        |
| [huffman](huffman/)           | `stormlib/src/huffman/huff.cpp`          | Compress + decompress (round-trip).    |
| [adpcm](adpcm/)               | `stormlib/src/adpcm/adpcm.cpp`           | Decompression only (`Decompress`, mono/stereo). |

Each subpackage has its own fuzz target (`Fuzz*`) covering panic-safety and
output-size invariants. Run them via:

```bash
task fuzz:compress
```

## Adding a codec

1. Port the C reference into a new subpackage with a single public
   `Decompress` (and optionally `Compress`) entry point.
2. Add unit tests with explicit byte-level fixtures.
3. Add a fuzz test that asserts no panics and bounded output.
4. Wire the codec into the dispatch table in
   [internal/archive/read.go](../archive/read.go).
