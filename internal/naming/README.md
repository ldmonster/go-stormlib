# internal/naming

Pure-Go port of StormLib's UTF-8 ↔ narrow-`TCHAR` filename helpers
(`stormlib/src/SMemUtf8.cpp`). MPQ archives store filenames as 8-bit
strings whose interpretation depends on flags; this package implements
the same `SFILE_UTF8_*` flag semantics StormLib uses.

## Files

| File                          | Purpose                                                  |
| ----------------------------- | -------------------------------------------------------- |
| [utf8filename.go](utf8filename.go) | `UTF8ToFileName`, `FileNameToUTF8`, flags, errors. |
| [utf8filename_test.go](utf8filename_test.go) | Round-trip and StormLib parity tests.   |

## Public API

The functions are re-exported by [pkg/storm](../../pkg/storm) so callers
do not need to import `internal/...`.

## Flags

The supported flag bits (from `StormLib.h`) are:

| Constant                     | StormLib equivalent           | Effect                                                   |
| ---------------------------- | ----------------------------- | -------------------------------------------------------- |
| `naming.UTF8ReplaceInvalid`  | `SFILE_UTF8_REPLACE_INVALID`  | Replace ill-formed sequences with U+FFFD instead of erroring. |
| `naming.UTF8KeepInvalidFCH`  | `SFILE_UTF8_KEEP_INVALID_FCH` | Preserve non-ASCII bytes verbatim during conversion.     |

See the package doc-comment in [utf8filename.go](utf8filename.go) for the
exact precedence of these flags.
