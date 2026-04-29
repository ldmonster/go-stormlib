// Package archive implements the mid-level MPQ archive engine: open, read,
// write, create, compact, and patch operations.
//
// It composes [github.com/ldmonster/go-stormlib/internal/mpq] (table parsing
// and cryptography) with the codec packages under
// [github.com/ldmonster/go-stormlib/internal/compress] to produce a complete
// read/write pipeline for MPQ v1 and v2 archives.
//
// This package is internal. External callers should use
// [github.com/ldmonster/go-stormlib/pkg/storm] instead.
package archive
