// Package mpq implements the on-disk MPQ format: header detection,
// hash/block tables, HET/BET secondary tables, and file-key derivation.
//
// The package performs no I/O orchestration on its own. Callers (typically
// [github.com/ldmonster/go-stormlib/internal/archive]) pass already-positioned
// byte slices or readers; this package returns typed, decrypted structures
// suitable for higher-level dispatch.
//
// This package is internal. External callers should use
// [github.com/ldmonster/go-stormlib/pkg/storm] instead.
package mpq
