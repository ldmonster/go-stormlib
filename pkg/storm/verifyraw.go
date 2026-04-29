package storm

import (
	"crypto/md5"
	"errors"
	"io"
	"os"

	"github.com/ldmonster/go-stormlib/internal/mpq"
)

// VerifyRawData target codes (parity with StormLib SFILE_VERIFY_*).
const (
	VerifyMPQHeader    uint32 = 1
	VerifyHETTable     uint32 = 2
	VerifyBETTable     uint32 = 3
	VerifyHashTable    uint32 = 4
	VerifyBlockTable   uint32 = 5
	VerifyHiBlockTable uint32 = 6
	VerifyFileRaw      uint32 = 7
)

// ErrRawChunkMD5Mismatch is returned by VerifyRawData when at least one
// per-chunk MD5 does not match the trailing MD5 array stored in the archive.
var ErrRawChunkMD5Mismatch = errors.New("storm: raw chunk md5 mismatch")

// VerifyRawData verifies the per-chunk MD5 trailers introduced in MPQ v4.
// Returns nil for archives that do not embed raw-chunk MD5 metadata
// (RawChunkSize == 0), matching StormLib's "ERROR_SUCCESS for non-v4" rule.
//
// `dataType` selects the region: VerifyMPQHeader, VerifyHETTable,
// VerifyBETTable, VerifyHashTable (no-op), VerifyBlockTable (no-op),
// VerifyHiBlockTable (no-op), or VerifyFileRaw (uses `name`).
func (a *Archive) VerifyRawData(dataType uint32, name string) error {
	h := a.inner.Header
	if h.RawChunkSize == 0 {
		return nil
	}

	switch dataType {
	case VerifyMPQHeader:
		// First 192 bytes (header up to the MD5 region itself).
		const headerHashLen = 192
		if h.HeaderSize < headerHashLen {
			return nil
		}

		return verifyRawChunkRange(a.inner.Path, uint64(h.Offset), headerHashLen, h.RawChunkSize)

	case VerifyHETTable:
		if h.HetTablePos64 == 0 || h.HetTableSize64 == 0 {
			return nil
		}

		return verifyRawChunkRange(
			a.inner.Path,
			uint64(h.Offset)+h.HetTablePos64,
			h.HetTableSize64,
			h.RawChunkSize,
		)

	case VerifyBETTable:
		if h.BetTablePos64 == 0 || h.BetTableSize64 == 0 {
			return nil
		}

		return verifyRawChunkRange(
			a.inner.Path,
			uint64(h.Offset)+h.BetTablePos64,
			h.BetTableSize64,
			h.RawChunkSize,
		)

	case VerifyHashTable, VerifyBlockTable, VerifyHiBlockTable:
		// StormLib reports ERROR_SUCCESS for these (not protected by raw MD5).
		return nil

	case VerifyFileRaw:
		if name == "" {
			return ErrInvalidParameter
		}

		entry, ok := a.findEntryForName(name)
		if !ok {
			return ErrFileNotFound
		}

		base := uint64(h.Offset)
		if h.FormatVersion == 0 {
			// v1: file offsets are relative-with-wrap; modern archives use
			// absolute. The archive layer's NormalizeBlockTableEntries does
			// the wrap, so we recompute from the same logic for safety.
			base = wrapV1Offset(h.Offset, entry.Block.FilePos)

			return verifyRawChunkRange(
				a.inner.Path,
				base,
				uint64(entry.Block.CompressedSize),
				h.RawChunkSize,
			)
		}

		return verifyRawChunkRange(
			a.inner.Path,
			base+uint64(entry.Block.FilePos),
			uint64(entry.Block.CompressedSize),
			h.RawChunkSize,
		)
	}

	return ErrInvalidParameter
}

func (a *Archive) findEntryForName(name string) (mpq.IndexedFileEntry, bool) {
	hashA := mpq.NameHashA(name)
	hashB := mpq.NameHashB(name)
	locale := a.locale

	// First pass: exact locale match.
	for _, e := range a.inner.FileIndex {
		if e.Hash.HashA == hashA && e.Hash.HashB == hashB && e.Hash.Locale == locale {
			return e, true
		}
	}
	// Fallback: any locale (mirrors GetFileEntryLocale → GetFileEntryAny).
	for _, e := range a.inner.FileIndex {
		if e.Hash.HashA == hashA && e.Hash.HashB == hashB {
			return e, true
		}
	}

	return mpq.IndexedFileEntry{}, false
}

// verifyRawChunkRange reads `size` bytes starting at `pos`, splits them into
// chunks of `chunkSize`, computes the MD5 of each chunk, then reads the
// trailing MD5 array (chunkCount * 16 bytes) and compares.
func verifyRawChunkRange(path string, pos, size uint64, chunkSize uint32) error {
	if size == 0 {
		return nil
	}

	if chunkSize == 0 {
		return nil
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.Seek(int64(pos), io.SeekStart); err != nil {
		return err
	}

	chunkCount := (size + uint64(chunkSize) - 1) / uint64(chunkSize)
	calc := make([][16]byte, chunkCount)

	buf := make([]byte, chunkSize)
	remaining := size

	for i := uint64(0); i < chunkCount; i++ {
		n := uint64(chunkSize)
		if n > remaining {
			n = remaining
		}

		if _, err := io.ReadFull(f, buf[:n]); err != nil {
			return err
		}

		calc[i] = md5.Sum(buf[:n])
		remaining -= n
	}

	stored := make([]byte, chunkCount*16)
	if _, err := io.ReadFull(f, stored); err != nil {
		return err
	}

	for i := uint64(0); i < chunkCount; i++ {
		for j := 0; j < 16; j++ {
			if calc[i][j] != stored[i*16+uint64(j)] {
				return ErrRawChunkMD5Mismatch
			}
		}
	}

	return nil
}

// wrapV1Offset mirrors internal/mpq.wrapV1Offset for v1 file-pos resolution.
func wrapV1Offset(headerOffset int64, filePos uint32) uint64 {
	base := uint64(headerOffset)
	off := uint64(filePos)
	// v1 wraps to 32 bits relative to the lower 32 bits of the header offset.
	low := uint64(uint32(base))
	if off < low {
		// already wrapped
		return base + off
	}

	return base + off
}
