package archive

import (
	"crypto/md5"
	"fmt"
	"io"
	"os"

	"github.com/ldmonster/go-stormlib/internal/mpq"
)

// Compact rewrites the archive in place so that only live block entries remain,
// reclaiming gaps left behind by removed/replaced files. The on-disk archive layout
// after compaction is:
//
//	[lead padding] [header] [live block payloads concatenated] [hash table] [block table]
//
// HET/BET/Hi-block extension tables are stripped by Compact — StormLib's
// BuildFileTable transparently falls back to the classic hash/block tables
// when the HET pointer is zero. v4 archives have their MD5HashTable and
// MD5BlockTable digests recomputed so VerifyHashTableMD5/VerifyBlockTableMD5
// succeed after compaction.
func (a *Archive) Compact() error {
	if a == nil {
		return fmt.Errorf("%w: nil archive", ErrArchiveWriteUnsupported)
	}

	if a.pendingWrite != nil {
		return ErrWriteInProgress
	}

	src, err := os.Open(a.Path)
	if err != nil {
		return fmt.Errorf("open archive for compact: %w", err)
	}
	defer src.Close()

	tmpPath := a.Path + ".compact.tmp"

	dst, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("create compact tmp: %w", err)
	}

	defer func() {
		dst.Close()

		_ = os.Remove(tmpPath)
	}()

	// Lead padding (lifted byte-for-byte from source through header offset).
	leadEnd := a.Header.Offset
	if leadEnd > 0 {
		if _, err := dst.Write(make([]byte, leadEnd)); err != nil {
			return fmt.Errorf("write compact lead pad: %w", err)
		}
	}

	// Reserve header space; it will be rewritten at the end.
	headerBytes := a.Header.HeaderSize
	if headerBytes == 0 {
		headerBytes = 32
	}

	headerOff := leadEnd

	if _, err := dst.Write(make([]byte, headerBytes)); err != nil {
		return fmt.Errorf("write compact header placeholder: %w", err)
	}

	// Walk live entries in their original block order, copying payload bytes.
	type liveEntry struct {
		oldHashIndex int
		oldBlock     mpq.BlockEntry
		newBlock     mpq.BlockEntry
		newIndex     uint32
	}

	live := make([]liveEntry, 0, len(a.BlockTable))
	hashLiveByOldIdx := make(map[int]uint32)

	for _, e := range a.FileIndex {
		if e.Block.Flags&mpq.FileFlagExists == 0 {
			continue
		}

		live = append(live, liveEntry{
			oldHashIndex: e.HashIndex,
			oldBlock:     e.Block,
		})
	}

	cursor := uint64(headerOff) + uint64(headerBytes)

	for i := range live {
		oldFilePos := uint64(a.Header.Offset) + uint64(live[i].oldBlock.FilePos)

		buf := make([]byte, live[i].oldBlock.CompressedSize)
		if _, err := src.ReadAt(buf, int64(oldFilePos)); err != nil && err != io.EOF {
			return fmt.Errorf("compact read block %d: %w", i, err)
		}

		if _, err := dst.Write(buf); err != nil {
			return fmt.Errorf("compact write block %d: %w", i, err)
		}

		live[i].newBlock = live[i].oldBlock
		live[i].newBlock.FilePos = uint32(cursor - uint64(headerOff))
		live[i].newIndex = uint32(i)
		hashLiveByOldIdx[live[i].oldHashIndex] = live[i].newIndex
		cursor += uint64(len(buf))
	}

	hashTablePos := uint32(cursor - uint64(headerOff))

	// Rebuild hash table: live entries keep their slot positions; deleted/dead
	// entries are reset to FREE.
	newHashes := make([]mpq.HashEntry, len(a.HashTable))
	for i := range newHashes {
		newHashes[i] = mpq.HashEntry{
			HashA:      0xFFFFFFFF,
			HashB:      0xFFFFFFFF,
			Locale:     0xFFFF,
			Platform:   0xFF,
			Flags:      0xFF,
			BlockIndex: hashEntryEmpty,
		}
	}

	for oldIdx, newIdx := range hashLiveByOldIdx {
		h := a.HashTable[oldIdx]
		h.BlockIndex = newIdx
		newHashes[oldIdx] = h
	}

	hashRaw := marshalHashTable(newHashes)
	mpq.EncryptMpqTableDiskBytes(hashRaw, mpq.HashTableEncryptKey())

	if _, err := dst.Write(hashRaw); err != nil {
		return fmt.Errorf("compact write hash table: %w", err)
	}

	blockTablePos := hashTablePos + uint32(len(hashRaw))

	newBlocks := make([]mpq.BlockEntry, len(live))
	for i := range live {
		newBlocks[i] = live[i].newBlock
	}

	blockRaw := marshalBlockTable(newBlocks)
	mpq.EncryptMpqTableDiskBytes(blockRaw, mpq.BlockTableEncryptKey())

	if _, err := dst.Write(blockRaw); err != nil {
		return fmt.Errorf("compact write block table: %w", err)
	}

	archiveSize32 := blockTablePos + uint32(len(blockRaw))

	newHeader := a.Header
	newHeader.HashTablePos = hashTablePos
	newHeader.BlockTablePos = blockTablePos
	newHeader.HashTableSize = uint32(len(newHashes))
	newHeader.BlockTableSize = uint32(len(newBlocks))
	newHeader.HashTablePosHi = 0
	newHeader.BlockTablePosHi = 0

	// Rebuild HET/BET for v3+ archives so the lookup acceleration still
	// reflects the post-compaction file table. Block names are taken from
	// the recorded blockNames map (populated by writeFile/CreateFile).
	var hetRaw, betRaw []byte

	if newHeader.FormatVersion >= 2 {
		inputs := make([]mpq.HetBetInput, len(newBlocks))
		for i := range live {
			inputs[i].Block = live[i].newBlock
			if name, ok := a.blockNames[uint32(live[i].oldHashIndex)]; ok {
				inputs[i].HasName = true
				inputs[i].FileNameHash = mpq.JenkinsHash(name)
			}
		}

		var hetMD5, betMD5 [16]byte

		hetRaw, betRaw, hetMD5, betMD5 = mpq.MarshalHetBet(inputs)

		hetPos := uint64(blockTablePos) + uint64(len(blockRaw))
		betPos := hetPos + uint64(len(hetRaw))

		if _, err := dst.Write(hetRaw); err != nil {
			return fmt.Errorf("compact write het: %w", err)
		}

		if _, err := dst.Write(betRaw); err != nil {
			return fmt.Errorf("compact write bet: %w", err)
		}

		newHeader.HetTablePos64 = hetPos
		newHeader.HetTableSize64 = uint64(len(hetRaw))
		newHeader.BetTablePos64 = betPos
		newHeader.BetTableSize64 = uint64(len(betRaw))
		newHeader.MD5HetTable = hetMD5
		newHeader.MD5BetTable = betMD5
		newHeader.HiBlockTablePos = 0
		newHeader.HiBlockSize64 = 0
		newHeader.MD5HiBlockTable = [16]byte{}
		newHeader.HashTableSize64 = uint64(len(hashRaw))
		newHeader.BlockTableSize64 = uint64(len(blockRaw))

		archiveSize32 = uint32(betPos + uint64(len(betRaw)))
		newHeader.ArchiveSize64 = uint64(archiveSize32)
	}

	newHeader.ArchiveSize32 = archiveSize32
	if newHeader.FormatVersion >= 3 {
		newHeader.MD5HashTable = md5.Sum(hashRaw)
		newHeader.MD5BlockTable = md5.Sum(blockRaw)
	}

	hdrBytes, err := mpq.MarshalHeader(newHeader)
	if err != nil {
		return fmt.Errorf("marshal compact header: %w", err)
	}

	if _, err := dst.WriteAt(hdrBytes, headerOff); err != nil {
		return fmt.Errorf("write compact header: %w", err)
	}

	if err := dst.Close(); err != nil {
		return fmt.Errorf("close compact tmp: %w", err)
	}

	src.Close()

	if err := os.Rename(tmpPath, a.Path); err != nil {
		return fmt.Errorf("compact rename: %w", err)
	}

	a.Header = newHeader
	a.HashTable = newHashes
	a.BlockTable = newBlocks
	a.FileIndex = mpq.BuildFileIndex(newHashes, newBlocks)

	return nil
}
