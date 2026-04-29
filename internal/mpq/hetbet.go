package mpq

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"io"
)

// HET/BET on-disk constants. The "ExtHeader" is a common 12-byte preamble:
//
//	dwSignature  ('HET\x1A' or 'BET\x1A'), dwVersion (1), dwDataSize.
//
// The data after the ExtHeader is what gets encrypted with the same Storm
// block cipher used for hash/block tables (key MPQ_KEY_HASH_TABLE / _BLOCK_TABLE).
// MD5 is computed over the full on-disk bytes (including the ExtHeader).
const (
	hetSignature uint32 = 0x1A544548 // "HET\x1A" little-endian
	betSignature uint32 = 0x1A544542 // "BET\x1A" little-endian

	mpqExtHeaderSize    = 12
	mpqHetHeaderBodyLen = 32 // sizeof(TMPQHetHeader) - sizeof(TMPQExtHeader)
	mpqBetHeaderBodyLen = 80 // sizeof(TMPQBetHeader) - sizeof(TMPQExtHeader); 20 DWORDs.

	mpqHetEntryFree byte = 0
	mpqHetNameBits  byte = 0x40
)

// asciiLowerForHash mirrors StormLib's AsciiToLowerTable: lowercase A-Z and
// fold '/' to '\\'. Other bytes pass through unchanged.
func asciiLowerForHash(b byte) byte {
	switch {
	case b == '/':
		return '\\'
	case b >= 'A' && b <= 'Z':
		return b + 0x20
	default:
		return b
	}
}

// JenkinsHash returns the Storm 64-bit Jenkins hash of an MPQ filename. The
// name is normalized via asciiLowerForHash before hashing. The result is
// (primary << 32) | secondary, matching HashStringJenkins in StormLib.
func JenkinsHash(name string) uint64 {
	buf := make([]byte, len(name))
	for i := 0; i < len(name); i++ {
		buf[i] = asciiLowerForHash(name[i])
	}

	primary := uint32(1)
	secondary := uint32(2)
	hashlittle2(buf, &primary, &secondary)

	return (uint64(primary) << 32) | uint64(secondary)
}

// hashlittle2 is a port of Bob Jenkins's lookup3.c hashlittle2 for byte
// arrays. The pc argument receives the primary hash (initial value 1 in
// StormLib's call) and pb receives the secondary hash (initial 2).
func hashlittle2(key []byte, pc, pb *uint32) {
	rot := func(x uint32, k uint) uint32 { return (x << k) | (x >> (32 - k)) }
	mix := func(a, b, c *uint32) {
		*a -= *c
		*a ^= rot(*c, 4)
		*c += *b
		*b -= *a
		*b ^= rot(*a, 6)
		*a += *c
		*c -= *b
		*c ^= rot(*b, 8)
		*b += *a
		*a -= *c
		*a ^= rot(*c, 16)
		*c += *b
		*b -= *a
		*b ^= rot(*a, 19)
		*a += *c
		*c -= *b
		*c ^= rot(*b, 4)
		*b += *a
	}
	finalMix := func(a, b, c *uint32) {
		*c ^= *b
		*c -= rot(*b, 14)
		*a ^= *c
		*a -= rot(*c, 11)
		*b ^= *a
		*b -= rot(*a, 25)
		*c ^= *b
		*c -= rot(*b, 16)
		*a ^= *c
		*a -= rot(*c, 4)
		*b ^= *a
		*b -= rot(*a, 14)
		*c ^= *b
		*c -= rot(*b, 24)
	}

	length := uint32(len(key))
	a := uint32(0xdeadbeef) + length + *pc
	b := a
	c := a + *pb

	off := 0
	for length > 12 {
		a += binary.LittleEndian.Uint32(key[off : off+4])
		b += binary.LittleEndian.Uint32(key[off+4 : off+8])
		c += binary.LittleEndian.Uint32(key[off+8 : off+12])
		mix(&a, &b, &c)

		length -= 12
		off += 12
	}

	switch length {
	case 12:
		c += binary.LittleEndian.Uint32(key[off+8 : off+12])
		b += binary.LittleEndian.Uint32(key[off+4 : off+8])
		a += binary.LittleEndian.Uint32(key[off : off+4])
	case 11:
		c += uint32(key[off+10]) << 16
		fallthrough
	case 10:
		c += uint32(key[off+9]) << 8
		fallthrough
	case 9:
		c += uint32(key[off+8])
		fallthrough
	case 8:
		b += binary.LittleEndian.Uint32(key[off+4 : off+8])
		a += binary.LittleEndian.Uint32(key[off : off+4])
	case 7:
		b += uint32(key[off+6]) << 16
		fallthrough
	case 6:
		b += uint32(key[off+5]) << 8
		fallthrough
	case 5:
		b += uint32(key[off+4])
		fallthrough
	case 4:
		a += binary.LittleEndian.Uint32(key[off : off+4])
	case 3:
		a += uint32(key[off+2]) << 16
		fallthrough
	case 2:
		a += uint32(key[off+1]) << 8
		fallthrough
	case 1:
		a += uint32(key[off])
	case 0:
		*pc = c
		*pb = b

		return
	}

	finalMix(&a, &b, &c)
	*pc = c
	*pb = b
}

// necessaryBitCount returns the number of bits required to represent `max`,
// matching StormLib's GetNecessaryBitCount. Note: returns 1 for max==1, 0 for
// max==0; matches the C reference exactly.
func necessaryBitCount(max uint64) uint32 {
	n := uint32(0)

	for max > 0 {
		max >>= 1
		n++
	}

	return n
}

// setBits writes `bitLen` low-order bits of `value` into `bits` starting at
// bit position `pos`. The bit array is little-endian: bit 0 = LSB of byte 0.
// Caller must ensure pos+bitLen <= 8*len(bits).
func setBits(bits []byte, pos, bitLen uint32, value uint64) {
	for i := uint32(0); i < bitLen; i++ {
		bit := byte((value >> i) & 1)
		idx := pos + i
		bits[idx>>3] |= bit << (idx & 7)
	}
}

// HetBetInput is the per-block-entry information needed to build HET/BET tables.
// Order of entries in the slice is the canonical block index order; deleted
// blocks (MPQ_FILE_EXISTS == 0) must still appear in the slice.
type HetBetInput struct {
	Block        BlockEntry
	HasName      bool   // true if FileNameHash is the real Jenkins hash
	FileNameHash uint64 // 64-bit Jenkins hash, with high bit forced (HET OrMask)
}

// MarshalHetBet builds on-disk encrypted HET and BET tables for the given
// block entries. The returned bytes are ready to be written at the offsets
// recorded in TMPQHeader.HetTablePos64 / BetTablePos64. The companion MD5s
// are computed over the full on-disk byte ranges and should be stored in
// TMPQHeader.MD5HetTable / MD5BetTable for v4 archives.
func MarshalHetBet(entries []HetBetInput) ([]byte, []byte, [16]byte, [16]byte) {
	hetBytes := buildHet(entries)
	betBytes := buildBet(entries)

	EncryptMpqTableDiskBytes(hetBytes[mpqExtHeaderSize:], HashTableEncryptKey())
	EncryptMpqTableDiskBytes(betBytes[mpqExtHeaderSize:], BlockTableEncryptKey())

	hetMD5 := md5.Sum(hetBytes)
	betMD5 := md5.Sum(betBytes)

	return hetBytes, betBytes, hetMD5, betMD5
}

func buildHet(entries []HetBetInput) []byte {
	entryCount := uint32(0)

	for _, e := range entries {
		if e.HasName && (e.Block.Flags&FileFlagExists) != 0 {
			entryCount++
		}
	}

	// totalCount = (entryCount * 4) / 3, matching StormLib's CreateHetTable
	// when dwTotalCount is zero.
	totalCount := (entryCount * 4) / 3
	if totalCount < entryCount {
		totalCount = entryCount
	}

	if totalCount == 0 {
		// Edge case: no named files. Use a single slot so divisor is non-zero.
		totalCount = 1
	}

	indexSizeTotal := necessaryBitCount(uint64(len(entries)))
	if indexSizeTotal == 0 {
		indexSizeTotal = 1
	}

	indexTableSize := (indexSizeTotal*totalCount + 7) / 8
	tableSize := uint32(mpqHetHeaderBodyLen) + totalCount + indexTableSize

	nameHashes := make([]byte, totalCount)
	indexBits := make([]byte, indexTableSize)
	// File-index bit array starts as all 0xFF, matching TMPQBits::Create(..., 0xFF).
	for i := range indexBits {
		indexBits[i] = 0xFF
	}

	for i, e := range entries {
		if !e.HasName || (e.Block.Flags&FileFlagExists) == 0 {
			continue
		}

		startIdx := uint32(e.FileNameHash % uint64(totalCount))
		nameHash1 := byte(e.FileNameHash >> (mpqHetNameBits - 8))

		idx := startIdx
		for {
			if nameHashes[idx] == mpqHetEntryFree {
				nameHashes[idx] = nameHash1

				// Clear the "free" bits (all-ones) in the index slot
				// before writing the actual file index, so the OR-based
				// setBits produces the correct value.
				bitOff := indexSizeTotal * idx
				for b := uint32(0); b < indexSizeTotal; b++ {
					indexBits[(bitOff+b)>>3] &^= 1 << ((bitOff + b) & 7)
				}

				setBits(indexBits, bitOff, indexSizeTotal, uint64(uint32(i)))

				break
			}

			idx = (idx + 1) % totalCount
			if idx == startIdx {
				break // No room — should not happen given totalCount > entryCount.
			}
		}
	}

	out := make([]byte, mpqExtHeaderSize+int(tableSize))
	binary.LittleEndian.PutUint32(out[0:4], hetSignature)
	binary.LittleEndian.PutUint32(out[4:8], 1)
	binary.LittleEndian.PutUint32(out[8:12], tableSize)

	// HET header body (32 bytes) at offset 12.
	binary.LittleEndian.PutUint32(out[12:16], tableSize)
	binary.LittleEndian.PutUint32(out[16:20], entryCount)
	binary.LittleEndian.PutUint32(out[20:24], totalCount)
	binary.LittleEndian.PutUint32(out[24:28], uint32(mpqHetNameBits))
	binary.LittleEndian.PutUint32(out[28:32], indexSizeTotal)
	binary.LittleEndian.PutUint32(out[32:36], 0) // dwIndexSizeExtra
	binary.LittleEndian.PutUint32(out[36:40], indexSizeTotal)
	binary.LittleEndian.PutUint32(out[40:44], indexTableSize)

	copy(out[44:44+totalCount], nameHashes)
	copy(out[44+totalCount:], indexBits)

	return out
}

func buildBet(entries []HetBetInput) []byte {
	const maxFlagIndex = 512

	flagsArray := make([]uint32, 0, 16)
	flagOf := func(f uint32) uint32 {
		for i, v := range flagsArray {
			if v == f {
				return uint32(i)
			}
		}

		flagsArray = append(flagsArray, f)
		if len(flagsArray) > maxFlagIndex {
			// Should never happen for any sane archive.
			flagsArray = flagsArray[:maxFlagIndex]
		}

		return uint32(len(flagsArray) - 1)
	}

	var maxOffset, maxFileSize, maxCmpSize uint64

	maxFlagIdx := uint32(0)

	for _, e := range entries {
		if uint64(e.Block.FilePos) > maxOffset {
			maxOffset = uint64(e.Block.FilePos)
		}

		if uint64(e.Block.UncompressedSize) > maxFileSize {
			maxFileSize = uint64(e.Block.UncompressedSize)
		}

		if uint64(e.Block.CompressedSize) > maxCmpSize {
			maxCmpSize = uint64(e.Block.CompressedSize)
		}

		fi := flagOf(e.Block.Flags)
		if fi > maxFlagIdx {
			maxFlagIdx = fi
		}
	}

	bitCntFilePos := necessaryBitCount(maxOffset)
	bitCntFileSize := necessaryBitCount(maxFileSize)
	bitCntCmpSize := necessaryBitCount(maxCmpSize)
	bitCntFlagIdx := necessaryBitCount(uint64(maxFlagIdx + 1))

	bitIdxFilePos := uint32(0)
	bitIdxFileSize := bitIdxFilePos + bitCntFilePos
	bitIdxCmpSize := bitIdxFileSize + bitCntFileSize
	bitIdxFlagIdx := bitIdxCmpSize + bitCntCmpSize
	bitIdxUnknown := bitIdxFlagIdx + bitCntFlagIdx

	tableEntrySize := bitCntFilePos + bitCntFileSize + bitCntCmpSize + bitCntFlagIdx
	entryCount := uint32(len(entries))
	flagCount := uint32(len(flagsArray))

	bitTotalNH2 := uint32(mpqHetNameBits - 8) // 56
	nameHashArraySize := (bitTotalNH2*entryCount + 7) / 8

	fileTableBits := (tableEntrySize*entryCount + 7) / 8
	tableSize := uint32(mpqBetHeaderBodyLen) + flagCount*4 + fileTableBits + nameHashArraySize

	out := make([]byte, mpqExtHeaderSize+int(tableSize))
	binary.LittleEndian.PutUint32(out[0:4], betSignature)
	binary.LittleEndian.PutUint32(out[4:8], 1)
	binary.LittleEndian.PutUint32(out[8:12], tableSize)

	// BET header body at offset 12.
	binary.LittleEndian.PutUint32(out[12:16], tableSize)
	binary.LittleEndian.PutUint32(out[16:20], entryCount)
	binary.LittleEndian.PutUint32(out[20:24], 0x10) // dwUnknown08, matches CreateBetHeader
	binary.LittleEndian.PutUint32(out[24:28], tableEntrySize)
	binary.LittleEndian.PutUint32(out[28:32], bitIdxFilePos)
	binary.LittleEndian.PutUint32(out[32:36], bitIdxFileSize)
	binary.LittleEndian.PutUint32(out[36:40], bitIdxCmpSize)
	binary.LittleEndian.PutUint32(out[40:44], bitIdxFlagIdx)
	binary.LittleEndian.PutUint32(out[44:48], bitIdxUnknown)
	binary.LittleEndian.PutUint32(out[48:52], bitCntFilePos)
	binary.LittleEndian.PutUint32(out[52:56], bitCntFileSize)
	binary.LittleEndian.PutUint32(out[56:60], bitCntCmpSize)
	binary.LittleEndian.PutUint32(out[60:64], bitCntFlagIdx)
	binary.LittleEndian.PutUint32(out[64:68], 0) // dwBitCount_Unknown
	binary.LittleEndian.PutUint32(out[68:72], bitTotalNH2)
	binary.LittleEndian.PutUint32(out[72:76], 0) // dwBitExtra_NameHash2
	binary.LittleEndian.PutUint32(out[76:80], bitTotalNH2)
	binary.LittleEndian.PutUint32(out[80:84], nameHashArraySize)
	binary.LittleEndian.PutUint32(out[84:88], flagCount)

	// Flags array.
	flagsBase := mpqExtHeaderSize + mpqBetHeaderBodyLen
	for i, f := range flagsArray {
		binary.LittleEndian.PutUint32(out[flagsBase+i*4:flagsBase+(i+1)*4], f)
	}

	// Bit-packed file table.
	tableBase := uint32(flagsBase) + flagCount*4

	for i, e := range entries {
		bitOff := uint32(i) * tableEntrySize
		setBits(
			out[tableBase:tableBase+fileTableBits],
			bitOff+bitIdxFilePos,
			bitCntFilePos,
			uint64(e.Block.FilePos),
		)
		setBits(
			out[tableBase:tableBase+fileTableBits],
			bitOff+bitIdxFileSize,
			bitCntFileSize,
			uint64(e.Block.UncompressedSize),
		)
		setBits(
			out[tableBase:tableBase+fileTableBits],
			bitOff+bitIdxCmpSize,
			bitCntCmpSize,
			uint64(e.Block.CompressedSize),
		)
		setBits(
			out[tableBase:tableBase+fileTableBits],
			bitOff+bitIdxFlagIdx,
			bitCntFlagIdx,
			uint64(flagOf(e.Block.Flags)),
		)
	}

	// Bit-packed name-hash table (low 56 bits per entry).
	nhBase := tableBase + fileTableBits

	for i, e := range entries {
		var nh uint64
		if e.HasName {
			nh = e.FileNameHash
		}

		setBits(out[nhBase:nhBase+nameHashArraySize], uint32(i)*bitTotalNH2, bitTotalNH2, nh)
	}

	return out
}

// HetTable is the parsed representation of an HET extension table.
type HetTable struct {
	EntryCount     uint32
	TotalCount     uint32
	NameHashBits   uint32
	IndexSizeTotal uint32
	IndexSize      uint32
	NameHashes     []byte // length = TotalCount
	IndexBits      []byte // bit-packed file indexes; size = (IndexSizeTotal*TotalCount+7)/8
}

// BetTable is the parsed representation of a BET extension table.
type BetTable struct {
	EntryCount       uint32
	TableEntrySize   uint32
	BitIndexFilePos  uint32
	BitIndexFileSize uint32
	BitIndexCmpSize  uint32
	BitIndexFlagIdx  uint32
	BitCountFilePos  uint32
	BitCountFileSize uint32
	BitCountCmpSize  uint32
	BitCountFlagIdx  uint32
	BitTotalNH2      uint32
	BitCountNH2      uint32
	NameHashArrSize  uint32
	Flags            []uint32
	FileTableBits    []byte
	NameHashBits     []byte
}

// getBits reads bitLen low-order bits at position pos from a little-endian
// bit array (LSB-first per byte). Caller must ensure pos+bitLen <= 8*len(bits).
func getBits(bits []byte, pos, bitLen uint32) uint64 {
	var v uint64

	for i := uint32(0); i < bitLen; i++ {
		idx := pos + i
		bit := (bits[idx>>3] >> (idx & 7)) & 1
		v |= uint64(bit) << i
	}

	return v
}

// LoadHetTable reads an encrypted HET extension table from r at the given
// archive-relative position (already including header offset) and returns
// the parsed structure.
func LoadHetTable(r io.ReaderAt, pos int64, size uint32) (*HetTable, error) {
	if size < mpqExtHeaderSize+mpqHetHeaderBodyLen {
		return nil, fmt.Errorf("het: size %d too small", size)
	}

	raw := make([]byte, size)
	if _, err := r.ReadAt(raw, pos); err != nil {
		return nil, fmt.Errorf("het read: %w", err)
	}

	if binary.LittleEndian.Uint32(raw[0:4]) != hetSignature {
		return nil, fmt.Errorf("het: bad signature")
	}

	if binary.LittleEndian.Uint32(raw[4:8]) != 1 {
		return nil, fmt.Errorf("het: unsupported version")
	}

	// Decrypt body in place.
	DecryptMpqTableDiskBytes(raw[mpqExtHeaderSize:], HashTableEncryptKey())

	h := &HetTable{
		EntryCount:     binary.LittleEndian.Uint32(raw[16:20]),
		TotalCount:     binary.LittleEndian.Uint32(raw[20:24]),
		NameHashBits:   binary.LittleEndian.Uint32(raw[24:28]),
		IndexSizeTotal: binary.LittleEndian.Uint32(raw[28:32]),
		IndexSize:      binary.LittleEndian.Uint32(raw[36:40]),
	}
	indexTableSize := binary.LittleEndian.Uint32(raw[40:44])

	bodyStart := uint32(mpqExtHeaderSize + mpqHetHeaderBodyLen)
	if uint64(bodyStart)+uint64(h.TotalCount)+uint64(indexTableSize) > uint64(len(raw)) {
		return nil, fmt.Errorf("het: truncated body")
	}

	h.NameHashes = make([]byte, h.TotalCount)
	copy(h.NameHashes, raw[bodyStart:bodyStart+h.TotalCount])
	h.IndexBits = make([]byte, indexTableSize)
	copy(h.IndexBits, raw[bodyStart+h.TotalCount:bodyStart+h.TotalCount+indexTableSize])

	return h, nil
}

// Lookup probes the HET table for the given Jenkins file-name hash. Returns
// the file index (block table index) and true if found, or 0/false otherwise.
func (h *HetTable) Lookup(nameHash uint64) (uint32, bool) {
	if h.TotalCount == 0 || h.IndexSizeTotal == 0 {
		return 0, false
	}

	startIdx := uint32(nameHash % uint64(h.TotalCount))
	nameHash1 := byte(nameHash >> (h.NameHashBits - 8))

	idx := startIdx
	for {
		if h.NameHashes[idx] == mpqHetEntryFree {
			return 0, false
		}

		if h.NameHashes[idx] == nameHash1 {
			fi := uint32(getBits(h.IndexBits, h.IndexSizeTotal*idx, h.IndexSize))
			return fi, true
		}

		idx = (idx + 1) % h.TotalCount
		if idx == startIdx {
			return 0, false
		}
	}
}

// LoadBetTable reads an encrypted BET extension table from r at the given
// archive-relative position and returns the parsed structure.
func LoadBetTable(r io.ReaderAt, pos int64, size uint32) (*BetTable, error) {
	if size < mpqExtHeaderSize+mpqBetHeaderBodyLen {
		return nil, fmt.Errorf("bet: size %d too small", size)
	}

	raw := make([]byte, size)
	if _, err := r.ReadAt(raw, pos); err != nil {
		return nil, fmt.Errorf("bet read: %w", err)
	}

	if binary.LittleEndian.Uint32(raw[0:4]) != betSignature {
		return nil, fmt.Errorf("bet: bad signature")
	}

	if binary.LittleEndian.Uint32(raw[4:8]) != 1 {
		return nil, fmt.Errorf("bet: unsupported version")
	}

	DecryptMpqTableDiskBytes(raw[mpqExtHeaderSize:], BlockTableEncryptKey())

	b := &BetTable{
		EntryCount:       binary.LittleEndian.Uint32(raw[16:20]),
		TableEntrySize:   binary.LittleEndian.Uint32(raw[24:28]),
		BitIndexFilePos:  binary.LittleEndian.Uint32(raw[28:32]),
		BitIndexFileSize: binary.LittleEndian.Uint32(raw[32:36]),
		BitIndexCmpSize:  binary.LittleEndian.Uint32(raw[36:40]),
		BitIndexFlagIdx:  binary.LittleEndian.Uint32(raw[40:44]),
		BitCountFilePos:  binary.LittleEndian.Uint32(raw[48:52]),
		BitCountFileSize: binary.LittleEndian.Uint32(raw[52:56]),
		BitCountCmpSize:  binary.LittleEndian.Uint32(raw[56:60]),
		BitCountFlagIdx:  binary.LittleEndian.Uint32(raw[60:64]),
		BitTotalNH2:      binary.LittleEndian.Uint32(raw[68:72]),
		BitCountNH2:      binary.LittleEndian.Uint32(raw[76:80]),
		NameHashArrSize:  binary.LittleEndian.Uint32(raw[80:84]),
	}
	flagCount := binary.LittleEndian.Uint32(raw[84:88])

	flagsBase := uint32(mpqExtHeaderSize + mpqBetHeaderBodyLen)
	if uint64(flagsBase)+uint64(flagCount)*4 > uint64(len(raw)) {
		return nil, fmt.Errorf("bet: truncated flags")
	}

	b.Flags = make([]uint32, flagCount)
	for i := uint32(0); i < flagCount; i++ {
		b.Flags[i] = binary.LittleEndian.Uint32(raw[flagsBase+i*4 : flagsBase+(i+1)*4])
	}

	fileTableBits := (b.TableEntrySize*b.EntryCount + 7) / 8

	tableBase := flagsBase + flagCount*4
	if uint64(tableBase)+uint64(fileTableBits)+uint64(b.NameHashArrSize) > uint64(len(raw)) {
		return nil, fmt.Errorf("bet: truncated body")
	}

	b.FileTableBits = make([]byte, fileTableBits)
	copy(b.FileTableBits, raw[tableBase:tableBase+fileTableBits])
	b.NameHashBits = make([]byte, b.NameHashArrSize)
	copy(b.NameHashBits, raw[tableBase+fileTableBits:tableBase+fileTableBits+b.NameHashArrSize])

	return b, nil
}

// Entry returns the block-equivalent fields for the BET entry at fileIndex.
func (b *BetTable) Entry(fileIndex uint32) (BlockEntry, bool) {
	if fileIndex >= b.EntryCount {
		return BlockEntry{}, false
	}

	bitOff := fileIndex * b.TableEntrySize
	filePos := uint32(getBits(b.FileTableBits, bitOff+b.BitIndexFilePos, b.BitCountFilePos))
	fileSize := uint32(getBits(b.FileTableBits, bitOff+b.BitIndexFileSize, b.BitCountFileSize))
	cmpSize := uint32(getBits(b.FileTableBits, bitOff+b.BitIndexCmpSize, b.BitCountCmpSize))
	flagIdx := uint32(getBits(b.FileTableBits, bitOff+b.BitIndexFlagIdx, b.BitCountFlagIdx))

	var flags uint32
	if flagIdx < uint32(len(b.Flags)) {
		flags = b.Flags[flagIdx]
	}

	return BlockEntry{
		FilePos:          filePos,
		CompressedSize:   cmpSize,
		UncompressedSize: fileSize,
		Flags:            flags,
	}, true
}
