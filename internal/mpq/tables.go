// Copyright 2026 go-stormlib Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mpq

import (
	"encoding/binary"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
)

const (
	mpqHashTableIndex = 0x000
	mpqHashNameA      = 0x100
	mpqHashNameB      = 0x200
	mpqHashFileKey    = 0x300
	// mpqStormCryptMix is MPQ_HASH_KEY2_MIX in StormLib: EncryptMpqBlock/DecryptMpqBlock use
	// StormBuffer[0x400+(key&0xFF)] for the key2 stream; table save/load wraps that with BSWAP32.
	mpqStormCryptMix = 0x400
)

type HashEntry struct {
	HashA      uint32
	HashB      uint32
	Locale     uint16
	Platform   uint8
	Flags      uint8
	BlockIndex uint32
}

type BlockEntry struct {
	FilePos          uint32
	CompressedSize   uint32
	UncompressedSize uint32
	Flags            uint32
}

type IndexedFileEntry struct {
	HashIndex  int
	BlockIndex uint32
	Hash       HashEntry
	Block      BlockEntry
}

var (
	cryptTable     [0x500]uint32
	cryptTableOnce sync.Once
)

func LoadHashTable(r io.ReaderAt, fileSize int64, h Header) ([]HashEntry, error) {
	if h.HashTableSize == 0 {
		return []HashEntry{}, nil
	}

	offset, err := hashTableOffset(h)
	if err != nil {
		return nil, err
	}

	tableBytes := uint64(h.HashTableSize) * hashEntrySize
	if tableBytes%4 != 0 {
		return nil, fmt.Errorf("hash table byte size not aligned")
	}

	if offset+tableBytes > uint64(fileSize) {
		return nil, fmt.Errorf("hash table out of range")
	}

	raw := make([]byte, tableBytes)
	if _, err := r.ReadAt(raw, int64(offset)); err != nil {
		return nil, fmt.Errorf("read hash table: %w", err)
	}

	DecryptMpqTableDiskBytes(raw, hashTableKey())

	entries := make([]HashEntry, h.HashTableSize)
	for i := range entries {
		base := i * hashEntrySize
		entries[i] = HashEntry{
			HashA:      binary.LittleEndian.Uint32(raw[base : base+4]),
			HashB:      binary.LittleEndian.Uint32(raw[base+4 : base+8]),
			Locale:     binary.LittleEndian.Uint16(raw[base+8 : base+10]),
			Platform:   raw[base+10],
			Flags:      raw[base+11],
			BlockIndex: binary.LittleEndian.Uint32(raw[base+12 : base+16]),
		}
	}

	return entries, nil
}

func LoadBlockTable(r io.ReaderAt, fileSize int64, h Header) ([]BlockEntry, error) {
	if h.BlockTableSize == 0 {
		return []BlockEntry{}, nil
	}

	offset, err := blockTableOffset(h)
	if err != nil {
		return nil, err
	}

	tableBytes := uint64(h.BlockTableSize) * blockEntrySize
	if tableBytes%4 != 0 {
		return nil, fmt.Errorf("block table byte size not aligned")
	}

	if offset+tableBytes > uint64(fileSize) {
		return nil, fmt.Errorf("block table out of range")
	}

	raw := make([]byte, tableBytes)
	if _, err := r.ReadAt(raw, int64(offset)); err != nil {
		return nil, fmt.Errorf("read block table: %w", err)
	}

	DecryptMpqTableDiskBytes(raw, blockTableKey())

	entries := make([]BlockEntry, h.BlockTableSize)
	for i := range entries {
		base := i * blockEntrySize
		entries[i] = BlockEntry{
			FilePos:          binary.LittleEndian.Uint32(raw[base : base+4]),
			CompressedSize:   binary.LittleEndian.Uint32(raw[base+4 : base+8]),
			UncompressedSize: binary.LittleEndian.Uint32(raw[base+8 : base+12]),
			Flags:            binary.LittleEndian.Uint32(raw[base+12 : base+16]),
		}
	}

	return entries, nil
}

func BuildFileIndex(hashTable []HashEntry, blockTable []BlockEntry) []IndexedFileEntry {
	const (
		hashEntryEmpty   = 0xFFFFFFFF
		hashEntryDeleted = 0xFFFFFFFE
	)

	out := make([]IndexedFileEntry, 0, len(hashTable))
	for i, h := range hashTable {
		if h.BlockIndex == hashEntryEmpty || h.BlockIndex == hashEntryDeleted {
			continue
		}

		if int(h.BlockIndex) >= len(blockTable) {
			continue
		}

		out = append(out, IndexedFileEntry{
			HashIndex:  i,
			BlockIndex: h.BlockIndex,
			Hash:       h,
			Block:      blockTable[h.BlockIndex],
		})
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Hash.HashA != out[j].Hash.HashA {
			return out[i].Hash.HashA < out[j].Hash.HashA
		}

		if out[i].Hash.HashB != out[j].Hash.HashB {
			return out[i].Hash.HashB < out[j].Hash.HashB
		}

		if out[i].Hash.Locale != out[j].Hash.Locale {
			return out[i].Hash.Locale < out[j].Hash.Locale
		}

		if out[i].Hash.Platform != out[j].Hash.Platform {
			return out[i].Hash.Platform < out[j].Hash.Platform
		}

		return out[i].BlockIndex < out[j].BlockIndex
	})

	return out
}

func FindIndexedFileEntry(
	index []IndexedFileEntry,
	hashA, hashB uint32,
	locale uint16,
	platform uint8,
) (IndexedFileEntry, bool) {
	// Exact locale+platform match first.
	for _, e := range index {
		if e.Hash.HashA == hashA && e.Hash.HashB == hashB && e.Hash.Locale == locale &&
			e.Hash.Platform == platform {
			return e, true
		}
	}
	// Locale-only match with neutral platform.
	for _, e := range index {
		if e.Hash.HashA == hashA && e.Hash.HashB == hashB && e.Hash.Locale == locale &&
			e.Hash.Platform == 0 {
			return e, true
		}
	}
	// Language-neutral fallback with platform match.
	for _, e := range index {
		if e.Hash.HashA == hashA && e.Hash.HashB == hashB && e.Hash.Locale == 0 &&
			e.Hash.Platform == platform {
			return e, true
		}
	}
	// Fully neutral fallback.
	for _, e := range index {
		if e.Hash.HashA == hashA && e.Hash.HashB == hashB && e.Hash.Locale == 0 &&
			e.Hash.Platform == 0 {
			return e, true
		}
	}

	return IndexedFileEntry{}, false
}

func NormalizeBlockTableEntries(entries []BlockEntry, fileSize int64, h Header) []BlockEntry {
	out := make([]BlockEntry, len(entries))
	copy(out, entries)

	if fileSize <= 0 {
		return out
	}

	for i := range out {
		start := uint64(h.Offset)
		if h.FormatVersion == 0 {
			start = wrapV1Offset(h.Offset, out[i].FilePos)
		} else {
			start += uint64(out[i].FilePos)
		}

		if start >= uint64(fileSize) {
			out[i].CompressedSize = 0
			out[i].UncompressedSize = 0

			continue
		}

		maxAvail := uint64(fileSize) - start
		if uint64(out[i].CompressedSize) > maxAvail {
			out[i].CompressedSize = uint32(maxAvail)
		}
	}

	return out
}

func hashTableOffset(h Header) (uint64, error) {
	if h.FormatVersion == 0 {
		return wrapV1Offset(h.Offset, h.HashTablePos), nil
	}

	if h.FormatVersion >= 1 {
		return uint64(h.Offset) + makeOffset64(h.HashTablePosHi, h.HashTablePos), nil
	}

	return 0, fmt.Errorf("unsupported format version for hash table offset: %d", h.FormatVersion)
}

func blockTableOffset(h Header) (uint64, error) {
	if h.FormatVersion == 0 {
		return wrapV1Offset(h.Offset, h.BlockTablePos), nil
	}

	if h.FormatVersion >= 1 {
		return uint64(h.Offset) + makeOffset64(h.BlockTablePosHi, h.BlockTablePos), nil
	}

	return 0, fmt.Errorf("unsupported format version for block table offset: %d", h.FormatVersion)
}

func hashTableKey() uint32 {
	return hashString("(hash table)", mpqHashFileKey)
}

func blockTableKey() uint32 {
	return hashString("(block table)", mpqHashFileKey)
}

// HashTableEncryptKey is the Storm SaveMpqTable / LoadMpqTable key for uncompressed on-disk hash tables.
func HashTableEncryptKey() uint32 { return hashTableKey() }

// BlockTableEncryptKey is the encryption key for uncompressed on-disk block tables.
func BlockTableEncryptKey() uint32 { return blockTableKey() }

func NameHashA(name string) uint32 {
	return hashString(name, mpqHashNameA)
}

func NameHashB(name string) uint32 {
	return hashString(name, mpqHashNameB)
}

func NameHashIndex(name string) uint32 {
	return hashString(name, mpqHashTableIndex)
}

func initCryptTable() {
	cryptTableOnce.Do(func() {
		seed := uint32(0x00100001)

		for i := 0; i < 0x100; i++ {
			idx := i

			for j := 0; j < 5; j++ {
				seed = (seed*125 + 3) % 0x2AAAAB
				temp1 := (seed & 0xFFFF) << 16

				seed = (seed*125 + 3) % 0x2AAAAB
				temp2 := seed & 0xFFFF

				cryptTable[idx] = temp1 | temp2
				idx += 0x100
			}
		}
	})
}

func hashString(name string, hashType uint32) uint32 {
	initCryptTable()

	seed1 := uint32(0x7FED7FED)
	seed2 := uint32(0xEEEEEEEE)

	upper := strings.ToUpper(strings.ReplaceAll(name, "/", "\\"))
	for i := 0; i < len(upper); i++ {
		ch := upper[i]
		val := cryptTable[hashType+uint32(ch)]
		seed1 = val ^ (seed1 + seed2)
		seed2 = uint32(ch) + seed1 + seed2 + (seed2 << 5) + 3
	}

	return seed1
}

func mpqDecryptBlockStorm(data []byte, key uint32) {
	initCryptTable()

	seed := uint32(0xEEEEEEEE)
	for i := 0; i+4 <= len(data); i += 4 {
		seed += cryptTable[mpqStormCryptMix+(key&0xFF)]
		value := binary.LittleEndian.Uint32(data[i : i+4])
		out := value ^ (key + seed)
		binary.LittleEndian.PutUint32(data[i:i+4], out)

		key = ((^key << 21) + 0x11111111) | (key >> 11)
		seed = out + seed + (seed << 5) + 3
	}
}

func mpqEncryptBlockStorm(data []byte, key uint32) {
	initCryptTable()

	seed := uint32(0xEEEEEEEE)
	for i := 0; i+4 <= len(data); i += 4 {
		seed += cryptTable[mpqStormCryptMix+(key&0xFF)]
		in := binary.LittleEndian.Uint32(data[i : i+4])
		enc := in ^ (key + seed)
		binary.LittleEndian.PutUint32(data[i:i+4], enc)

		key = ((^key << 21) + 0x11111111) | (key >> 11)
		seed = in + seed + (seed << 5) + 3
	}
}

// DecryptMpqTableDiskBytes reverses Storm LoadMpqTable for an uncompressed encrypted table.
// On STORMLIB_LITTLE_ENDIAN builds, BSWAP_ARRAY32_* around the block cipher is a no-op
// (see StormPort.h); the on-disk transform is DecryptMpqBlock only.
func DecryptMpqTableDiskBytes(data []byte, key uint32) {
	mpqDecryptBlockStorm(data, key)
}

// EncryptMpqTableDiskBytes matches Storm SaveMpqTable on little-endian hosts: EncryptMpqBlock
// only (StormPort.h no-op swaps). Big-endian Storm would prepend/append byte conversion; Go
// targets LE file layout used by typical MPQ tooling.
func EncryptMpqTableDiskBytes(plain []byte, key uint32) {
	mpqEncryptBlockStorm(plain, key)
}
