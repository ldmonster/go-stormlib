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
	"bytes"
	"crypto/md5"
	"fmt"
)

// StormLib defaults for an empty archive (see HASH_TABLE_SIZE_DEFAULT, GetNearestPowerOfTwo).
const (
	DefaultHashTableEntries = 0x1000
	// MPQCreateLeadPadding is the aligned base offset StormLib uses after rounding an empty file up (SFileCreateArchive).
	MPQCreateLeadPadding = 0x200
)

// NearestPowerOfTwoStorm matches DWORD GetNearestPowerOfTwo in StormLib SBaseCommon.cpp
// (including the dwFileCount==0 underflow behavior that yields 0).
func NearestPowerOfTwoStorm(fileCount uint32) uint32 {
	n := fileCount
	n--
	n |= n >> 1
	n |= n >> 2
	n |= n >> 4
	n |= n >> 8
	n |= n >> 16

	return n + 1
}

// HashTableSizeForCreate returns the hash table entry count StormLib would allocate for SFileCreateArchive.
func HashTableSizeForCreate(maxFileCount, reservedSlots uint32) uint32 {
	n := NearestPowerOfTwoStorm(maxFileCount + reservedSlots)
	if n == 0 {
		return DefaultHashTableEntries
	}

	return n
}

// SectorExponentFromSize returns wSectorSize (shift) for power-of-two sector sizes > 0x200, matching GetSectorSizeShift.
func SectorExponentFromSize(sectorSize uint32) uint16 {
	var shift uint16
	for s := sectorSize; s > 0x200; s >>= 1 {
		shift++
	}

	return shift
}

// EmptyArchiveLayout describes the on-disk layout for a minimal empty MPQ matching SFileCreateArchive
// initial header fields (hash table present, block table size 0).
type EmptyArchiveLayout struct {
	MPQOffset      int64
	Header         Header
	HashTableBytes []byte
	FileSize       int64
}

// BuildEmptyArchiveLayout builds header + encrypted hash table bytes (all deleted/empty slots 0xFF).
func BuildEmptyArchiveLayout(
	formatVersion uint16,
	maxFileCount, reservedSlots uint32,
) (EmptyArchiveLayout, error) {
	// Match SFileCreateArchive reserved-file accounting: reserved slots only apply when maxFileCount != 0.
	var reserved uint32
	if maxFileCount != 0 {
		reserved = reservedSlots
	}

	hashN := HashTableSizeForCreate(maxFileCount, reserved)

	hashBytes := make([]byte, int(hashN)*hashEntrySize)
	for i := range hashBytes {
		hashBytes[i] = 0xff
	}

	EncryptMpqTableDiskBytes(hashBytes, hashTableKey())

	sectorSize := uint32(0x1000)

	var headerSize uint32

	switch formatVersion {
	case 0:
		headerSize = headerMinSize
	case 1:
		headerSize = headerSizeV2
	case 2:
		headerSize = headerSizeV3
		sectorSize = 0x4000
	case 3:
		headerSize = headerSizeV4
		sectorSize = 0x4000
	default:
		return EmptyArchiveLayout{}, fmt.Errorf(
			"%w: empty create supports format 0..3 (v1..v4 headers) only",
			ErrUnsupportedFormat,
		)
	}

	secExp := SectorExponentFromSize(sectorSize)

	mpqOff := int64(MPQCreateLeadPadding)
	hashRel := headerSize
	blockRel := hashRel + hashN*hashEntrySize
	archiveSize := headerSize + hashN*hashEntrySize

	h := Header{
		Offset:         mpqOff,
		HeaderSize:     headerSize,
		ArchiveSize32:  archiveSize,
		FormatVersion:  formatVersion,
		SectorSizeExp:  secExp,
		HashTablePos:   hashRel,
		BlockTablePos:  blockRel,
		HashTableSize:  hashN,
		BlockTableSize: 0,
		ArchiveSize64:  uint64(archiveSize),
	}
	if formatVersion >= 3 {
		// v4 validation in open path checks tandem table ranges and header MD5.
		h.HashTableSize64 = uint64(len(hashBytes))
	}

	fileSize := mpqOff + int64(archiveSize)

	return EmptyArchiveLayout{
		MPQOffset:      mpqOff,
		Header:         h,
		HashTableBytes: hashBytes,
		FileSize:       fileSize,
	}, nil
}

// MarshalHeader writes MPQ headers for v1..v4 formats.
func MarshalHeader(h Header) ([]byte, error) {
	n := int(h.HeaderSize)
	if n < headerMinSize || n > headerSizeV4 {
		return nil, fmt.Errorf("unsupported header size for marshal: %d", h.HeaderSize)
	}

	buf := bytes.Repeat([]byte{0}, n)
	binaryPutU32(buf[0:4], idMPQ)
	binaryPutU32(buf[4:8], h.HeaderSize)
	binaryPutU32(buf[8:12], h.ArchiveSize32)
	binaryPutU16(buf[12:14], h.FormatVersion)
	binaryPutU16(buf[14:16], h.SectorSizeExp)
	binaryPutU32(buf[16:20], h.HashTablePos)
	binaryPutU32(buf[20:24], h.BlockTablePos)
	binaryPutU32(buf[24:28], h.HashTableSize)
	binaryPutU32(buf[28:32], h.BlockTableSize)

	if n >= headerSizeV2 {
		binaryPutU64(buf[32:40], h.HiBlockTablePos)
		binaryPutU16(buf[40:42], h.HashTablePosHi)
		binaryPutU16(buf[42:44], h.BlockTablePosHi)
	}

	if n >= headerSizeV3 {
		binaryPutU64(buf[44:52], h.ArchiveSize64)
		binaryPutU64(buf[52:60], h.BetTablePos64)
		binaryPutU64(buf[60:68], h.HetTablePos64)
	}

	if n >= 108 {
		binaryPutU64(buf[68:76], h.HashTableSize64)
		binaryPutU64(buf[76:84], h.BlockTableSize64)
		binaryPutU64(buf[84:92], h.HiBlockSize64)
		binaryPutU64(buf[92:100], h.HetTableSize64)
		binaryPutU64(buf[100:108], h.BetTableSize64)
	}

	if n >= 112 {
		binaryPutU32(buf[108:112], h.RawChunkSize)
	}

	if n >= headerSizeV4 {
		copy(buf[112:128], h.MD5BlockTable[:])
		copy(buf[128:144], h.MD5HashTable[:])
		copy(buf[144:160], h.MD5HiBlockTable[:])
		copy(buf[160:176], h.MD5BetTable[:])
		copy(buf[176:192], h.MD5HetTable[:])
		sum := md5.Sum(buf[0:192])
		copy(buf[192:208], sum[:])
	}

	return buf, nil
}

func binaryPutU32(b []byte, v uint32) {
	_ = b[3]
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
}

func binaryPutU16(b []byte, v uint16) {
	_ = b[1]
	b[0] = byte(v)
	b[1] = byte(v >> 8)
}

func binaryPutU64(b []byte, v uint64) {
	_ = b[7]
	for i := 0; i < 8; i++ {
		b[i] = byte(v >> (8 * i))
	}
}
