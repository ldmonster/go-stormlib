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
	"encoding/binary"
	"io"
	"testing"
)

func TestEncryptMpqTableRoundTrip(t *testing.T) {
	plain := make([]byte, 64)
	for i := range plain {
		plain[i] = byte(i + 1)
	}
	want := append([]byte(nil), plain...)
	key := HashTableEncryptKey()
	buf := append([]byte(nil), plain...)
	EncryptMpqTableDiskBytes(buf, key)
	DecryptMpqTableDiskBytes(buf, key)
	if !bytes.Equal(buf, want) {
		t.Fatalf("round-trip mismatch")
	}
}

func TestLoadHashTable_V1(t *testing.T) {
	data := make([]byte, 0x2000)
	headerOffset := 0x200
	writeHeader(data, headerOffset, 32, 0, 3, 0x400, 0x600, 2, 1)

	plain := make([]byte, 32)
	binary.LittleEndian.PutUint32(plain[0:4], 0xAAAAAAAA)
	binary.LittleEndian.PutUint32(plain[4:8], 0xBBBBBBBB)
	binary.LittleEndian.PutUint16(plain[8:10], 0x0409)
	plain[10] = 0
	plain[11] = 1
	binary.LittleEndian.PutUint32(plain[12:16], 3)
	binary.LittleEndian.PutUint32(plain[16:20], 0x11111111)
	binary.LittleEndian.PutUint32(plain[20:24], 0x22222222)
	binary.LittleEndian.PutUint16(plain[24:26], 0x0410)
	plain[26] = 1
	plain[27] = 0
	binary.LittleEndian.PutUint32(plain[28:32], 5)

	enc := append([]byte(nil), plain...)
	EncryptMpqTableDiskBytes(enc, hashTableKey())
	copy(data[headerOffset+0x400:headerOffset+0x400+len(enc)], enc)

	h, err := FindHeader(data)
	if err != nil {
		t.Fatalf("FindHeader() error = %v", err)
	}
	h = sanitizeAndClampHeaderForValidation(normalizeHeaderForVersion(h), int64(len(data)))
	entries, err := LoadHashTable(bytesReaderAt(data), int64(len(data)), h)
	if err != nil {
		t.Fatalf("LoadHashTable() error = %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("entry count = %d, want 2", len(entries))
	}
	if entries[0].HashA != 0xAAAAAAAA || entries[1].BlockIndex != 5 {
		t.Fatalf("decoded entries mismatch: %#v", entries)
	}
}

func TestLoadHashTable_OutOfRange(t *testing.T) {
	h := Header{
		Offset:        0,
		FormatVersion: 0,
		HashTablePos:  0x1FF0,
		HashTableSize: 4,
	}
	_, err := LoadHashTable(bytesReaderAt(make([]byte, 0x2000)), 0x2000, h)
	if err == nil {
		t.Fatal("expected out-of-range error")
	}
}

func TestLoadHashTable_V2HighWordOffset(t *testing.T) {
	data := make([]byte, 0x4000)
	h := Header{
		Offset:         0,
		FormatVersion:  1,
		HashTablePos:   0x1200,
		HashTablePosHi: 0,
		HashTableSize:  1,
	}

	plain := make([]byte, 16)
	binary.LittleEndian.PutUint32(plain[0:4], 0x13572468)
	EncryptMpqTableDiskBytes(plain, hashTableKey())
	copy(data[0x1200:0x1210], plain)

	entries, err := LoadHashTable(bytesReaderAt(data), int64(len(data)), h)
	if err != nil {
		t.Fatalf("LoadHashTable() error = %v", err)
	}
	if len(entries) != 1 || entries[0].HashA != 0x13572468 {
		t.Fatalf("decoded v2 entry mismatch: %#v", entries)
	}
}

func TestLoadBlockTable_V1(t *testing.T) {
	data := make([]byte, 0x2000)
	headerOffset := 0x200
	writeHeader(data, headerOffset, 32, 0, 3, 0x400, 0x600, 1, 2)

	plain := make([]byte, 32)
	binary.LittleEndian.PutUint32(plain[0:4], 0x1000)
	binary.LittleEndian.PutUint32(plain[4:8], 0x80)
	binary.LittleEndian.PutUint32(plain[8:12], 0x100)
	binary.LittleEndian.PutUint32(plain[12:16], 0x80000100)
	binary.LittleEndian.PutUint32(plain[16:20], 0x2000)
	binary.LittleEndian.PutUint32(plain[20:24], 0x40)
	binary.LittleEndian.PutUint32(plain[24:28], 0x40)
	binary.LittleEndian.PutUint32(plain[28:32], 0x80000100)
	EncryptMpqTableDiskBytes(plain, blockTableKey())
	copy(data[headerOffset+0x600:headerOffset+0x600+len(plain)], plain)

	h, err := FindHeader(data)
	if err != nil {
		t.Fatalf("FindHeader() error = %v", err)
	}
	h = sanitizeAndClampHeaderForValidation(normalizeHeaderForVersion(h), int64(len(data)))
	entries, err := LoadBlockTable(bytesReaderAt(data), int64(len(data)), h)
	if err != nil {
		t.Fatalf("LoadBlockTable() error = %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("entry count = %d, want 2", len(entries))
	}
	if entries[0].FilePos != 0x1000 || entries[1].CompressedSize != 0x40 {
		t.Fatalf("decoded entries mismatch: %#v", entries)
	}
}

func TestLoadBlockTable_OutOfRange(t *testing.T) {
	h := Header{
		Offset:         0,
		FormatVersion:  0,
		BlockTablePos:  0x1FF0,
		BlockTableSize: 4,
	}
	_, err := LoadBlockTable(bytesReaderAt(make([]byte, 0x2000)), 0x2000, h)
	if err == nil {
		t.Fatal("expected out-of-range error")
	}
}

func TestBuildFileIndex(t *testing.T) {
	hashes := []HashEntry{
		{BlockIndex: 0},
		{BlockIndex: 0xFFFFFFFF},
		{BlockIndex: 1},
		{BlockIndex: 42},
	}
	blocks := []BlockEntry{
		{CompressedSize: 10},
		{CompressedSize: 20},
	}
	idx := BuildFileIndex(hashes, blocks)
	if len(idx) != 2 {
		t.Fatalf("index len = %d, want 2", len(idx))
	}
	if idx[0].HashIndex != 0 || idx[1].HashIndex != 2 {
		t.Fatalf("unexpected deterministic index order: %#v", idx)
	}
}

func TestFindIndexedFileEntry_LocalePlatformFallback(t *testing.T) {
	index := []IndexedFileEntry{
		{
			Hash:  HashEntry{HashA: 1, HashB: 2, Locale: 0, Platform: 0},
			Block: BlockEntry{CompressedSize: 1},
		},
		{
			Hash:  HashEntry{HashA: 1, HashB: 2, Locale: 0x0409, Platform: 0},
			Block: BlockEntry{CompressedSize: 2},
		},
		{
			Hash:  HashEntry{HashA: 1, HashB: 2, Locale: 0x0409, Platform: 1},
			Block: BlockEntry{CompressedSize: 3},
		},
	}

	got, ok := FindIndexedFileEntry(index, 1, 2, 0x0409, 1)
	if !ok || got.Block.CompressedSize != 3 {
		t.Fatalf("exact locale/platform match failed: %+v %v", got, ok)
	}
	got, ok = FindIndexedFileEntry(index, 1, 2, 0x0409, 5)
	if !ok || got.Block.CompressedSize != 2 {
		t.Fatalf("locale fallback failed: %+v %v", got, ok)
	}
	got, ok = FindIndexedFileEntry(index, 1, 2, 0x0410, 0)
	if !ok || got.Block.CompressedSize != 1 {
		t.Fatalf("neutral fallback failed: %+v %v", got, ok)
	}
}

func TestFindIndexedFileEntry_DeterministicCollisionTieBreak(t *testing.T) {
	index := BuildFileIndex(
		[]HashEntry{
			{HashA: 7, HashB: 9, Locale: 0x0409, Platform: 0, BlockIndex: 2},
			{HashA: 7, HashB: 9, Locale: 0x0409, Platform: 0, BlockIndex: 1},
		},
		[]BlockEntry{
			{},
			{CompressedSize: 11},
			{CompressedSize: 22},
		},
	)
	got, ok := FindIndexedFileEntry(index, 7, 9, 0x0409, 0)
	if !ok {
		t.Fatal("expected a match")
	}
	if got.Block.CompressedSize != 11 {
		t.Fatalf("unexpected tie-break pick: got %#v", got)
	}
}

func TestNormalizeBlockTableEntries(t *testing.T) {
	h := Header{FormatVersion: 0, Offset: 0x200}
	entries := []BlockEntry{
		{FilePos: 0x100, CompressedSize: 0x80, UncompressedSize: 0x80},
		{FilePos: 0xFFFFFF00, CompressedSize: 0xFFFFFFFF, UncompressedSize: 0x40},
	}
	out := NormalizeBlockTableEntries(entries, 0x1000, h)

	if out[0].CompressedSize != 0x80 {
		t.Fatalf("unexpected non-malformed change: %d", out[0].CompressedSize)
	}
	// Wrapped v1 position may still be openable, but size must be clamped to file bounds.
	if out[1].CompressedSize == 0xFFFFFFFF || out[1].CompressedSize == 0 {
		t.Fatalf("expected clamped wrapped entry size, got %d", out[1].CompressedSize)
	}
}

type bytesReaderAt []byte

func (b bytesReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || int(off) > len(b) {
		return 0, io.EOF
	}
	n := copy(p, b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
