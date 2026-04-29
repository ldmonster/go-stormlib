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

package archive

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/ldmonster/go-stormlib/internal/mpq"
)

func TestReadUncompressedBySectors(t *testing.T) {
	const sectorSize = 512
	payload := []byte("hello world from sector data")
	sectorTable := make([]byte, 8)
	binary.LittleEndian.PutUint32(sectorTable[0:4], 8)
	binary.LittleEndian.PutUint32(sectorTable[4:8], 8+uint32(len(payload)))

	blob := append(sectorTable, payload...)
	out, err := readUncompressedBySectors(bytesReaderAt(blob), 0, uint32(len(blob)), uint32(len(payload)), sectorSize, false, 0, false)
	if err != nil {
		t.Fatalf("readUncompressedBySectors() error = %v", err)
	}
	if string(out) != string(payload) {
		t.Fatalf("payload mismatch: got %q want %q", string(out), string(payload))
	}
}

func TestReadUncompressedBySectors_Bounds(t *testing.T) {
	blob := make([]byte, 16)
	binary.LittleEndian.PutUint32(blob[0:4], 12)
	binary.LittleEndian.PutUint32(blob[4:8], 40) // beyond csize
	_, err := readUncompressedBySectors(bytesReaderAt(blob), 0, uint32(len(blob)), 4, 512, false, 0, false)
	if err == nil {
		t.Fatal("expected bounds error")
	}
}

func TestArchiveOpenIndexedFileAndRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "archive.bin")
	data := make([]byte, 0x1000)
	payload := []byte("single unit payload")
	copy(data[0x200:0x200+len(payload)], payload)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	a := &Archive{
		Path: path,
		Header: mpq.Header{
			FormatVersion: 0,
			Offset:        0,
			SectorSizeExp: 3,
		},
		FileIndex: []mpq.IndexedFileEntry{
			{
				BlockIndex: 0,
				Block: mpq.BlockEntry{
					FilePos:          0x200,
					CompressedSize:   uint32(len(payload)),
					UncompressedSize: uint32(len(payload)),
					Flags:            mpqFileSingleUnit,
				},
			},
		},
	}

	h, err := a.OpenIndexedFile(0)
	if err != nil {
		t.Fatalf("OpenIndexedFile() error = %v", err)
	}
	out, err := a.ReadFile(h)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(out) != string(payload) {
		t.Fatalf("payload mismatch: got %q want %q", string(out), string(payload))
	}
}

func TestOpenIndexedFile_OutOfRange(t *testing.T) {
	a := &Archive{}
	_, err := a.OpenIndexedFile(1)
	if err == nil {
		t.Fatal("expected out-of-range error")
	}
}

func TestOpenIndexedFileByHash_LocalePlatformFallback(t *testing.T) {
	a := &Archive{
		FileIndex: []mpq.IndexedFileEntry{
			{BlockIndex: 0, Hash: mpq.HashEntry{HashA: 1, HashB: 2, Locale: 0, Platform: 0}, Block: mpq.BlockEntry{FilePos: 1}},
			{BlockIndex: 1, Hash: mpq.HashEntry{HashA: 1, HashB: 2, Locale: 0x0409, Platform: 0}, Block: mpq.BlockEntry{FilePos: 2}},
			{BlockIndex: 2, Hash: mpq.HashEntry{HashA: 1, HashB: 2, Locale: 0x0409, Platform: 1}, Block: mpq.BlockEntry{FilePos: 3}},
		},
	}
	h, err := a.OpenIndexedFileByHash(1, 2, 0x0409, 5)
	if err != nil {
		t.Fatalf("OpenIndexedFileByHash() error = %v", err)
	}
	if h.Entry.FilePos != 2 {
		t.Fatalf("fallback selection mismatch: got filePos=%d want=2", h.Entry.FilePos)
	}
}

func TestReadCompressedBySectors_Zlib(t *testing.T) {
	const sectorSize = 512
	payload := bytes.Repeat([]byte("compressed sector payload bytes "), 16)
	compressed := compressZlibForTest(t, payload)
	chunk := append([]byte{mpqCompZlib}, compressed...)
	if len(chunk) >= len(payload) {
		t.Fatalf("test fixture: zlib chunk did not shrink (len=%d payload=%d)", len(chunk), len(payload))
	}
	table := make([]byte, 8)
	binary.LittleEndian.PutUint32(table[0:4], 8)
	binary.LittleEndian.PutUint32(table[4:8], 8+uint32(len(chunk)))
	blob := append(table, chunk...)

	out, err := readCompressedBySectors(bytesReaderAt(blob), 0, uint32(len(blob)), uint32(len(payload)), sectorSize, false, 0, false)
	if err != nil {
		t.Fatalf("readCompressedBySectors() error = %v", err)
	}
	if string(out) != string(payload) {
		t.Fatalf("payload mismatch: got %q want %q", string(out), string(payload))
	}
}

func TestReadCompressedBySectors_ZlibTruncated(t *testing.T) {
	const sectorSize = 512
	payload := bytes.Repeat([]byte("compressed sector payload bytes "), 16)
	compressed := compressZlibForTest(t, payload)
	if len(compressed) > 2 {
		compressed = compressed[:len(compressed)-2]
	}
	chunk := append([]byte{mpqCompZlib}, compressed...)
	table := make([]byte, 8)
	binary.LittleEndian.PutUint32(table[0:4], 8)
	binary.LittleEndian.PutUint32(table[4:8], 8+uint32(len(chunk)))
	blob := append(table, chunk...)

	_, err := readCompressedBySectors(bytesReaderAt(blob), 0, uint32(len(blob)), uint32(len(payload)), sectorSize, false, 0, false)
	if err == nil {
		t.Fatal("expected truncated zlib error")
	}
}

func TestReadCompressedBySectors_CorruptType(t *testing.T) {
	const sectorSize = 512
	// Build a chunk that is shorter than the expected uncompressed size so the
	// reader actually invokes the codec dispatch (raw passthrough is taken when
	// chunk size >= expected).
	payload := []byte("abcdefghijklmnop")
	chunk := []byte{0x7F, 'a', 'b'} // 3 bytes; expected = 16
	table := make([]byte, 8)
	binary.LittleEndian.PutUint32(table[0:4], 8)
	binary.LittleEndian.PutUint32(table[4:8], 8+uint32(len(chunk)))
	blob := append(table, chunk...)
	_, err := readCompressedBySectors(bytesReaderAt(blob), 0, uint32(len(blob)), uint32(len(payload)), sectorSize, false, 0, false)
	if err == nil {
		t.Fatal("expected unsupported compression type error")
	}
}

func TestReadFileData_ZeroSizeReturnsEmpty(t *testing.T) {
	t.Parallel()

	got, err := readFileData(
		bytesReaderAt(nil),
		mpq.Header{SectorSizeExp: 3},
		0,
		0,
		0,
		mpqFileExists,
		"",
	)
	if err != nil {
		t.Fatalf("readFileData() error = %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("readFileData() len = %d, want 0", len(got))
	}
}

type bytesReaderAt []byte

func (b bytesReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || int(off) > len(b) {
		return 0, os.ErrInvalid
	}
	n := copy(p, b[off:])
	if n < len(p) {
		return n, os.ErrInvalid
	}
	return n, nil
}

func compressZlibForTest(t *testing.T, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(payload); err != nil {
		t.Fatalf("zlib write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}
	return buf.Bytes()
}

// TestReadCompressedBySectors_SectorCRC_Valid verifies adler32 sector checksums
// are honored when MPQ_FILE_SECTOR_CRC is set.
func TestReadCompressedBySectors_SectorCRC_Valid(t *testing.T) {
	const sectorSize = 512
	payload := bytes.Repeat([]byte("sector crc payload "), 16)
	compressed := compressZlibForTest(t, payload)
	chunk := append([]byte{mpqCompZlib}, compressed...)

	// Build offset table with hasCRC: sectorCount=1 → 3 entries.
	tableBytes := uint32(12)
	dataOff := tableBytes
	crcOff := dataOff + uint32(len(chunk))
	// Compute adler32 over the chunk (post-decrypt, pre-decompress bytes).
	crcVal := adler32SumForTest(chunk)
	crcRaw := make([]byte, 4)
	binary.LittleEndian.PutUint32(crcRaw, crcVal)
	crcEnd := crcOff + uint32(len(crcRaw))

	table := make([]byte, tableBytes)
	binary.LittleEndian.PutUint32(table[0:4], dataOff)
	binary.LittleEndian.PutUint32(table[4:8], crcOff)
	binary.LittleEndian.PutUint32(table[8:12], crcEnd)

	blob := append([]byte{}, table...)
	blob = append(blob, chunk...)
	blob = append(blob, crcRaw...)

	out, err := readCompressedBySectors(bytesReaderAt(blob), 0, uint32(len(blob)), uint32(len(payload)), sectorSize, false, 0, true)
	if err != nil {
		t.Fatalf("readCompressedBySectors() error = %v", err)
	}
	if !bytes.Equal(out, payload) {
		t.Fatalf("payload mismatch")
	}
}

// TestReadCompressedBySectors_SectorCRC_Mismatch ensures a wrong adler32 is detected.
func TestReadCompressedBySectors_SectorCRC_Mismatch(t *testing.T) {
	const sectorSize = 512
	payload := bytes.Repeat([]byte("sector crc payload "), 16)
	compressed := compressZlibForTest(t, payload)
	chunk := append([]byte{mpqCompZlib}, compressed...)

	tableBytes := uint32(12)
	dataOff := tableBytes
	crcOff := dataOff + uint32(len(chunk))
	crcRaw := []byte{0xAA, 0xBB, 0xCC, 0xDD} // bogus
	crcEnd := crcOff + uint32(len(crcRaw))

	table := make([]byte, tableBytes)
	binary.LittleEndian.PutUint32(table[0:4], dataOff)
	binary.LittleEndian.PutUint32(table[4:8], crcOff)
	binary.LittleEndian.PutUint32(table[8:12], crcEnd)

	blob := append([]byte{}, table...)
	blob = append(blob, chunk...)
	blob = append(blob, crcRaw...)

	_, err := readCompressedBySectors(bytesReaderAt(blob), 0, uint32(len(blob)), uint32(len(payload)), sectorSize, false, 0, true)
	if err == nil {
		t.Fatal("expected sector checksum error")
	}
}

func adler32SumForTest(b []byte) uint32 {
	const mod = 65521
	a, c := uint32(1), uint32(0)
	for _, x := range b {
		a = (a + uint32(x)) % mod
		c = (c + a) % mod
	}
	return (c << 16) | a
}
