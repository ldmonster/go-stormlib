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

package storm

import (
	"bytes"
	"compress/zlib"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"os"
	"path/filepath"
	"testing"

	"github.com/ldmonster/go-stormlib/internal/mpq"
)

func TestOpenCustomMarkerOption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "archive.mpq")
	data := make([]byte, 0x2000)
	customMarker := uint32(0x12345678)
	binary.LittleEndian.PutUint32(data[0:4], customMarker)
	binary.LittleEndian.PutUint32(data[4:8], 32)
	binary.LittleEndian.PutUint32(data[8:12], uint32(len(data)))
	binary.LittleEndian.PutUint16(data[12:14], 0)
	binary.LittleEndian.PutUint16(data[14:16], 3)
	binary.LittleEndian.PutUint32(data[16:20], 0x200)
	binary.LittleEndian.PutUint32(data[20:24], 0x300)
	binary.LittleEndian.PutUint32(data[24:28], 1)
	binary.LittleEndian.PutUint32(data[28:32], 1)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err := Open(path, OpenOptions{MarkerSignature: customMarker})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
}

func TestOpenMapsForeignHeaderErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "foreign.mpq")
	data := make([]byte, 0x2000)
	binary.LittleEndian.PutUint32(data[0:4], 0x1A4B504D)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	_, err := Open(path, OpenOptions{})
	if err == nil {
		t.Fatal("expected unsupported option error")
	}
	if !errors.Is(err, ErrUnsupportedOption) {
		t.Fatalf("error = %v, want %v", err, ErrUnsupportedOption)
	}
}

func TestOpenMapsAviError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "movie.avi")
	data := make([]byte, 0x2000)
	copy(data[0:4], []byte("RIFF"))
	copy(data[8:12], []byte("AVI "))
	copy(data[12:16], []byte("LIST"))
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	_, err := Open(path, OpenOptions{})
	if err == nil {
		t.Fatal("expected avi file error")
	}
	if !errors.Is(err, ErrAviFile) {
		t.Fatalf("error = %v, want %v", err, ErrAviFile)
	}
}

func TestOpenForceMPQV1Option(t *testing.T) {
	path := filepath.Join(t.TempDir(), "force-v1.mpq")
	data := make([]byte, 0x2000)
	writeHeader(data, 0x200, 32, 9, 3, 0x200, 0x300, 1, 1)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	a, err := Open(path, OpenOptions{ForceMPQV1: true})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if a.Header().Version != 0 {
		t.Fatalf("header version = %d, want 0", a.Header().Version)
	}
}

func TestOpenErrorPrecedenceUnsupportedFormatOverForeign(t *testing.T) {
	path := filepath.Join(t.TempDir(), "precedence.mpq")
	data := make([]byte, 0x4000)
	// Non-coercible unsupported candidate first.
	writeHeader(data, 0x200, 32, 9, 3, 0xFFFFF000, 0xFFFFF100, 2, 2)
	// Foreign MPK header later.
	binary.LittleEndian.PutUint32(data[0x800:0x804], 0x1A4B504D)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err := Open(path, OpenOptions{})
	if err == nil {
		t.Fatal("expected open error")
	}
	if !errors.Is(err, ErrUnsupportedMPQ) {
		t.Fatalf("error = %v, want %v", err, ErrUnsupportedMPQ)
	}
}

func TestOpenErrorPrecedenceForeignOverInvalid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "foreign-only.mpq")
	data := make([]byte, 0x2000)
	binary.LittleEndian.PutUint32(data[0:4], 0x1A4B504D)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	_, err := Open(path, OpenOptions{})
	if err == nil {
		t.Fatal("expected open error")
	}
	if !errors.Is(err, ErrUnsupportedOption) {
		t.Fatalf("error = %v, want %v", err, ErrUnsupportedOption)
	}
}

func TestOpenTypedErrorMappingMatrix(t *testing.T) {
	tests := []struct {
		name    string
		build   func([]byte)
		wantErr error
	}{
		{
			name: "header not found maps invalid mpq",
			build: func(data []byte) {
				// keep zeroed data: no MPQ candidates
			},
			wantErr: ErrInvalidMPQ,
		},
		{
			name: "avi maps avi error",
			build: func(data []byte) {
				copy(data[0:4], []byte("RIFF"))
				copy(data[8:12], []byte("AVI "))
				copy(data[12:16], []byte("LIST"))
			},
			wantErr: ErrAviFile,
		},
		{
			name: "unsupported format maps unsupported mpq",
			build: func(data []byte) {
				writeHeader(data, 0x200, 32, 9, 3, 0xFFFFF000, 0xFFFFF100, 2, 2)
			},
			wantErr: ErrUnsupportedMPQ,
		},
		{
			name: "foreign subtype maps unsupported option",
			build: func(data []byte) {
				binary.LittleEndian.PutUint32(data[0:4], 0x1A4B504D)
			},
			wantErr: ErrUnsupportedOption,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "matrix.mpq")
			data := make([]byte, 0x2000)
			tc.build(data)
			if err := os.WriteFile(path, data, 0o644); err != nil {
				t.Fatalf("WriteFile() error = %v", err)
			}
			_, err := Open(path, OpenOptions{})
			if err == nil {
				t.Fatalf("expected error %v", tc.wantErr)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestListFilesFromMaterializedTables(t *testing.T) {
	path := filepath.Join(t.TempDir(), "list.mpq")
	data := make([]byte, 0x3000)
	writeHeader(data, 0x200, 32, 0, 3, 0x400, 0x600, 1, 2)
	// hash table entry -> block index 1
	hashPlain := make([]byte, 16)
	binary.LittleEndian.PutUint32(hashPlain[12:16], 1)
	mpq.EncryptMpqTableDiskBytes(hashPlain, mpq.HashTableEncryptKey())
	copy(data[0x200+0x400:0x200+0x400+len(hashPlain)], hashPlain)
	// block table entries
	blockPlain := make([]byte, 32)
	binary.LittleEndian.PutUint32(blockPlain[0:4], 0x1000)
	binary.LittleEndian.PutUint32(blockPlain[4:8], 0x20)
	binary.LittleEndian.PutUint32(blockPlain[8:12], 0x40)
	binary.LittleEndian.PutUint32(blockPlain[12:16], 0x80000100)
	binary.LittleEndian.PutUint32(blockPlain[16:20], 0x2000)
	binary.LittleEndian.PutUint32(blockPlain[20:24], 0x80)
	binary.LittleEndian.PutUint32(blockPlain[24:28], 0x100)
	binary.LittleEndian.PutUint32(blockPlain[28:32], 0x80000100)
	mpq.EncryptMpqTableDiskBytes(blockPlain, mpq.BlockTableEncryptKey())
	copy(data[0x200+0x600:0x200+0x600+len(blockPlain)], blockPlain)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	a, err := Open(path, OpenOptions{})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	files, err := a.ListFiles()
	if err != nil {
		t.Fatalf("ListFiles() error = %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("file count = %d, want 1", len(files))
	}
	if files[0].CompressedSize != 0x80 || files[0].UnpackedSize != 0x100 {
		t.Fatalf("unexpected file info: %#v", files[0])
	}
	if files[0].Name != "hash_00000000_00000000_loc_0000_plat_00" {
		t.Fatalf("unexpected deterministic fallback name: %q", files[0].Name)
	}
}

func TestListFiles_ListfileResolutionAndDeterministicFallback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "listfile-names.mpq")
	data := make([]byte, 0x6000)
	writeHeader(data, 0x200, 32, 0, 3, 0x400, 0x800, 3, 3)

	named := "maps\\(attributes)"
	namedA, namedB := mpq.NameHashA(named), mpq.NameHashB(named)
	listfileA, listfileB := mpq.NameHashA("(listfile)"), mpq.NameHashB("(listfile)")

	hashPlain := make([]byte, 48)
	// entry 0: named file
	binary.LittleEndian.PutUint32(hashPlain[0:4], namedA)
	binary.LittleEndian.PutUint32(hashPlain[4:8], namedB)
	binary.LittleEndian.PutUint32(hashPlain[12:16], 0)
	// entry 1: unresolved fallback file
	binary.LittleEndian.PutUint32(hashPlain[16:20], 0x11112222)
	binary.LittleEndian.PutUint32(hashPlain[20:24], 0x33334444)
	binary.LittleEndian.PutUint32(hashPlain[28:32], 1)
	// entry 2: (listfile)
	binary.LittleEndian.PutUint32(hashPlain[32:36], listfileA)
	binary.LittleEndian.PutUint32(hashPlain[36:40], listfileB)
	binary.LittleEndian.PutUint32(hashPlain[44:48], 2)
	mpq.EncryptMpqTableDiskBytes(hashPlain, mpq.HashTableEncryptKey())
	copy(data[0x200+0x400:0x200+0x400+len(hashPlain)], hashPlain)

	listfilePayload := []byte(named + "\n(listfile)\n")
	blockPlain := make([]byte, 48)
	// block 0 (named)
	binary.LittleEndian.PutUint32(blockPlain[0:4], 0x1200)
	binary.LittleEndian.PutUint32(blockPlain[4:8], 4)
	binary.LittleEndian.PutUint32(blockPlain[8:12], 4)
	binary.LittleEndian.PutUint32(blockPlain[12:16], 0x01000000)
	// block 1 (fallback)
	binary.LittleEndian.PutUint32(blockPlain[16:20], 0x1300)
	binary.LittleEndian.PutUint32(blockPlain[20:24], 5)
	binary.LittleEndian.PutUint32(blockPlain[24:28], 5)
	binary.LittleEndian.PutUint32(blockPlain[28:32], 0x01000000)
	// block 2 (listfile)
	binary.LittleEndian.PutUint32(blockPlain[32:36], 0x1400)
	binary.LittleEndian.PutUint32(blockPlain[36:40], uint32(len(listfilePayload)))
	binary.LittleEndian.PutUint32(blockPlain[40:44], uint32(len(listfilePayload)))
	binary.LittleEndian.PutUint32(blockPlain[44:48], 0x01000000)
	mpq.EncryptMpqTableDiskBytes(blockPlain, mpq.BlockTableEncryptKey())
	copy(data[0x200+0x800:0x200+0x800+len(blockPlain)], blockPlain)

	copy(data[0x200+0x1200:0x200+0x1204], []byte("FILE"))
	copy(data[0x200+0x1300:0x200+0x1305], []byte("OTHER"))
	copy(data[0x200+0x1400:0x200+0x1400+len(listfilePayload)], listfilePayload)

	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	a, err := Open(path, OpenOptions{})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	files, err := a.ListFiles()
	if err != nil {
		t.Fatalf("ListFiles() error = %v", err)
	}
	if len(files) != 3 {
		t.Fatalf("file count = %d, want 3", len(files))
	}
	if files[0].Name != named {
		t.Fatalf("named file unresolved: got %q want %q", files[0].Name, named)
	}
	if files[1].Name != "hash_11112222_33334444_loc_0000_plat_00" {
		t.Fatalf("unexpected fallback file name: %q", files[1].Name)
	}
	if files[2].Name != "(listfile)" {
		t.Fatalf("listfile should resolve itself, got %q", files[2].Name)
	}
}

func TestReadFileByIndexAndHash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "read.mpq")
	data := make([]byte, 0x4000)
	writeHeader(data, 0x200, 32, 0, 3, 0x400, 0x600, 1, 1)
	payload := []byte("public read payload")
	copy(data[0x200+0x900:0x200+0x900+len(payload)], payload)

	hashPlain := make([]byte, 16)
	binary.LittleEndian.PutUint32(hashPlain[0:4], 0x11223344)
	binary.LittleEndian.PutUint32(hashPlain[4:8], 0x55667788)
	binary.LittleEndian.PutUint16(hashPlain[8:10], 0x0409)
	hashPlain[10] = 0
	hashPlain[11] = 0
	binary.LittleEndian.PutUint32(hashPlain[12:16], 0)
	mpq.EncryptMpqTableDiskBytes(hashPlain, mpq.HashTableEncryptKey())
	copy(data[0x200+0x400:0x200+0x400+len(hashPlain)], hashPlain)

	blockPlain := make([]byte, 16)
	binary.LittleEndian.PutUint32(blockPlain[0:4], 0x900)
	binary.LittleEndian.PutUint32(blockPlain[4:8], uint32(len(payload)))
	binary.LittleEndian.PutUint32(blockPlain[8:12], uint32(len(payload)))
	binary.LittleEndian.PutUint32(blockPlain[12:16], 0x01000000) // single unit
	mpq.EncryptMpqTableDiskBytes(blockPlain, mpq.BlockTableEncryptKey())
	copy(data[0x200+0x600:0x200+0x600+len(blockPlain)], blockPlain)

	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	a, err := Open(path, OpenOptions{})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	byIndex, err := a.ReadFileByIndex(0)
	if err != nil {
		t.Fatalf("ReadFileByIndex() error = %v", err)
	}
	if string(byIndex) != string(payload) {
		t.Fatalf("ReadFileByIndex() mismatch: got %q want %q", string(byIndex), string(payload))
	}
	byHash, err := a.ReadFileByHash(0x11223344, 0x55667788, 0x0409, 0)
	if err != nil {
		t.Fatalf("ReadFileByHash() error = %v", err)
	}
	if string(byHash) != string(payload) {
		t.Fatalf("ReadFileByHash() mismatch: got %q want %q", string(byHash), string(payload))
	}
}

func TestReadFileByHash_LocaleFallback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "read-locale.mpq")
	data := make([]byte, 0x5000)
	writeHeader(data, 0x200, 32, 0, 3, 0x400, 0x600, 2, 2)

	payloadNeutral := []byte("neutral payload")
	payloadLocale := []byte("locale payload")
	copy(data[0x200+0x900:0x200+0x900+len(payloadNeutral)], payloadNeutral)
	copy(data[0x200+0xA00:0x200+0xA00+len(payloadLocale)], payloadLocale)

	hashPlain := make([]byte, 32)
	// entry 0: neutral locale/platform
	binary.LittleEndian.PutUint32(hashPlain[0:4], 0xCAFEBABE)
	binary.LittleEndian.PutUint32(hashPlain[4:8], 0xDEADBEEF)
	binary.LittleEndian.PutUint16(hashPlain[8:10], 0x0000)
	hashPlain[10] = 0
	hashPlain[11] = 0
	binary.LittleEndian.PutUint32(hashPlain[12:16], 0)
	// entry 1: locale-specific
	binary.LittleEndian.PutUint32(hashPlain[16:20], 0xCAFEBABE)
	binary.LittleEndian.PutUint32(hashPlain[20:24], 0xDEADBEEF)
	binary.LittleEndian.PutUint16(hashPlain[24:26], 0x0409)
	hashPlain[26] = 0
	hashPlain[27] = 0
	binary.LittleEndian.PutUint32(hashPlain[28:32], 1)
	mpq.EncryptMpqTableDiskBytes(hashPlain, mpq.HashTableEncryptKey())
	copy(data[0x200+0x400:0x200+0x400+len(hashPlain)], hashPlain)

	blockPlain := make([]byte, 32)
	binary.LittleEndian.PutUint32(blockPlain[0:4], 0x900)
	binary.LittleEndian.PutUint32(blockPlain[4:8], uint32(len(payloadNeutral)))
	binary.LittleEndian.PutUint32(blockPlain[8:12], uint32(len(payloadNeutral)))
	binary.LittleEndian.PutUint32(blockPlain[12:16], 0x01000000)
	binary.LittleEndian.PutUint32(blockPlain[16:20], 0xA00)
	binary.LittleEndian.PutUint32(blockPlain[20:24], uint32(len(payloadLocale)))
	binary.LittleEndian.PutUint32(blockPlain[24:28], uint32(len(payloadLocale)))
	binary.LittleEndian.PutUint32(blockPlain[28:32], 0x01000000)
	mpq.EncryptMpqTableDiskBytes(blockPlain, mpq.BlockTableEncryptKey())
	copy(data[0x200+0x600:0x200+0x600+len(blockPlain)], blockPlain)

	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	a, err := Open(path, OpenOptions{})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	localeHit, err := a.ReadFileByHash(0xCAFEBABE, 0xDEADBEEF, 0x0409, 0)
	if err != nil {
		t.Fatalf("ReadFileByHash(locale) error = %v", err)
	}
	if string(localeHit) != string(payloadLocale) {
		t.Fatalf("locale-specific read mismatch: got %q want %q", string(localeHit), string(payloadLocale))
	}
	fallbackHit, err := a.ReadFileByHash(0xCAFEBABE, 0xDEADBEEF, 0x0410, 0)
	if err != nil {
		t.Fatalf("ReadFileByHash(fallback) error = %v", err)
	}
	if string(fallbackHit) != string(payloadNeutral) {
		t.Fatalf("neutral fallback read mismatch: got %q want %q", string(fallbackHit), string(payloadNeutral))
	}
}

func TestReadFileTypedErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "typed-errors.mpq")
	data := make([]byte, 0x3000)
	writeHeader(data, 0x200, 32, 0, 3, 0x400, 0x600, 1, 1)

	hashPlain := make([]byte, 16)
	binary.LittleEndian.PutUint32(hashPlain[0:4], 0xAAAABBBB)
	binary.LittleEndian.PutUint32(hashPlain[4:8], 0xCCCCDDDD)
	binary.LittleEndian.PutUint32(hashPlain[12:16], 0)
	mpq.EncryptMpqTableDiskBytes(hashPlain, mpq.HashTableEncryptKey())
	copy(data[0x200+0x400:0x200+0x400+len(hashPlain)], hashPlain)

	corruptCompressed := []byte{0x02, 0x01, 0x02, 0x03} // zlib tag with invalid payload
	blockPlain := make([]byte, 16)
	binary.LittleEndian.PutUint32(blockPlain[0:4], 0x900)
	binary.LittleEndian.PutUint32(blockPlain[4:8], uint32(len(corruptCompressed)))
	binary.LittleEndian.PutUint32(blockPlain[8:12], 16)
	binary.LittleEndian.PutUint32(blockPlain[12:16], 0x01000200) // single-unit + compressed
	mpq.EncryptMpqTableDiskBytes(blockPlain, mpq.BlockTableEncryptKey())
	copy(data[0x200+0x600:0x200+0x600+len(blockPlain)], blockPlain)
	copy(data[0x200+0x900:0x200+0x900+len(corruptCompressed)], corruptCompressed)

	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	a, err := Open(path, OpenOptions{})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if _, err := a.ReadFileByIndex(99); !errors.Is(err, ErrOutOfRange) {
		t.Fatalf("ReadFileByIndex out-of-range error = %v, want %v", err, ErrOutOfRange)
	}
	if _, err := a.ReadFileByHash(1, 2, 0, 0); !errors.Is(err, ErrFileNotFound) {
		t.Fatalf("ReadFileByHash missing error = %v, want %v", err, ErrFileNotFound)
	}
	if _, err := a.ReadFileByIndex(0); !errors.Is(err, ErrDecodeFailed) {
		t.Fatalf("ReadFileByIndex decode error = %v, want %v", err, ErrDecodeFailed)
	}
}

func TestReadFileCompressedPublicPaths(t *testing.T) {
	path := filepath.Join(t.TempDir(), "compressed-public.mpq")
	data := make([]byte, 0x6000)
	writeHeader(data, 0x200, 32, 0, 3, 0x400, 0x700, 2, 2)

	singlePayload := []byte("single-unit-zlib")
	var singleBuf bytes.Buffer
	zw1 := zlib.NewWriter(&singleBuf)
	if _, err := zw1.Write(singlePayload); err != nil {
		t.Fatalf("zlib write single payload: %v", err)
	}
	if err := zw1.Close(); err != nil {
		t.Fatalf("zlib close single payload: %v", err)
	}
	singleChunk := append([]byte{0x02}, singleBuf.Bytes()...)

	sectorPayload := bytes.Repeat([]byte("sector-zlib-payload-aaaaaaaaaa"), 8)
	var sectorBuf bytes.Buffer
	zw2 := zlib.NewWriter(&sectorBuf)
	if _, err := zw2.Write(sectorPayload); err != nil {
		t.Fatalf("zlib write sector payload: %v", err)
	}
	if err := zw2.Close(); err != nil {
		t.Fatalf("zlib close sector payload: %v", err)
	}
	sectorChunk := append([]byte{0x02}, sectorBuf.Bytes()...)
	sectorTable := make([]byte, 8)
	binary.LittleEndian.PutUint32(sectorTable[0:4], 8)
	binary.LittleEndian.PutUint32(sectorTable[4:8], uint32(8+len(sectorChunk)))

	hashPlain := make([]byte, 32)
	binary.LittleEndian.PutUint32(hashPlain[0:4], 0x10000001)
	binary.LittleEndian.PutUint32(hashPlain[4:8], 0x20000001)
	binary.LittleEndian.PutUint32(hashPlain[12:16], 0)
	binary.LittleEndian.PutUint32(hashPlain[16:20], 0x10000002)
	binary.LittleEndian.PutUint32(hashPlain[20:24], 0x20000002)
	binary.LittleEndian.PutUint32(hashPlain[28:32], 1)
	mpq.EncryptMpqTableDiskBytes(hashPlain, mpq.HashTableEncryptKey())
	copy(data[0x200+0x400:0x200+0x400+len(hashPlain)], hashPlain)

	blockPlain := make([]byte, 32)
	binary.LittleEndian.PutUint32(blockPlain[0:4], 0x1000)
	binary.LittleEndian.PutUint32(blockPlain[4:8], uint32(len(singleChunk)))
	binary.LittleEndian.PutUint32(blockPlain[8:12], uint32(len(singlePayload)))
	binary.LittleEndian.PutUint32(blockPlain[12:16], 0x01000200)
	binary.LittleEndian.PutUint32(blockPlain[16:20], 0x1200)
	binary.LittleEndian.PutUint32(blockPlain[20:24], uint32(len(sectorTable)+len(sectorChunk)))
	binary.LittleEndian.PutUint32(blockPlain[24:28], uint32(len(sectorPayload)))
	binary.LittleEndian.PutUint32(blockPlain[28:32], 0x00000200)
	mpq.EncryptMpqTableDiskBytes(blockPlain, mpq.BlockTableEncryptKey())
	copy(data[0x200+0x700:0x200+0x700+len(blockPlain)], blockPlain)

	copy(data[0x200+0x1000:0x200+0x1000+len(singleChunk)], singleChunk)
	copy(data[0x200+0x1200:0x200+0x1200+len(sectorTable)], sectorTable)
	copy(data[0x200+0x1200+len(sectorTable):0x200+0x1200+len(sectorTable)+len(sectorChunk)], sectorChunk)

	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	a, err := Open(path, OpenOptions{})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	gotSingle, err := a.ReadFileByHash(0x10000001, 0x20000001, 0, 0)
	if err != nil {
		t.Fatalf("ReadFileByHash(single compressed) error = %v", err)
	}
	if string(gotSingle) != string(singlePayload) {
		t.Fatalf("single compressed payload mismatch: got %q want %q", string(gotSingle), string(singlePayload))
	}
	gotSector, err := a.ReadFileByHash(0x10000002, 0x20000002, 0, 0)
	if err != nil {
		t.Fatalf("ReadFileByHash(sector compressed) error = %v", err)
	}
	if string(gotSector) != string(sectorPayload) {
		t.Fatalf("sector compressed payload mismatch: got %q want %q", string(gotSector), string(sectorPayload))
	}
}

func TestNormalizationOpenReadFlows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "normalized-read.mpq")
	data := make([]byte, 0x5000)
	writeHeader(data, 0x200, 32, 0, 3, 0x400, 0x700, 2, 2)

	clampedPayload := []byte("normalized-clamped-read")
	copy(data[0x200+0x1100:0x200+0x1100+len(clampedPayload)], clampedPayload)

	hashPlain := make([]byte, 32)
	// Entry 0: oversized compressed size, should be clamped and still readable.
	binary.LittleEndian.PutUint32(hashPlain[0:4], 0xABCD0001)
	binary.LittleEndian.PutUint32(hashPlain[4:8], 0xEF010001)
	binary.LittleEndian.PutUint32(hashPlain[12:16], 0)
	// Entry 1: out-of-file block pos, should be zero-normalized to empty payload.
	binary.LittleEndian.PutUint32(hashPlain[16:20], 0xABCD0002)
	binary.LittleEndian.PutUint32(hashPlain[20:24], 0xEF010002)
	binary.LittleEndian.PutUint32(hashPlain[28:32], 1)
	mpq.EncryptMpqTableDiskBytes(hashPlain, mpq.HashTableEncryptKey())
	copy(data[0x200+0x400:0x200+0x400+len(hashPlain)], hashPlain)

	blockPlain := make([]byte, 32)
	// Block 0: csize deliberately oversized; fsize remains valid.
	binary.LittleEndian.PutUint32(blockPlain[0:4], 0x1100)
	binary.LittleEndian.PutUint32(blockPlain[4:8], 0xFFFFFFFF)
	binary.LittleEndian.PutUint32(blockPlain[8:12], uint32(len(clampedPayload)))
	binary.LittleEndian.PutUint32(blockPlain[12:16], 0x01000000)
	// Block 1: beyond file bounds, should normalize to zero-size.
	binary.LittleEndian.PutUint32(blockPlain[16:20], 0x00010000)
	binary.LittleEndian.PutUint32(blockPlain[20:24], 0x40)
	binary.LittleEndian.PutUint32(blockPlain[24:28], 0x40)
	binary.LittleEndian.PutUint32(blockPlain[28:32], 0x01000000)
	mpq.EncryptMpqTableDiskBytes(blockPlain, mpq.BlockTableEncryptKey())
	copy(data[0x200+0x700:0x200+0x700+len(blockPlain)], blockPlain)

	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	a, err := Open(path, OpenOptions{})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	got, err := a.ReadFileByHash(0xABCD0001, 0xEF010001, 0, 0)
	if err != nil {
		t.Fatalf("ReadFileByHash(clamped) error = %v", err)
	}
	if string(got) != string(clampedPayload) {
		t.Fatalf("clamped read mismatch: got %q want %q", string(got), string(clampedPayload))
	}

	gotZero, err := a.ReadFileByHash(0xABCD0002, 0xEF010002, 0, 0)
	if err != nil {
		t.Fatalf("ReadFileByHash(zero-normalized) error = %v", err)
	}
	if len(gotZero) != 0 {
		t.Fatalf("zero-normalized read should be empty, got %d bytes", len(gotZero))
	}
}

func TestReadFileByName_EncryptedReadByNameSucceeds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enc-name-read.mpq")
	data := make([]byte, 0x5000)
	writeHeader(data, 0x200, 32, 0, 3, 0x400, 0x700, 1, 1)

	name := `secret\loot.bin`
	payload := []byte("gold and wood")
	filePos := uint32(0x1100)
	key := mpq.DecryptFileKey(name, uint64(filePos), uint32(len(payload)), mpq.FileFlagEncrypted)
	onDisk := append([]byte(nil), payload...)
	mpq.EncryptMpqFileBytes(onDisk, key)
	copy(data[0x200+filePos:0x200+filePos+uint32(len(onDisk))], onDisk)

	hashPlain := make([]byte, 16)
	binary.LittleEndian.PutUint32(hashPlain[0:4], mpq.NameHashA(name))
	binary.LittleEndian.PutUint32(hashPlain[4:8], mpq.NameHashB(name))
	binary.LittleEndian.PutUint32(hashPlain[12:16], 0)
	mpq.EncryptMpqTableDiskBytes(hashPlain, mpq.HashTableEncryptKey())
	copy(data[0x200+0x400:0x200+0x400+len(hashPlain)], hashPlain)

	flags := uint32(0x01000000 | mpq.FileFlagEncrypted)
	blockPlain := make([]byte, 16)
	binary.LittleEndian.PutUint32(blockPlain[0:4], filePos)
	binary.LittleEndian.PutUint32(blockPlain[4:8], uint32(len(onDisk)))
	binary.LittleEndian.PutUint32(blockPlain[8:12], uint32(len(payload)))
	binary.LittleEndian.PutUint32(blockPlain[12:16], flags)
	mpq.EncryptMpqTableDiskBytes(blockPlain, mpq.BlockTableEncryptKey())
	copy(data[0x200+0x700:0x200+0x700+len(blockPlain)], blockPlain)

	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	a, err := Open(path, OpenOptions{})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	got, err := a.ReadFileByName(name, 0, 0)
	if err != nil {
		t.Fatalf("ReadFileByName() error = %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("got %q want %q", got, payload)
	}
}

func TestReadFileByHash_EncryptedNeedsNameError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enc-hash.mpq")
	data := make([]byte, 0x5000)
	writeHeader(data, 0x200, 32, 0, 3, 0x400, 0x700, 1, 1)

	name := `hidden.dat`
	payload := []byte("secret")
	filePos := uint32(0x1100)
	key := mpq.DecryptFileKey(name, uint64(filePos), uint32(len(payload)), mpq.FileFlagEncrypted)
	onDisk := append([]byte(nil), payload...)
	mpq.EncryptMpqFileBytes(onDisk, key)
	copy(data[0x200+filePos:0x200+filePos+uint32(len(onDisk))], onDisk)

	ha, hb := mpq.NameHashA(name), mpq.NameHashB(name)
	hashPlain := make([]byte, 16)
	binary.LittleEndian.PutUint32(hashPlain[0:4], ha)
	binary.LittleEndian.PutUint32(hashPlain[4:8], hb)
	binary.LittleEndian.PutUint32(hashPlain[12:16], 0)
	mpq.EncryptMpqTableDiskBytes(hashPlain, mpq.HashTableEncryptKey())
	copy(data[0x200+0x400:0x200+0x400+len(hashPlain)], hashPlain)

	flags := uint32(0x01000000 | mpq.FileFlagEncrypted)
	blockPlain := make([]byte, 16)
	binary.LittleEndian.PutUint32(blockPlain[0:4], filePos)
	binary.LittleEndian.PutUint32(blockPlain[4:8], uint32(len(onDisk)))
	binary.LittleEndian.PutUint32(blockPlain[8:12], uint32(len(payload)))
	binary.LittleEndian.PutUint32(blockPlain[12:16], flags)
	mpq.EncryptMpqTableDiskBytes(blockPlain, mpq.BlockTableEncryptKey())
	copy(data[0x200+0x700:0x200+0x700+len(blockPlain)], blockPlain)

	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	a, err := Open(path, OpenOptions{})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	_, err = a.ReadFileByHash(ha, hb, 0, 0)
	if err == nil || !errors.Is(err, ErrEncryptedFileNeedsName) {
		t.Fatalf("ReadFileByHash() error = %v, want %v", err, ErrEncryptedFileNeedsName)
	}
}

func TestNameBasedReadAndMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "name-based.mpq")
	data := make([]byte, 0x6000)
	writeHeader(data, 0x200, 32, 0, 3, 0x400, 0x700, 2, 2)

	name := "units\\human\\footman.txt"
	payload := []byte("footman-stats")
	copy(data[0x200+0x1000:0x200+0x1000+len(payload)], payload)

	hashPlain := make([]byte, 32)
	binary.LittleEndian.PutUint32(hashPlain[0:4], mpq.NameHashA(name))
	binary.LittleEndian.PutUint32(hashPlain[4:8], mpq.NameHashB(name))
	binary.LittleEndian.PutUint32(hashPlain[12:16], 0)
	binary.LittleEndian.PutUint32(hashPlain[16:20], 0x01020304)
	binary.LittleEndian.PutUint32(hashPlain[20:24], 0x05060708)
	binary.LittleEndian.PutUint32(hashPlain[28:32], 1)
	mpq.EncryptMpqTableDiskBytes(hashPlain, mpq.HashTableEncryptKey())
	copy(data[0x200+0x400:0x200+0x400+len(hashPlain)], hashPlain)

	blockPlain := make([]byte, 32)
	binary.LittleEndian.PutUint32(blockPlain[0:4], 0x1000)
	binary.LittleEndian.PutUint32(blockPlain[4:8], uint32(len(payload)))
	binary.LittleEndian.PutUint32(blockPlain[8:12], uint32(len(payload)))
	binary.LittleEndian.PutUint32(blockPlain[12:16], 0x01000000)
	mpq.EncryptMpqTableDiskBytes(blockPlain, mpq.BlockTableEncryptKey())
	copy(data[0x200+0x700:0x200+0x700+len(blockPlain)], blockPlain)

	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	a, err := Open(path, OpenOptions{})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if !a.HasFile(name, 0, 0) {
		t.Fatalf("HasFile(%q) = false, want true", name)
	}
	got, err := a.ReadFileByName(name, 0, 0)
	if err != nil {
		t.Fatalf("ReadFileByName() error = %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("ReadFileByName() mismatch: got %q want %q", string(got), string(payload))
	}
	info, err := a.FileInfoByName(name, 0, 0)
	if err != nil {
		t.Fatalf("FileInfoByName() error = %v", err)
	}
	if info.CompressedSize != uint32(len(payload)) || info.UnpackedSize != uint32(len(payload)) {
		t.Fatalf("FileInfoByName() sizes mismatch: %#v", info)
	}
	if a.HasFile("missing.txt", 0, 0) {
		t.Fatalf("HasFile(missing) = true, want false")
	}
}

func TestGetFileChecksumsByName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "checksums.mpq")
	data := make([]byte, 0x5000)
	writeHeader(data, 0x200, 32, 0, 3, 0x400, 0x700, 1, 1)

	name := "scripts\\common.j"
	payload := []byte("function main takes nothing returns nothing")
	copy(data[0x200+0x1000:0x200+0x1000+len(payload)], payload)

	hashPlain := make([]byte, 16)
	binary.LittleEndian.PutUint32(hashPlain[0:4], mpq.NameHashA(name))
	binary.LittleEndian.PutUint32(hashPlain[4:8], mpq.NameHashB(name))
	binary.LittleEndian.PutUint32(hashPlain[12:16], 0)
	mpq.EncryptMpqTableDiskBytes(hashPlain, mpq.HashTableEncryptKey())
	copy(data[0x200+0x400:0x200+0x400+len(hashPlain)], hashPlain)

	blockPlain := make([]byte, 16)
	binary.LittleEndian.PutUint32(blockPlain[0:4], 0x1000)
	binary.LittleEndian.PutUint32(blockPlain[4:8], uint32(len(payload)))
	binary.LittleEndian.PutUint32(blockPlain[8:12], uint32(len(payload)))
	binary.LittleEndian.PutUint32(blockPlain[12:16], 0x01000000)
	mpq.EncryptMpqTableDiskBytes(blockPlain, mpq.BlockTableEncryptKey())
	copy(data[0x200+0x700:0x200+0x700+len(blockPlain)], blockPlain)

	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	a, err := Open(path, OpenOptions{})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	gotCRC, gotMD5, err := a.GetFileChecksumsByName(name, 0, 0)
	if err != nil {
		t.Fatalf("GetFileChecksumsByName() error = %v", err)
	}
	if gotCRC != crc32.ChecksumIEEE(payload) {
		t.Fatalf("crc mismatch: got %08x want %08x", gotCRC, crc32.ChecksumIEEE(payload))
	}
	if gotMD5 != md5.Sum(payload) {
		t.Fatalf("md5 mismatch")
	}
}

func TestVerifyFileChecksumByName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "verify-checksum.mpq")
	data := make([]byte, 0x5000)
	writeHeader(data, 0x200, 32, 0, 3, 0x400, 0x700, 1, 1)

	name := "signature\\placeholder.bin"
	payload := []byte("checksum-verification")
	copy(data[0x200+0x1000:0x200+0x1000+len(payload)], payload)

	hashPlain := make([]byte, 16)
	binary.LittleEndian.PutUint32(hashPlain[0:4], mpq.NameHashA(name))
	binary.LittleEndian.PutUint32(hashPlain[4:8], mpq.NameHashB(name))
	binary.LittleEndian.PutUint32(hashPlain[12:16], 0)
	mpq.EncryptMpqTableDiskBytes(hashPlain, mpq.HashTableEncryptKey())
	copy(data[0x200+0x400:0x200+0x400+len(hashPlain)], hashPlain)

	blockPlain := make([]byte, 16)
	binary.LittleEndian.PutUint32(blockPlain[0:4], 0x1000)
	binary.LittleEndian.PutUint32(blockPlain[4:8], uint32(len(payload)))
	binary.LittleEndian.PutUint32(blockPlain[8:12], uint32(len(payload)))
	binary.LittleEndian.PutUint32(blockPlain[12:16], 0x01000000)
	mpq.EncryptMpqTableDiskBytes(blockPlain, mpq.BlockTableEncryptKey())
	copy(data[0x200+0x700:0x200+0x700+len(blockPlain)], blockPlain)

	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	a, err := Open(path, OpenOptions{})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	ok, err := a.VerifyFileChecksumByName(name, 0, 0, crc32.ChecksumIEEE(payload), md5.Sum(payload))
	if err != nil {
		t.Fatalf("VerifyFileChecksumByName() error = %v", err)
	}
	if !ok {
		t.Fatal("VerifyFileChecksumByName() = false, want true")
	}
}

func TestMutationAndPatchMethodsReturnUnsupported(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "unsupported-mutation.mpq")
	data := make([]byte, 0x2000)
	writeHeader(data, 0x200, 32, 0, 3, 0x400, 0x600, 1, 1)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	a, err := Open(path, OpenOptions{})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if err := a.Flush(); err != nil {
		t.Fatalf("Flush() error = %v, want nil", err)
	}
	if err := a.RemoveFile("x", 0, 0); !errors.Is(err, ErrFileNotFound) {
		t.Fatalf("RemoveFile() error = %v, want %v", err, ErrFileNotFound)
	}
	if err := a.RenameFile("a", "b", 0, 0); !errors.Is(err, ErrFileNotFound) {
		t.Fatalf("RenameFile() error = %v, want %v", err, ErrFileNotFound)
	}
	if err := a.Compact(); err != nil {
		t.Fatalf("Compact() error = %v, want nil (compaction now supported)", err)
	}
	patchPath := filepath.Join(dir, "patch.mpq")
	patchData := make([]byte, 0x2000)
	writeHeader(patchData, 0x200, 32, 0, 3, 0x400, 0x600, 1, 1)
	if err := os.WriteFile(patchPath, patchData, 0o644); err != nil {
		t.Fatalf("WriteFile(patch) error = %v", err)
	}
	if err := a.OpenPatchArchive(patchPath, "", 0); err != nil {
		t.Fatalf("OpenPatchArchive() error = %v, want nil", err)
	}
	patch2Path := filepath.Join(dir, "patch2.mpq")
	if err := os.WriteFile(patch2Path, patchData, 0o644); err != nil {
		t.Fatalf("WriteFile(patch2) error = %v", err)
	}
	if err := a.OpenPatchArchive(patch2Path, "", 0); err != nil {
		t.Fatalf("OpenPatchArchive(second) error = %v, want nil", err)
	}
	patched, err := a.IsPatchedArchive()
	if err != nil {
		t.Fatalf("IsPatchedArchive() error = %v, want nil", err)
	}
	if !patched {
		t.Fatalf("IsPatchedArchive() = false, want true")
	}
	if err := a.SignArchive(0); !errors.Is(err, ErrUnsupportedFeature) {
		t.Fatalf("SignArchive() error = %v, want %v", err, ErrUnsupportedFeature)
	}
}

func TestCreateOpenFlushRoundTrip_V1AndV2(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		version uint32
		wantHV  uint16 // storm Header().Version reflects mpq.Header.FormatVersion
		wantHS  uint32
	}{
		{"v1_header", 0, 0, 32},
		{"v2_header", 1, 1, 44},
		{"v3_header", 2, 2, 68},
		{"v4_header", 3, 3, 208},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := filepath.Join(t.TempDir(), tc.name+".mpq")
			a, err := Create(p, CreateOptions{ArchiveVersion: tc.version, MaxFileCount: 0})
			if err != nil {
				t.Fatalf("Create() error = %v", err)
			}
			if err := a.Flush(); err != nil {
				t.Fatalf("Flush() error = %v", err)
			}
			if err := a.Close(); err != nil {
				t.Fatalf("Close() error = %v", err)
			}
			a2, err := Open(p, OpenOptions{})
			if err != nil {
				t.Fatalf("Open() after create error = %v", err)
			}
			h := a2.Header()
			if h.Version != tc.wantHV {
				t.Fatalf("Header().Version = %d, want %d", h.Version, tc.wantHV)
			}
			if h.HeaderSize != tc.wantHS {
				t.Fatalf("Header().HeaderSize = %d, want %d", h.HeaderSize, tc.wantHS)
			}
			if err := a2.Close(); err != nil {
				t.Fatalf("Close() error = %v", err)
			}
		})
	}
}

func TestCreateRejectsUnsupportedVersion(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.mpq")
	_, err := Create(p, CreateOptions{ArchiveVersion: 4, MaxFileCount: 0})
	if !errors.Is(err, ErrUnsupportedMPQ) {
		t.Fatalf("Create() error = %v, want %v", err, ErrUnsupportedMPQ)
	}
}

func TestCreate_WithReservedSlots_HashTableSizing(t *testing.T) {
	t.Parallel()
	p := filepath.Join(t.TempDir(), "reserved-create.mpq")
	const maxFiles uint32 = 80
	const reserved uint32 = 5
	wantN := mpq.HashTableSizeForCreate(maxFiles, reserved)
	a, err := Create(p, CreateOptions{ArchiveVersion: 0, MaxFileCount: maxFiles, ReservedSlots: reserved})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	defer a.Close()
	if a.Header().HashTableSize != wantN {
		t.Fatalf("HashTableSize = %d, want %d", a.Header().HashTableSize, wantN)
	}
}

func TestCreate_WithInternalReservationFlags_HashTableSizing(t *testing.T) {
	t.Parallel()
	p := filepath.Join(t.TempDir(), "reserved-flags-create.mpq")
	const maxFiles uint32 = 80
	wantN := mpq.HashTableSizeForCreate(maxFiles, 3)
	a, err := Create(p, CreateOptions{
		ArchiveVersion:    0,
		MaxFileCount:      maxFiles,
		ReserveListfile:   true,
		ReserveAttributes: true,
		ReserveSignature:  true,
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	defer a.Close()
	if a.Header().HashTableSize != wantN {
		t.Fatalf("HashTableSize = %d, want %d", a.Header().HashTableSize, wantN)
	}
}

func TestCreateWithFlags_CreateMatrixReservationParity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		flags        uint32
		maxFileCount uint32
		wantVersion  uint16
		wantReserved uint32
	}{
		{
			name:         "v1_no_internal_flags_still_reserves_listfile",
			flags:        0,
			maxFileCount: 32,
			wantVersion:  0,
			wantReserved: 1,
		},
		{
			name:         "v2_attributes_reserves_two",
			flags:        CreateFlagArchiveV2 | CreateFlagAttributes,
			maxFileCount: 32,
			wantVersion:  1,
			wantReserved: 2,
		},
		{
			name:         "v3_signature_reserves_two",
			flags:        CreateFlagArchiveV3 | CreateFlagSignature,
			maxFileCount: 32,
			wantVersion:  2,
			wantReserved: 2,
		},
		{
			name:         "v4_all_internal_flags_reserve_three",
			flags:        CreateFlagArchiveV4 | CreateFlagListfile | CreateFlagAttributes | CreateFlagSignature,
			maxFileCount: 32,
			wantVersion:  3,
			wantReserved: 3,
		},
		{
			name:         "max_file_count_zero_uses_default_hash_size",
			flags:        CreateFlagArchiveV4 | CreateFlagAttributes | CreateFlagSignature,
			maxFileCount: 0,
			wantVersion:  3,
			wantReserved: 3,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := filepath.Join(t.TempDir(), tc.name+".mpq")
			a, err := CreateWithFlags(p, tc.flags, tc.maxFileCount)
			if err != nil {
				t.Fatalf("CreateWithFlags() error = %v", err)
			}
			defer a.Close()

			if got := a.Header().Version; got != tc.wantVersion {
				t.Fatalf("Header().Version = %d, want %d", got, tc.wantVersion)
			}

			var wantHashSize uint32 = mpq.DefaultHashTableEntries
			if tc.maxFileCount != 0 {
				wantHashSize = mpq.HashTableSizeForCreate(tc.maxFileCount, tc.wantReserved)
			}

			if got := a.Header().HashTableSize; got != wantHashSize {
				t.Fatalf("Header().HashTableSize = %d, want %d", got, wantHashSize)
			}
		})
	}
}

func TestCreateWithFlags_DoesNotEagerlySeedInternalEntries(t *testing.T) {
	t.Parallel()
	p := filepath.Join(t.TempDir(), "createflags-seeded.mpq")
	a, err := CreateWithFlags(
		p,
		CreateFlagArchiveV4|CreateFlagAttributes|CreateFlagSignature,
		32,
	)
	if err != nil {
		t.Fatalf("CreateWithFlags() error = %v", err)
	}
	defer a.Close()

	for _, name := range []string{"(listfile)", "(attributes)", "(signature)"} {
		if a.HasFile(name, 0, 0) {
			t.Fatalf("HasFile(%q) = true, want false", name)
		}
		if _, err := a.ReadFileByName(name, 0, 0); !errors.Is(err, ErrFileNotFound) {
			t.Fatalf("ReadFileByName(%q) error = %v, want %v", name, err, ErrFileNotFound)
		}
	}
}

func TestCreateWithFlags_NoInternalSeedsWhenMaxFileCountZero(t *testing.T) {
	t.Parallel()
	p := filepath.Join(t.TempDir(), "createflags-no-seeds-zero-max.mpq")
	a, err := CreateWithFlags(
		p,
		CreateFlagArchiveV4|CreateFlagAttributes|CreateFlagSignature,
		0,
	)
	if err != nil {
		t.Fatalf("CreateWithFlags() error = %v", err)
	}
	defer a.Close()

	for _, name := range []string{"(listfile)", "(attributes)", "(signature)"} {
		if a.HasFile(name, 0, 0) {
			t.Fatalf("HasFile(%q) = true, want false", name)
		}
		if _, err := a.ReadFileByName(name, 0, 0); !errors.Is(err, ErrFileNotFound) {
			t.Fatalf("ReadFileByName(%q) error = %v, want %v", name, err, ErrFileNotFound)
		}
	}
}

func TestCreateWithFlags_InternalSeedMatrixParity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		flags        uint32
		maxFileCount uint32
		wantSeeded   map[string]bool
	}{
		{
			name:         "v1_default_listfile_only",
			flags:        CreateFlagArchiveV1,
			maxFileCount: 32,
			wantSeeded: map[string]bool{
				"(listfile)":   false,
				"(attributes)": false,
				"(signature)":  false,
			},
		},
		{
			name:         "v2_attributes",
			flags:        CreateFlagArchiveV2 | CreateFlagAttributes,
			maxFileCount: 32,
			wantSeeded: map[string]bool{
				"(listfile)":   false,
				"(attributes)": false,
				"(signature)":  false,
			},
		},
		{
			name:         "v3_signature",
			flags:        CreateFlagArchiveV3 | CreateFlagSignature,
			maxFileCount: 32,
			wantSeeded: map[string]bool{
				"(listfile)":   false,
				"(attributes)": false,
				"(signature)":  false,
			},
		},
		{
			name:         "v4_all_internal",
			flags:        CreateFlagArchiveV4 | CreateFlagAttributes | CreateFlagSignature,
			maxFileCount: 32,
			wantSeeded: map[string]bool{
				"(listfile)":   false,
				"(attributes)": false,
				"(signature)":  false,
			},
		},
		{
			name:         "zero_max_no_internal_seeds",
			flags:        CreateFlagArchiveV4 | CreateFlagAttributes | CreateFlagSignature,
			maxFileCount: 0,
			wantSeeded: map[string]bool{
				"(listfile)":   false,
				"(attributes)": false,
				"(signature)":  false,
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := filepath.Join(t.TempDir(), tc.name+".mpq")
			a, err := CreateWithFlags(p, tc.flags, tc.maxFileCount)
			if err != nil {
				t.Fatalf("CreateWithFlags() error = %v", err)
			}
			defer a.Close()

			for name, want := range tc.wantSeeded {
				got := a.HasFile(name, 0, 0)
				if got != want {
					t.Fatalf("HasFile(%q) = %v, want %v", name, got, want)
				}
			}
		})
	}
}

func TestCreateWithFlags_RejectsUnsupportedArchiveVersion(t *testing.T) {
	t.Parallel()

	p := filepath.Join(t.TempDir(), "createflags-bad-version.mpq")
	_, err := CreateWithFlags(p, 0x04000000, 32)
	if !errors.Is(err, ErrUnsupportedMPQ) {
		t.Fatalf("CreateWithFlags() error = %v, want %v", err, ErrUnsupportedMPQ)
	}
}

func TestCreateWriteFinish_ReadFileByNameRoundTrip(t *testing.T) {
	t.Parallel()
	p := filepath.Join(t.TempDir(), "write-roundtrip.mpq")
	a, err := Create(p, CreateOptions{ArchiveVersion: 0, MaxFileCount: 0})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	name := "scripts\\test.txt"
	payload := []byte("hello from write lifecycle")
	if err := a.CreateFile(name, uint32(len(payload)), 0); err != nil {
		t.Fatalf("CreateFile() error = %v", err)
	}
	if err := a.WriteFile(payload[:5]); err != nil {
		t.Fatalf("WriteFile(first) error = %v", err)
	}
	if err := a.WriteFile(payload[5:]); err != nil {
		t.Fatalf("WriteFile(second) error = %v", err)
	}
	if err := a.FinishFile(); err != nil {
		t.Fatalf("FinishFile() error = %v", err)
	}
	if err := a.Flush(); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	a2, err := Open(p, OpenOptions{})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	got, err := a2.ReadFileByName(name, 0, 0)
	if err != nil {
		t.Fatalf("ReadFileByName() error = %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("ReadFileByName() bytes mismatch: got %q want %q", got, payload)
	}
}

func TestRemoveAndRenameFile_PersistAfterReopen(t *testing.T) {
	t.Parallel()
	p := filepath.Join(t.TempDir(), "rename-remove-roundtrip.mpq")
	a, err := Create(p, CreateOptions{ArchiveVersion: 0, MaxFileCount: 4})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	oldName := "scripts\\a.txt"
	newName := "scripts\\renamed.txt"
	payload := []byte("rename then remove")
	if err := a.CreateFile(oldName, uint32(len(payload)), 0); err != nil {
		t.Fatalf("CreateFile() error = %v", err)
	}
	if err := a.WriteFile(payload); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := a.FinishFile(); err != nil {
		t.Fatalf("FinishFile() error = %v", err)
	}
	if err := a.RenameFile(oldName, newName, 0, 0); err != nil {
		t.Fatalf("RenameFile() error = %v", err)
	}
	if err := a.RemoveFile(newName, 0, 0); err != nil {
		t.Fatalf("RemoveFile() error = %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	a2, err := Open(p, OpenOptions{})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if _, err := a2.ReadFileByName(newName, 0, 0); !errors.Is(err, ErrFileNotFound) {
		t.Fatalf("ReadFileByName(removed) error = %v, want %v", err, ErrFileNotFound)
	}
	if _, err := a2.ReadFileByName(oldName, 0, 0); !errors.Is(err, ErrFileNotFound) {
		t.Fatalf("ReadFileByName(old) error = %v, want %v", err, ErrFileNotFound)
	}
}

func TestCreateWriteFinish_MultiFileAppend_ReadFileByNameRoundTrip(t *testing.T) {
	t.Parallel()
	p := filepath.Join(t.TempDir(), "write-multi-roundtrip.mpq")
	a, err := Create(p, CreateOptions{ArchiveVersion: 0, MaxFileCount: 4})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	cases := []struct {
		name    string
		payload []byte
	}{
		{name: "scripts\\first.txt", payload: []byte("first")},
		{name: "scripts\\second.txt", payload: []byte("second")},
	}
	for _, tc := range cases {
		if err := a.CreateFile(tc.name, uint32(len(tc.payload)), 0); err != nil {
			t.Fatalf("CreateFile(%q) error = %v", tc.name, err)
		}
		if err := a.WriteFile(tc.payload); err != nil {
			t.Fatalf("WriteFile(%q) error = %v", tc.name, err)
		}
		if err := a.FinishFile(); err != nil {
			t.Fatalf("FinishFile(%q) error = %v", tc.name, err)
		}
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	a2, err := Open(p, OpenOptions{})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	for _, tc := range cases {
		got, err := a2.ReadFileByName(tc.name, 0, 0)
		if err != nil {
			t.Fatalf("ReadFileByName(%q) error = %v", tc.name, err)
		}
		if string(got) != string(tc.payload) {
			t.Fatalf("ReadFileByName(%q) bytes mismatch: got %q want %q", tc.name, got, tc.payload)
		}
	}
}

func TestCreateWriteFinish_CompressedEncrypted_ReadFileByNameRoundTrip(t *testing.T) {
	t.Parallel()
	p := filepath.Join(t.TempDir(), "write-compressed-encrypted-roundtrip.mpq")
	a, err := Create(p, CreateOptions{ArchiveVersion: 0, MaxFileCount: 4})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	name := "scripts\\compressed-encrypted.txt"
	payload := []byte("write path compressed + encrypted roundtrip")
	flags := uint32(0x00000200 | mpq.FileFlagEncrypted)
	if err := a.CreateFile(name, uint32(len(payload)), flags); err != nil {
		t.Fatalf("CreateFile() error = %v", err)
	}
	if err := a.WriteFile(payload); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := a.FinishFile(); err != nil {
		t.Fatalf("FinishFile() error = %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	a2, err := Open(p, OpenOptions{})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	got, err := a2.ReadFileByName(name, 0, 0)
	if err != nil {
		t.Fatalf("ReadFileByName() error = %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("ReadFileByName() bytes mismatch: got %q want %q", got, payload)
	}
}

func TestSetAddFileCallback_WriteLifecycleProgress(t *testing.T) {
	t.Parallel()
	p := filepath.Join(t.TempDir(), "write-callback.mpq")
	a, err := Create(p, CreateOptions{ArchiveVersion: 0, MaxFileCount: 0})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	type event struct {
		written uint32
		total   uint32
		done    bool
	}
	var got []event
	a.SetAddFileCallback(func(written, total uint32, done bool) {
		got = append(got, event{written: written, total: total, done: done})
	})

	payload := []byte("public-callback")
	if err := a.CreateFile("scripts\\cb.txt", uint32(len(payload)), 0); err != nil {
		t.Fatalf("CreateFile() error = %v", err)
	}
	if err := a.WriteFile(payload); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := a.FinishFile(); err != nil {
		t.Fatalf("FinishFile() error = %v", err)
	}

	if len(got) != 3 {
		t.Fatalf("callback events len = %d, want 3", len(got))
	}
	if got[0] != (event{written: 0, total: uint32(len(payload)), done: false}) {
		t.Fatalf("callback first = %#v", got[0])
	}
	if got[1] != (event{written: uint32(len(payload)), total: uint32(len(payload)), done: false}) {
		t.Fatalf("callback second = %#v", got[1])
	}
	if got[2] != (event{written: uint32(len(payload)), total: uint32(len(payload)), done: true}) {
		t.Fatalf("callback third = %#v", got[2])
	}
}

func TestRenameFile_Encrypted_RecryptParity(t *testing.T) {
	t.Parallel()
	p := filepath.Join(t.TempDir(), "rename-encrypted-public.mpq")
	a, err := Create(p, CreateOptions{ArchiveVersion: 0, MaxFileCount: 4})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	oldName := "scripts\\enc-old.txt"
	newName := "scripts\\enc-new.txt"
	payload := []byte("public rename encrypted recrypt")
	flags := uint32(mpq.FileFlagEncrypted | mpq.FileFlagKeyV2)
	if err := a.CreateFile(oldName, uint32(len(payload)), flags); err != nil {
		t.Fatalf("CreateFile() error = %v", err)
	}
	if err := a.WriteFile(payload); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := a.FinishFile(); err != nil {
		t.Fatalf("FinishFile() error = %v", err)
	}
	if err := a.RenameFile(oldName, newName, 0, 0); err != nil {
		t.Fatalf("RenameFile() error = %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	a2, err := Open(p, OpenOptions{})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	got, err := a2.ReadFileByName(newName, 0, 0)
	if err != nil {
		t.Fatalf("ReadFileByName(new) error = %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("ReadFileByName(new) mismatch: got %q want %q", got, payload)
	}
}

func TestExtractFileSFileExtractFileParity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "extract.mpq")
	data := make([]byte, 0x6000)
	writeHeader(data, 0x200, 32, 0, 3, 0x400, 0x700, 2, 2)

	name := "units\\human\\footman.txt"
	payload := []byte("extract-me")
	copy(data[0x200+0x1000:0x200+0x1000+len(payload)], payload)

	hashPlain := make([]byte, 32)
	binary.LittleEndian.PutUint32(hashPlain[0:4], mpq.NameHashA(name))
	binary.LittleEndian.PutUint32(hashPlain[4:8], mpq.NameHashB(name))
	binary.LittleEndian.PutUint32(hashPlain[12:16], 0)
	binary.LittleEndian.PutUint32(hashPlain[16:20], 0x01020304)
	binary.LittleEndian.PutUint32(hashPlain[20:24], 0x05060708)
	binary.LittleEndian.PutUint32(hashPlain[28:32], 1)
	mpq.EncryptMpqTableDiskBytes(hashPlain, mpq.HashTableEncryptKey())
	copy(data[0x200+0x400:0x200+0x400+len(hashPlain)], hashPlain)

	blockPlain := make([]byte, 32)
	binary.LittleEndian.PutUint32(blockPlain[0:4], 0x1000)
	binary.LittleEndian.PutUint32(blockPlain[4:8], uint32(len(payload)))
	binary.LittleEndian.PutUint32(blockPlain[8:12], uint32(len(payload)))
	binary.LittleEndian.PutUint32(blockPlain[12:16], 0x01000000)
	mpq.EncryptMpqTableDiskBytes(blockPlain, mpq.BlockTableEncryptKey())
	copy(data[0x200+0x700:0x200+0x700+len(blockPlain)], blockPlain)

	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	a, err := Open(path, OpenOptions{})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	outPath := filepath.Join(t.TempDir(), "out.txt")
	if err := a.ExtractFile(name, outPath, ExtractOptions{}); err != nil {
		t.Fatalf("ExtractFile() error = %v", err)
	}
	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile extracted: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("extracted bytes: got %q want %q", got, payload)
	}

	err = a.ExtractFile("missing.ini", outPath, ExtractOptions{})
	if err == nil || !errors.Is(err, ErrFileNotFound) {
		t.Fatalf("missing file: err = %v", err)
	}

	err = a.ExtractFile(name, outPath, ExtractOptions{SearchScope: ExtractSearchLocalFile})
	if err == nil || !errors.Is(err, ErrUnsupportedFeature) {
		t.Fatalf("unsupported scope: err = %v", err)
	}
}

func writeHeader(buf []byte, offset int, headerSize uint32, version uint16, sectorExp uint16, hashPos uint32, blockPos uint32, hashSize uint32, blockSize uint32) {
	binary.LittleEndian.PutUint32(buf[offset+0:offset+4], 0x1A51504D)
	binary.LittleEndian.PutUint32(buf[offset+4:offset+8], headerSize)
	binary.LittleEndian.PutUint32(buf[offset+8:offset+12], uint32(len(buf)-offset))
	binary.LittleEndian.PutUint16(buf[offset+12:offset+14], version)
	binary.LittleEndian.PutUint16(buf[offset+14:offset+16], sectorExp)
	binary.LittleEndian.PutUint32(buf[offset+16:offset+20], hashPos)
	binary.LittleEndian.PutUint32(buf[offset+20:offset+24], blockPos)
	binary.LittleEndian.PutUint32(buf[offset+24:offset+28], hashSize)
	binary.LittleEndian.PutUint32(buf[offset+28:offset+32], blockSize)
}

// TestFlushEmitsListfile validates that a (listfile) entry is automatically
// generated on Flush() containing all user-added filenames sorted lexically.
func TestFlushEmitsListfile(t *testing.T) {
	t.Parallel()
	p := filepath.Join(t.TempDir(), "listfile.mpq")
	a, err := Create(p, CreateOptions{ArchiveVersion: 0, MaxFileCount: 8, ReserveListfile: true})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	for _, name := range []string{"banana.txt", "apple.txt", "cherry/sub.bin"} {
		payload := []byte("data:" + name)
		if err := a.CreateFile(name, uint32(len(payload)), 0); err != nil {
			t.Fatalf("CreateFile(%q): %v", name, err)
		}
		if err := a.WriteFile(payload); err != nil {
			t.Fatalf("WriteFile(%q): %v", name, err)
		}
		if err := a.FinishFile(); err != nil {
			t.Fatalf("FinishFile(%q): %v", name, err)
		}
	}
	if err := a.Flush(); err != nil {
		t.Fatalf("Flush(): %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}

	a2, err := Open(p, OpenOptions{})
	if err != nil {
		t.Fatalf("Open(): %v", err)
	}
	defer a2.Close()
	got, err := a2.ReadFileByName("(listfile)", 0, 0)
	if err != nil {
		t.Fatalf("ReadFileByName((listfile)): %v", err)
	}
	want := "apple.txt\r\nbanana.txt\r\ncherry/sub.bin\r\n"
	if string(got) != want {
		t.Fatalf("listfile mismatch:\n got=%q\nwant=%q", string(got), want)
	}
}

// TestFlushEmitsAttributes validates that Flush() emits an (attributes) file
// with CRC32+FILETIME+MD5 entries that match the data we wrote.
func TestFlushEmitsAttributes(t *testing.T) {
	t.Parallel()
	p := filepath.Join(t.TempDir(), "attrs.mpq")
	a, err := Create(p, CreateOptions{ArchiveVersion: 0, MaxFileCount: 8, ReserveListfile: true, ReserveAttributes: true})
	if err != nil {
		t.Fatalf("Create(): %v", err)
	}
	payload := []byte("attribute roundtrip payload")
	if err := a.CreateFile("alpha.bin", uint32(len(payload)), 0); err != nil {
		t.Fatalf("CreateFile: %v", err)
	}
	if err := a.WriteFile(payload); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := a.FinishFile(); err != nil {
		t.Fatalf("FinishFile: %v", err)
	}
	if err := a.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	a2, err := Open(p, OpenOptions{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer a2.Close()
	attrs, err := a2.GetAttributes()
	if err != nil {
		t.Fatalf("GetAttributes: %v", err)
	}
	if attrs.Version != 100 {
		t.Fatalf("attrs.Version = %d want 100", attrs.Version)
	}
	if (attrs.Flags & 0x07) != 0x07 {
		t.Fatalf("attrs.Flags = 0x%x want CRC|FILETIME|MD5", attrs.Flags)
	}
	if len(attrs.CRC32) < 1 || len(attrs.MD5) < 1 || len(attrs.Filetime) < 1 {
		t.Fatalf("expected at least one entry per array, got crc=%d md5=%d ft=%d", len(attrs.CRC32), len(attrs.MD5), len(attrs.Filetime))
	}
	// First block we wrote = "alpha.bin"; verify its CRC32 / MD5 match the payload.
	import_crc32 := crc32.ChecksumIEEE(payload)
	import_md5 := md5.Sum(payload)
	if attrs.CRC32[0] != import_crc32 {
		t.Fatalf("CRC32[0] = 0x%x want 0x%x", attrs.CRC32[0], import_crc32)
	}
	if attrs.MD5[0] != import_md5 {
		t.Fatalf("MD5[0] = %x want %x", attrs.MD5[0], import_md5)
	}
}

func TestVerifyArchiveStrong_NoSignature(t *testing.T) {
	t.Parallel()
	p := filepath.Join(t.TempDir(), "nostrong.mpq")
	a, err := Create(p, CreateOptions{ArchiveVersion: 0, MaxFileCount: 4})
	if err != nil {
		t.Fatalf("Create(): %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
	a2, err := Open(p, OpenOptions{})
	if err != nil {
		t.Fatalf("Open(): %v", err)
	}
	defer a2.Close()
	got, err := a2.VerifyArchiveStrong()
	if err != nil {
		t.Fatalf("VerifyArchiveStrong(): %v", err)
	}
	if got != VerifyNoSignature {
		t.Fatalf("VerifyArchiveStrong got %d want VerifyNoSignature(%d)", got, VerifyNoSignature)
	}
}

func TestVerifyHeaderMD5_PreV4(t *testing.T) {
	t.Parallel()
	p := filepath.Join(t.TempDir(), "v0.mpq")
	a, err := Create(p, CreateOptions{ArchiveVersion: 0, MaxFileCount: 4})
	if err != nil {
		t.Fatalf("Create(): %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
	a2, err := Open(p, OpenOptions{})
	if err != nil {
		t.Fatalf("Open(): %v", err)
	}
	defer a2.Close()
	got, err := a2.VerifyHeaderMD5()
	if err != nil {
		t.Fatalf("VerifyHeaderMD5(): %v", err)
	}
	if got != VerifyHeaderNoMD5 {
		t.Fatalf("got %d want VerifyHeaderNoMD5(%d)", got, VerifyHeaderNoMD5)
	}
}

func TestVerifyTableMD5_PreV4(t *testing.T) {
	t.Parallel()
	p := filepath.Join(t.TempDir(), "tbl.mpq")
	a, err := Create(p, CreateOptions{ArchiveVersion: 0, MaxFileCount: 4})
	if err != nil {
		t.Fatalf("Create(): %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
	a2, err := Open(p, OpenOptions{})
	if err != nil {
		t.Fatalf("Open(): %v", err)
	}
	defer a2.Close()
	for _, tc := range []struct {
		name string
		fn   func() (uint32, error)
	}{
		{"hash", a2.VerifyHashTableMD5},
		{"block", a2.VerifyBlockTableMD5},
	} {
		got, err := tc.fn()
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got != VerifyHeaderNoMD5 {
			t.Fatalf("%s: got %d want VerifyHeaderNoMD5", tc.name, got)
		}
	}
}
