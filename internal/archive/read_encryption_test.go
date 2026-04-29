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
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ldmonster/go-stormlib/internal/mpq"
)

func TestReadEncrypted_NoPath_ReturnsErrEncryptionNeedsPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enc-no-path.bin")
	data := make([]byte, 0x1000)
	payload := []byte("x")
	filePos := uint32(0x200)
	key := mpq.DecryptFileKey("ignored.txt", uint64(filePos), uint32(len(payload)), mpq.FileFlagEncrypted)
	onDisk := append([]byte(nil), payload...)
	mpq.EncryptMpqFileBytes(onDisk, key)
	copy(data[filePos:filePos+uint32(len(onDisk))], onDisk)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
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
					FilePos:          filePos,
					CompressedSize:   uint32(len(onDisk)),
					UncompressedSize: uint32(len(payload)),
					Flags:            mpqFileSingleUnit | mpq.FileFlagEncrypted,
				},
			},
		},
	}

	h, err := a.OpenIndexedFile(0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.ReadFile(h)
	if err == nil || !errors.Is(err, ErrEncryptionNeedsPath) {
		t.Fatalf("ReadFile() error = %v, want %v", err, ErrEncryptionNeedsPath)
	}
}

func TestReadEncrypted_WithPath_RoundTripPlain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enc-plain.bin")
	data := make([]byte, 0x1000)
	payload := []byte("encrypted single-unit plaintext")
	mpqPath := `units\encrypted.txt`
	filePos := uint32(0x200)
	key := mpq.DecryptFileKey(mpqPath, uint64(filePos), uint32(len(payload)), mpq.FileFlagEncrypted)
	onDisk := append([]byte(nil), payload...)
	mpq.EncryptMpqFileBytes(onDisk, key)
	copy(data[filePos:filePos+uint32(len(onDisk))], onDisk)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
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
				Hash: mpq.HashEntry{
					HashA: mpq.NameHashA(mpqPath),
					HashB: mpq.NameHashB(mpqPath),
				},
				Block: mpq.BlockEntry{
					FilePos:          filePos,
					CompressedSize:   uint32(len(onDisk)),
					UncompressedSize: uint32(len(payload)),
					Flags:            mpqFileSingleUnit | mpq.FileFlagEncrypted,
				},
			},
		},
	}

	h, err := a.OpenIndexedFileForDecrypt(mpq.NameHashA(mpqPath), mpq.NameHashB(mpqPath), 0, 0, mpqPath)
	if err != nil {
		t.Fatal(err)
	}
	out, err := a.ReadFile(h)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(payload) {
		t.Fatalf("got %q want %q", out, payload)
	}
}

func TestReadEncrypted_WithPath_KeyV2(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enc-keyv2.bin")
	data := make([]byte, 0x1000)
	payload := []byte("key v2 adjust")
	mpqPath := `data.bin`
	filePos := uint32(0x200)
	flags := uint32(mpq.FileFlagEncrypted | mpq.FileFlagKeyV2)
	key := mpq.DecryptFileKey(mpqPath, uint64(filePos), uint32(len(payload)), flags)
	onDisk := append([]byte(nil), payload...)
	mpq.EncryptMpqFileBytes(onDisk, key)
	copy(data[filePos:filePos+uint32(len(onDisk))], onDisk)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
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
				Hash: mpq.HashEntry{
					HashA: mpq.NameHashA(mpqPath),
					HashB: mpq.NameHashB(mpqPath),
				},
				Block: mpq.BlockEntry{
					FilePos:          filePos,
					CompressedSize:   uint32(len(onDisk)),
					UncompressedSize: uint32(len(payload)),
					Flags:            mpqFileSingleUnit | flags,
				},
			},
		},
	}

	h, err := a.OpenIndexedFileForDecrypt(mpq.NameHashA(mpqPath), mpq.NameHashB(mpqPath), 0, 0, mpqPath)
	if err != nil {
		t.Fatal(err)
	}
	out, err := a.ReadFile(h)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(payload) {
		t.Fatalf("got %q want %q", out, payload)
	}
}

func TestReadEncrypted_SingleUnitZlib(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enc-zlib.bin")
	data := make([]byte, 0x2000)
	plain := []byte("zlib under encryption")
	mpqPath := `file.w3a`
	filePos := uint32(0x400)
	var zbuf bytes.Buffer
	zw := zlib.NewWriter(&zbuf)
	if _, err := zw.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	chunk := append(append([]byte(nil), mpqCompZlib), zbuf.Bytes()...)
	key := mpq.DecryptFileKey(mpqPath, uint64(filePos), uint32(len(plain)), mpq.FileFlagEncrypted)
	onDisk := append([]byte(nil), chunk...)
	mpq.EncryptMpqFileBytes(onDisk, key)
	copy(data[filePos:filePos+uint32(len(onDisk))], onDisk)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
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
				Hash: mpq.HashEntry{
					HashA: mpq.NameHashA(mpqPath),
					HashB: mpq.NameHashB(mpqPath),
				},
				Block: mpq.BlockEntry{
					FilePos:          filePos,
					CompressedSize:   uint32(len(onDisk)),
					UncompressedSize:   uint32(len(plain)),
					Flags:            mpqFileSingleUnit | mpqFileCompressed | mpq.FileFlagEncrypted,
				},
			},
		},
	}

	h, err := a.OpenIndexedFileForDecrypt(mpq.NameHashA(mpqPath), mpq.NameHashB(mpqPath), 0, 0, mpqPath)
	if err != nil {
		t.Fatal(err)
	}
	out, err := a.ReadFile(h)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(plain) {
		t.Fatalf("got %q want %q", out, plain)
	}
}

func TestReadEncrypted_SectorZlibDecryptsBeforeDecompress(t *testing.T) {
	const sectorSize = 512
	plain := bytes.Repeat([]byte("sector zlib encrypted "), 16)
	var zbuf bytes.Buffer
	zw := zlib.NewWriter(&zbuf)
	if _, err := zw.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	chunk := append(append([]byte(nil), mpqCompZlib), zbuf.Bytes()...)
	table := make([]byte, 8)
	binary.LittleEndian.PutUint32(table[0:4], 8)
	binary.LittleEndian.PutUint32(table[4:8], 8+uint32(len(chunk)))

	mpqPath := `x.txt`
	fileKey := mpq.DecryptFileKey(mpqPath, 0x100, uint32(len(plain)), mpq.FileFlagEncrypted)
	sectorCopy := append([]byte(nil), chunk...)
	mpq.EncryptMpqFileBytes(sectorCopy, fileKey+0)

	tableEnc := append([]byte(nil), table...)
	mpq.EncryptMpqFileBytes(tableEnc, fileKey-1)
	blob := append(tableEnc, sectorCopy...)
	out, err := readCompressedBySectors(bytesReaderAt(blob), 0, uint32(len(blob)), uint32(len(plain)), sectorSize, true, fileKey, false)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(plain) {
		t.Fatalf("got %q want %q", out, plain)
	}
}
