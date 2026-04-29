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
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ldmonster/go-stormlib/internal/mpq"
)

func TestOpenFallbackFromUnsupportedCandidate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fallback.mpq")
	data := make([]byte, 0x2000)

	// First candidate is unsupported version; later aligned candidate is valid.
	writeHeader(data, 0x200, 32, 7, 3, 0xFFFFF000, 0xFFFFF100, 2, 2)
	writeHeader(data, 0x800, 32, 1, 3, 0x200, 0x300, 1, 1)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	a, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if a.Header.Offset != 0x800 {
		t.Fatalf("header offset = %d, want %d", a.Header.Offset, 0x800)
	}
}

func TestOpenUnsupportedWhenNoValidHeaderExists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unsupported.mpq")
	data := make([]byte, 0x2000)
	writeHeader(data, 0x200, 32, 9, 3, 0xFFFFF000, 0xFFFFF100, 2, 2)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err := Open(path)
	if err == nil {
		t.Fatal("expected open error")
	}
	if !errors.Is(err, mpq.ErrUnsupportedFormat) {
		t.Fatalf("error = %v, want wrapped %v", err, mpq.ErrUnsupportedFormat)
	}
}

func TestOpenCoercesLoneUnknownVersionToV1(t *testing.T) {
	path := filepath.Join(t.TempDir(), "coerced.mpq")
	data := make([]byte, 0x2000)
	writeHeader(data, 0x200, 32, 9, 3, 0x200, 0x300, 1, 1)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	a, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if a.Header.FormatVersion != 0 {
		t.Fatalf("header version = %d, want coerced 0", a.Header.FormatVersion)
	}
}

func TestOpenWithOptions_ForceMPQV1(t *testing.T) {
	path := filepath.Join(t.TempDir(), "force-v1.mpq")
	data := make([]byte, 0x2000)
	writeHeader(data, 0x200, 32, 9, 3, 0x200, 0x300, 1, 1)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	a, err := OpenWithOptions(path, OpenOptions{ForceMPQV1: true})
	if err != nil {
		t.Fatalf("OpenWithOptions() error = %v", err)
	}
	if a.Header.FormatVersion != 0 {
		t.Fatalf("header version = %d, want 0", a.Header.FormatVersion)
	}
}

func TestOpenWithOptions_CustomMarker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "marker.mpq")
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

	_, err := OpenWithOptions(path, OpenOptions{MarkerSignature: customMarker})
	if err != nil {
		t.Fatalf("OpenWithOptions() error = %v", err)
	}
}

func TestOpenWithOptions_ForeignHeaderPrecedence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mixed.mpq")
	data := make([]byte, 0x2000)
	binary.LittleEndian.PutUint32(data[0:4], 0x1A4B504D) // MPK
	writeHeader(data, 0x400, 32, 0, 3, 0x200, 0x300, 1, 1)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	a, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if a.Header.Offset != 0x400 {
		t.Fatalf("header offset = %d, want %d", a.Header.Offset, 0x400)
	}
}

func TestOpenWithOptions_MapTypeWarcraftForcesV1ByExtension(t *testing.T) {
	path := filepath.Join(t.TempDir(), "map.w3x")
	data := make([]byte, 0x2000)
	writeHeader(data, 0x200, 32, 9, 3, 0x200, 0x300, 1, 1)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	a, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if a.Header.FormatVersion != 0 {
		t.Fatalf("header version = %d, want 0", a.Header.FormatVersion)
	}
}

func TestOpenWithOptions_MapTypeWarcraftForcesV1ByContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "map.bin")
	data := make([]byte, 0x2000)
	copy(data[0:4], []byte("HM3W"))
	writeHeader(data, 0x200, 32, 9, 3, 0x200, 0x300, 1, 1)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	a, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if a.Header.FormatVersion != 0 {
		t.Fatalf("header version = %d, want 0", a.Header.FormatVersion)
	}
}

func TestOpenWithOptions_AviRejectedByContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cinematic.bin")
	data := make([]byte, 0x2000)
	copy(data[0:4], []byte("RIFF"))
	copy(data[8:12], []byte("AVI "))
	copy(data[12:16], []byte("LIST"))
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	_, err := Open(path)
	if err == nil || !errors.Is(err, mpq.ErrAviFile) {
		t.Fatalf("error = %v, want %v", err, mpq.ErrAviFile)
	}
}

func TestDetectMapType_ExtensionsAndContent(t *testing.T) {
	if got := detectMapType("foo.scx", nil); got != mapTypeStarcraft {
		t.Fatalf("map type = %v, want %v", got, mapTypeStarcraft)
	}
	if got := detectMapType("foo.w3x", nil); got != mapTypeWarcraft3 {
		t.Fatalf("map type = %v, want %v", got, mapTypeWarcraft3)
	}
	probe := make([]byte, 16)
	copy(probe[0:4], []byte("RIFF"))
	copy(probe[8:12], []byte("AVI "))
	copy(probe[12:16], []byte("LIST"))
	if got := detectMapType("foo.bin", probe); got != mapTypeAvi {
		t.Fatalf("map type = %v, want %v", got, mapTypeAvi)
	}
	// Content-first: AVI bytes override map extensions.
	if got := detectMapType("foo.w3x", probe); got != mapTypeAvi {
		t.Fatalf("map type = %v, want %v", got, mapTypeAvi)
	}
	// StarCraft extension remains extension-routed even with conflicting content.
	if got := detectMapType("foo.scx", probe); got != mapTypeStarcraft {
		t.Fatalf("map type = %v, want %v", got, mapTypeStarcraft)
	}
	if got := detectMapType("foo.SC2Map", nil); got != mapTypeStarcraft2 {
		t.Fatalf("map type = %v, want %v", got, mapTypeStarcraft2)
	}
}

func TestDetectMapType_DLLTreatedAsWarcraft3(t *testing.T) {
	probe := make([]byte, 0x200)
	copy(probe[0:2], []byte("MZ"))
	binary.LittleEndian.PutUint32(probe[0x3C:0x40], 0x80)
	copy(probe[0x80:0x84], []byte("PE\x00\x00"))
	// IMAGE_FILE_HEADER.Characteristics with IMAGE_FILE_DLL set
	binary.LittleEndian.PutUint16(probe[0x80+4+18:0x80+4+20], 0x2000)
	if got := detectMapType("foo.bin", probe); got != mapTypeWarcraft3 {
		t.Fatalf("map type = %v, want %v", got, mapTypeWarcraft3)
	}
}

func TestOpenDoesNotReintroduceSecondStageValidationPrefix(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid.mpq")
	data := make([]byte, 0x2000)
	// non-coercible unsupported candidate
	writeHeader(data, 0x200, 32, 9, 3, 0xFFFFF000, 0xFFFFF100, 2, 2)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	_, err := Open(path)
	if err == nil {
		t.Fatal("expected open error")
	}
	if strings.Contains(err.Error(), "invalid mpq header layout") {
		t.Fatalf("unexpected second-stage validation prefix in error: %v", err)
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
