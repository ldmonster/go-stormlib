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
	"testing"

	"github.com/ldmonster/go-stormlib/internal/mpq"
)

func TestCreateEmptyAndOpen(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		format    uint16
		wantSize  uint32
		wantShift uint16
	}{
		{"v1", 0, 32, 3},
		{"v2", 1, 44, 3},
		{"v3", 2, 68, 5},
		{"v4", 3, 208, 5},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			path := dir + "/empty.mpq"
			if err := CreateEmpty(path, CreateOptions{ArchiveFormat: tc.format, MaxFileCount: 0}); err != nil {
				t.Fatal(err)
			}
			a, err := OpenWithOptions(path, OpenOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if a.Header.FormatVersion != tc.format {
				t.Fatalf("format = %d, want %d", a.Header.FormatVersion, tc.format)
			}
			if a.Header.HeaderSize != tc.wantSize {
				t.Fatalf("header size = %d, want %d", a.Header.HeaderSize, tc.wantSize)
			}
			if a.Header.SectorSizeExp != tc.wantShift {
				t.Fatalf("sector size exp = %d, want %d", a.Header.SectorSizeExp, tc.wantShift)
			}
			if a.Header.HashTableSize != mpq.DefaultHashTableEntries {
				t.Fatalf("hash size = %d", a.Header.HashTableSize)
			}
			if len(a.FileIndex) != 0 {
				t.Fatalf("expected empty index, got %d entries", len(a.FileIndex))
			}
		})
	}
}

func TestCreateEmpty_WithReservedSlots_HashTableSizing(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := dir + "/reserved.mpq"
	const maxFiles = uint32(100)
	const reserved = uint32(3)
	wantN := mpq.HashTableSizeForCreate(maxFiles, reserved)
	if err := CreateEmpty(path, CreateOptions{ArchiveFormat: 0, MaxFileCount: maxFiles, ReservedSlots: reserved}); err != nil {
		t.Fatal(err)
	}
	a, err := OpenWithOptions(path, OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if a.Header.HashTableSize != wantN {
		t.Fatalf("hash table entries = %d, want %d (Storm nearest-pow2 of max+reserved)", a.Header.HashTableSize, wantN)
	}
}

func TestCreateEmpty_InternalReservationFlags_HashTableSizing(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name              string
		maxFiles          uint32
		reservedSlots     uint32
		reserveListfile   bool
		reserveAttributes bool
		reserveSignature  bool
		wantReserved      uint32
	}{
		{
			name:              "listfile_attributes_signature",
			maxFiles:          32,
			reserveListfile:   true,
			reserveAttributes: true,
			reserveSignature:  true,
			wantReserved:      3,
		},
		{
			name:             "manual_plus_listfile",
			maxFiles:         32,
			reservedSlots:    2,
			reserveListfile:  true,
			wantReserved:     3,
		},
		{
			name:              "ignored_when_max_file_count_zero",
			maxFiles:          0,
			reserveListfile:   true,
			reserveAttributes: true,
			reserveSignature:  true,
			wantReserved:      3,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			path := dir + "/reserved-flags.mpq"
			if err := CreateEmpty(path, CreateOptions{
				ArchiveFormat:      0,
				MaxFileCount:       tc.maxFiles,
				ReservedSlots:      tc.reservedSlots,
				ReserveListfile:    tc.reserveListfile,
				ReserveAttributes:  tc.reserveAttributes,
				ReserveSignature:   tc.reserveSignature,
			}); err != nil {
				t.Fatal(err)
			}
			a, err := OpenWithOptions(path, OpenOptions{})
			if err != nil {
				t.Fatal(err)
			}

			var wantN uint32 = mpq.DefaultHashTableEntries
			if tc.maxFiles != 0 {
				wantN = mpq.HashTableSizeForCreate(tc.maxFiles, tc.wantReserved)
			}
			if a.Header.HashTableSize != wantN {
				t.Fatalf("hash table entries = %d, want %d", a.Header.HashTableSize, wantN)
			}
		})
	}
}

func TestCreateEmpty_InternalReservationFlags_DoesNotEagerlySeedInternalEntries(t *testing.T) {
	t.Parallel()
	path := t.TempDir() + "/seeded-internal.mpq"
	if err := CreateEmpty(path, CreateOptions{
		ArchiveFormat:     0,
		MaxFileCount:      32,
		ReserveListfile:   true,
		ReserveAttributes: true,
		ReserveSignature:  true,
	}); err != nil {
		t.Fatal(err)
	}

	a, err := OpenWithOptions(path, OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := a.Header.BlockTableSize, uint32(0); got != want {
		t.Fatalf("block table size = %d, want %d", got, want)
	}

	for _, name := range []string{"(listfile)", "(attributes)", "(signature)"} {
		if _, err := a.OpenIndexedFileByHash(mpq.NameHashA(name), mpq.NameHashB(name), 0, 0); err != ErrFileHashNotFound {
			t.Fatalf("OpenIndexedFileByHash(%q) error = %v, want %v", name, err, ErrFileHashNotFound)
		}
	}
}

func TestCreateEmpty_InternalReservationFlags_NoSeedsWhenMaxFileCountZero(t *testing.T) {
	t.Parallel()
	path := t.TempDir() + "/seeded-internal-zero-max.mpq"
	if err := CreateEmpty(path, CreateOptions{
		ArchiveFormat:     0,
		MaxFileCount:      0,
		ReserveListfile:   true,
		ReserveAttributes: true,
		ReserveSignature:  true,
	}); err != nil {
		t.Fatal(err)
	}

	a, err := OpenWithOptions(path, OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := a.Header.BlockTableSize, uint32(0); got != want {
		t.Fatalf("block table size = %d, want %d", got, want)
	}

	for _, name := range []string{"(listfile)", "(attributes)", "(signature)"} {
		if _, err := a.OpenIndexedFileByHash(mpq.NameHashA(name), mpq.NameHashB(name), 0, 0); err != ErrFileHashNotFound {
			t.Fatalf("OpenIndexedFileByHash(%q) error = %v, want %v", name, err, ErrFileHashNotFound)
		}
	}
}
