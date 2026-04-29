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
	"testing"
)

func TestNearestPowerOfTwoStorm(t *testing.T) {
	if got := NearestPowerOfTwoStorm(0); got != 0 {
		t.Fatalf("NearestPowerOfTwoStorm(0) = %#x, want 0", got)
	}
	if got := NearestPowerOfTwoStorm(1); got != 1 {
		t.Fatalf("NearestPowerOfTwoStorm(1) = %d, want 1", got)
	}
	if got := NearestPowerOfTwoStorm(1024); got != 1024 {
		t.Fatalf("NearestPowerOfTwoStorm(1024) = %d, want 1024", got)
	}
}

func TestHashTableSizeForCreate_DefaultWhenZeroRequested(t *testing.T) {
	n := HashTableSizeForCreate(0, 0)
	if n != DefaultHashTableEntries {
		t.Fatalf("HashTableSizeForCreate(0,0) = %d, want %d", n, DefaultHashTableEntries)
	}
}

func TestBuildEmptyArchiveLayout_V1_BlockTableZero(t *testing.T) {
	layout, err := BuildEmptyArchiveLayout(0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if layout.Header.BlockTableSize != 0 {
		t.Fatalf("block table size = %d, want 0", layout.Header.BlockTableSize)
	}
	if layout.Header.HashTableSize != DefaultHashTableEntries {
		t.Fatalf("hash entries = %d", layout.Header.HashTableSize)
	}
	if int64(layout.Header.HeaderSize)+int64(layout.Header.HashTableSize)*hashEntrySize != int64(layout.Header.ArchiveSize32) {
		t.Fatalf("archive size mismatch")
	}
}

func TestMarshalHeaderRoundTrip_V2(t *testing.T) {
	layout, err := BuildEmptyArchiveLayout(1, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalHeader(layout.Header)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != int(headerSizeV2) {
		t.Fatalf("len = %d", len(raw))
	}
	got, err := parseHeaderAt(raw, 0, idMPQ)
	if err != nil {
		t.Fatal(err)
	}
	got.Offset = layout.Header.Offset
	if got.FormatVersion != layout.Header.FormatVersion || got.HeaderSize != layout.Header.HeaderSize {
		t.Fatalf("parse mismatch: %+v vs %+v", got, layout.Header)
	}
}

func TestEncryptedHashTableDecryptsToFF(t *testing.T) {
	layout, err := BuildEmptyArchiveLayout(0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	buf := append([]byte(nil), layout.HashTableBytes...)
	DecryptMpqTableDiskBytes(buf, hashTableKey())
	if !bytes.Equal(buf, bytes.Repeat([]byte{0xff}, len(buf))) {
		t.Fatal("decrypted hash table should be all 0xFF empty slots")
	}
}
