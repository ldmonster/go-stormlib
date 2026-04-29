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
	"encoding/binary"
	"errors"
	"testing"
)

func TestFindHeaderWithMetaFromBytes(t *testing.T) {
	tests := []struct {
		name       string
		buf        []byte
		wantOffset int64
		wantUser   bool
	}{
		{
			name:       "header at zero",
			buf:        buildArchiveWithHeader(0, 0),
			wantOffset: 0,
		},
		{
			name:       "overlay aligned header",
			buf:        buildArchiveWithHeader(0x400, 0),
			wantOffset: 0x400,
		},
		{
			name:       "userdata points to header",
			buf:        buildArchiveWithUserData(0, 0x600),
			wantOffset: 0x600,
			wantUser:   true,
		},
		{
			name: "fallback after malformed aligned candidate",
			buf: func() []byte {
				b := buildArchiveWithHeader(0x600, 0)
				writeHeader(b, 0x200, 16, 0, 3, 64, 128, 2, 2)
				return b
			}(),
			wantOffset: 0x600,
		},
		{
			name: "fallback after unknown version candidate",
			buf: func() []byte {
				b := buildArchiveWithHeader(0x600, 0)
				writeHeader(b, 0x200, 32, 7, 3, 0xFFFFF000, 0xFFFFF100, 2, 2)
				return b
			}(),
			wantOffset: 0x600,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			result, err := FindHeaderWithMetaFromBytes(tc.buf)
			if err != nil {
				t.Fatalf("FindHeaderWithMetaFromBytes() error = %v", err)
			}
			if result.Header.Offset != tc.wantOffset {
				t.Fatalf("offset = %d, want %d", result.Header.Offset, tc.wantOffset)
			}
			if (result.UserData != nil) != tc.wantUser {
				t.Fatalf("userdata detected = %v, want %v", result.UserData != nil, tc.wantUser)
			}
		})
	}
}

func TestFindHeaderWithMetaFromBytes_TruncatedCandidate(t *testing.T) {
	buf := make([]byte, 0x400+16)
	binary.LittleEndian.PutUint32(buf[0x400:0x404], idMPQ)

	_, err := FindHeaderWithMetaFromBytes(buf)
	if err == nil {
		t.Fatal("expected error for truncated header candidate")
	}
	if err != ErrHeaderNotFound {
		t.Fatalf("error = %v, want %v", err, ErrHeaderNotFound)
	}
}

func TestFindHeaderWithMetaFromBytes_BeyondEightMiB(t *testing.T) {
	offset := 9 * 1024 * 1024
	buf := buildArchiveWithHeader(offset, 0)

	result, err := FindHeaderWithMetaFromBytes(buf)
	if err != nil {
		t.Fatalf("FindHeaderWithMetaFromBytes() error = %v", err)
	}
	if result.Header.Offset != int64(offset) {
		t.Fatalf("offset = %d, want %d", result.Header.Offset, offset)
	}
}

func TestFindHeaderWithMeta_ValidatesAgainstFullArchiveSize(t *testing.T) {
	buf := make([]byte, 0x1000)
	writeHeader(buf, 0, 32, 1, 3, 0x08100000, 0x08100100, 1, 1)

	// Probe is capped to 0x08000000, but full archive size is larger.
	size := int64(0x09000000)
	result, err := FindHeaderWithMeta(bytes.NewReader(buf), size)
	if err != nil {
		t.Fatalf("FindHeaderWithMeta() error = %v", err)
	}
	if result.Header.Offset != 0 {
		t.Fatalf("offset = %d, want 0", result.Header.Offset)
	}
}

func TestFindHeaderWithMetaFromBytes_OnlyUnsupportedVersion(t *testing.T) {
	buf := buildArchiveWithHeader(0x200, 7)

	result, err := FindHeaderWithMetaFromBytes(buf)
	if err != nil {
		t.Fatalf("FindHeaderWithMetaFromBytes() error = %v", err)
	}
	if result.Header.FormatVersion != 0 {
		t.Fatalf("format version = %d, want coerced 0", result.Header.FormatVersion)
	}
}

func TestFindHeaderWithMetaFromBytes_UnsupportedVersionNotCoercible(t *testing.T) {
	buf := buildArchiveWithHeader(0x200, 7)
	writeHeader(buf, 0x200, 32, 7, 3, 0xFFFFF000, 0xFFFFF100, 2, 2)

	_, err := FindHeaderWithMetaFromBytes(buf)
	if err == nil {
		t.Fatal("expected unsupported format error")
	}
	if !errors.Is(err, ErrUnsupportedFormat) {
		t.Fatalf("error = %v, want %v", err, ErrUnsupportedFormat)
	}
}

func TestValidateHeaderLayout(t *testing.T) {
	tests := []struct {
		name    string
		header  Header
		size    int64
		wantErr error
		wantAny bool
	}{
		{
			name: "valid format version range 0..3",
			header: func() Header {
				h := Header{
					Offset:           0,
					HeaderSize:       208,
					FormatVersion:    3,
					SectorSizeExp:    3,
					ArchiveSize64:    0x300,
					HashTablePos:     0x40,
					BlockTablePos:    0x80,
					HashTableSize:    1,
					BlockTableSize:   1,
					HashTableSize64:  16,
					BlockTableSize64: 16,
				}
				h.MPQHeaderMD5 = md5.Sum(h.HeaderHashRegion[:])
				return h
			}(),
			size: 0x400,
		},
		{
			name: "unsupported format version",
			header: Header{
				Offset:         0,
				HeaderSize:     32,
				FormatVersion:  9,
				SectorSizeExp:  3,
				HashTablePos:   0x40,
				BlockTablePos:  0x80,
				HashTableSize:  1,
				BlockTableSize: 1,
			},
			size:    0x400,
			wantErr: ErrUnsupportedFormat,
		},
		{
			name: "hash table out of file bounds",
			header: Header{
				Offset:         0,
				HeaderSize:     32,
				FormatVersion:  0,
				SectorSizeExp:  3,
				HashTablePos:   0x3F0,
				BlockTablePos:  0x80,
				HashTableSize:  2,
				BlockTableSize: 1,
			},
			size:    0x400,
			wantAny: true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateHeaderLayout(tc.header, tc.size)
			if tc.wantErr == nil && !tc.wantAny && err != nil {
				t.Fatalf("ValidateHeaderLayout() error = %v", err)
			}
			if tc.wantErr == nil && !tc.wantAny {
				return
			}
			if err == nil {
				t.Fatal("expected non-nil error, got nil")
			}
			if tc.wantAny {
				return
			}
			if tc.wantErr == ErrUnsupportedFormat && !errors.Is(err, ErrUnsupportedFormat) {
				t.Fatalf("error = %v, want wrapped %v", err, tc.wantErr)
			}
		})
	}
}

func TestFindHeaderWithMetaFromBytes_NormalizesHeaderByFormat(t *testing.T) {
	tests := []struct {
		name           string
		version        uint16
		headerSize     uint32
		wantVersion    uint16
		wantHeaderSize uint32
	}{
		{
			name:           "v1 forces header size 0x20",
			version:        0,
			headerSize:     64,
			wantVersion:    0,
			wantHeaderSize: 32,
		},
		{
			name:           "malformed v2 falls back to v1",
			version:        1,
			headerSize:     32,
			wantVersion:    0,
			wantHeaderSize: 32,
		},
		{
			name:           "v3 caps header size to 0x44",
			version:        2,
			headerSize:     96,
			wantVersion:    2,
			wantHeaderSize: 68,
		},
		{
			name:           "v4 with full header forces header size 0xD0",
			version:        3,
			headerSize:     208,
			wantVersion:    3,
			wantHeaderSize: 208,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			buf := buildArchiveWithHeader(0, tc.version)
			writeHeader(buf, 0, tc.headerSize, tc.version, 3, 0x200, 0x300, 1, 1)
			if tc.version == 3 {
				writeV2V3Fields(buf, 0, 0x0, 0x0, 0x0, uint64(len(buf)), 0x0, 0x0)
				writeV4Fields(buf, 0, 16, 16, 0, 0, 0)
				writeV4MD5ForHeader(buf, 0)
			}

			result, err := FindHeaderWithMetaFromBytes(buf)
			if err != nil {
				t.Fatalf("FindHeaderWithMetaFromBytes() error = %v", err)
			}
			if result.Header.FormatVersion != tc.wantVersion {
				t.Fatalf("version = %d, want %d", result.Header.FormatVersion, tc.wantVersion)
			}
			if result.Header.HeaderSize != tc.wantHeaderSize {
				t.Fatalf("header size = %d, want %d", result.Header.HeaderSize, tc.wantHeaderSize)
			}
		})
	}
}

func TestFindHeaderWithMetaFromBytes_V4HeaderTooSmallRejected(t *testing.T) {
	buf := buildArchiveWithHeader(0, 3)
	writeHeader(buf, 0, 32, 3, 3, 0x200, 0x300, 1, 1)
	_, err := FindHeaderWithMetaFromBytes(buf)
	if err == nil {
		t.Fatal("expected error for undersized v4 header")
	}
}

func TestFindHeaderWithMetaWithOptions_ForceV1IgnoresUserData(t *testing.T) {
	buf := buildArchiveWithUserData(0, 0x600)
	result, err := FindHeaderWithMetaFromBytesWithOptions(buf, DiscoverOptions{ForceMPQV1: true})
	if err != nil {
		t.Fatalf("FindHeaderWithMetaFromBytesWithOptions() error = %v", err)
	}
	if result.UserData != nil {
		t.Fatal("expected userdata to be ignored in force-v1 mode")
	}
	if result.Header.Offset != 0x600 {
		t.Fatalf("offset = %d, want %d", result.Header.Offset, 0x600)
	}
	if result.Header.FormatVersion != 0 {
		t.Fatalf("format version = %d, want 0", result.Header.FormatVersion)
	}
}

func TestFindHeaderWithMetaWithOptions_CustomMarker(t *testing.T) {
	buf := buildArchiveWithHeader(0, 0)
	customMarker := uint32(0x42424242)
	binary.LittleEndian.PutUint32(buf[0:4], customMarker)
	result, err := FindHeaderWithMetaFromBytesWithOptions(buf, DiscoverOptions{MarkerSignature: customMarker})
	if err != nil {
		t.Fatalf("FindHeaderWithMetaFromBytesWithOptions() error = %v", err)
	}
	if result.Header.Offset != 0 {
		t.Fatalf("offset = %d, want 0", result.Header.Offset)
	}
}

func TestFindHeaderWithMetaFromBytes_ForeignHeader(t *testing.T) {
	buf := make([]byte, 0x400)
	binary.LittleEndian.PutUint32(buf[0:4], idMPK)
	_, err := FindHeaderWithMetaFromBytes(buf)
	if !errors.Is(err, ErrUnsupportedMPK) {
		t.Fatalf("error = %v, want %v", err, ErrUnsupportedMPK)
	}
}

func TestFindHeaderWithMetaFromBytes_SQPHeader(t *testing.T) {
	buf := make([]byte, 0x400)
	binary.LittleEndian.PutUint32(buf[0:4], idMPQ)
	binary.LittleEndian.PutUint32(buf[4:8], 32)
	binary.LittleEndian.PutUint32(buf[8:12], uint32(len(buf)))
	binary.LittleEndian.PutUint16(buf[28:30], 1)
	binary.LittleEndian.PutUint16(buf[30:32], 3)
	_, err := FindHeaderWithMetaFromBytes(buf)
	if !errors.Is(err, ErrUnsupportedSQP) {
		t.Fatalf("error = %v, want %v", err, ErrUnsupportedSQP)
	}
}

func TestFindHeaderWithMetaFromBytes_MalformedMPQNotMisclassifiedAsSQP(t *testing.T) {
	buf := make([]byte, 0x400)
	binary.LittleEndian.PutUint32(buf[0:4], idMPQ)
	binary.LittleEndian.PutUint32(buf[4:8], 16)
	binary.LittleEndian.PutUint16(buf[12:14], 9)
	binary.LittleEndian.PutUint16(buf[14:16], 0)
	_, err := FindHeaderWithMetaFromBytes(buf)
	if errors.Is(err, ErrUnsupportedSQP) {
		t.Fatalf("malformed mpq should not be classified as sqp: %v", err)
	}
}

func TestFindHeaderWithMetaFromBytes_ForeignHeaderPrecedence(t *testing.T) {
	buf := buildArchiveWithHeader(0x400, 0)
	binary.LittleEndian.PutUint32(buf[0:4], idMPK)
	result, err := FindHeaderWithMetaFromBytes(buf)
	if err != nil {
		t.Fatalf("FindHeaderWithMetaFromBytes() error = %v", err)
	}
	if result.Header.Offset != 0x400 {
		t.Fatalf("offset = %d, want %d", result.Header.Offset, 0x400)
	}
}

func TestFindHeaderWithMetaFromBytes_V4TandemRejectsFakeHeader(t *testing.T) {
	buf := buildArchiveWithHeader(0, 3)
	writeHeader(buf, 0, 208, 3, 3, 0x200, 0x100, 1, 1)
	writeV2V3Fields(buf, 0, 0, 0, 0, uint64(len(buf)), 0x500, 0x700)
	writeV4Fields(buf, 0, 64, 64, 0, 64, 64)
	_, err := FindHeaderWithMetaFromBytes(buf)
	if err == nil {
		t.Fatal("expected v4 tandem reject error")
	}
}

func TestFindHeaderWithMetaFromBytes_V4TandemAcceptsValidPair(t *testing.T) {
	buf := buildArchiveWithHeader(0, 3)
	writeHeader(buf, 0, 208, 3, 3, 0x200, 0x240, 1, 1)
	writeV2V3Fields(buf, 0, 0, 0, 0, uint64(len(buf)), 0x500, 0x480)
	writeV4Fields(buf, 0, 64, 64, 0, 64, 64)
	writeV4MD5ForHeader(buf, 0)
	result, err := FindHeaderWithMetaFromBytes(buf)
	if err != nil {
		t.Fatalf("FindHeaderWithMetaFromBytes() error = %v", err)
	}
	if result.Header.FormatVersion != 3 {
		t.Fatalf("version = %d, want 3", result.Header.FormatVersion)
	}
}

func TestFindHeaderWithMetaFromBytes_V4MalformedButOpenable(t *testing.T) {
	buf := buildArchiveWithHeader(0, 3)
	writeHeader(buf, 0, 208, 3, 3, 0x200, 0x240, 1, 1)
	writeV2V3Fields(buf, 0, 0, 0, 0, uint64(len(buf)), 0x500, 0x480)
	writeV4Fields(buf, 0, 64, 64, 0, 64, 64)
	// malformed v4 size should normalize to 0xD0 but still open if structural checks pass
	binary.LittleEndian.PutUint32(buf[4:8], 0x250)
	writeV4MD5ForHeader(buf, 0)
	result, err := FindHeaderWithMetaFromBytes(buf)
	if err != nil {
		t.Fatalf("FindHeaderWithMetaFromBytes() error = %v", err)
	}
	if result.Header.HeaderSize != 208 {
		t.Fatalf("header size = %d, want 208", result.Header.HeaderSize)
	}
}

func TestFindHeaderWithMetaFromBytes_V4MD5MissingRejected(t *testing.T) {
	buf := buildArchiveWithHeader(0, 3)
	writeHeader(buf, 0, 208, 3, 3, 0x200, 0x240, 1, 1)
	writeV2V3Fields(buf, 0, 0, 0, 0, uint64(len(buf)), 0x500, 0x480)
	writeV4Fields(buf, 0, 64, 64, 0, 64, 64)
	_, err := FindHeaderWithMetaFromBytes(buf)
	if err == nil {
		t.Fatal("expected v4 header md5 missing error")
	}
}

func TestFindHeaderWithMetaFromBytes_V4MD5MismatchRejected(t *testing.T) {
	buf := buildArchiveWithHeader(0, 3)
	writeHeader(buf, 0, 208, 3, 3, 0x200, 0x240, 1, 1)
	writeV2V3Fields(buf, 0, 0, 0, 0, uint64(len(buf)), 0x500, 0x480)
	writeV4Fields(buf, 0, 64, 64, 0, 64, 64)
	writeV4MD5(buf, 0, 0x55) // non-zero but wrong hash
	_, err := FindHeaderWithMetaFromBytes(buf)
	if err == nil {
		t.Fatal("expected v4 header md5 mismatch error")
	}
}

func TestFindHeaderWithMetaFromBytes_CustomMarkerUserDataContract(t *testing.T) {
	buf := buildArchiveWithUserData(0, 0x400)
	customMarker := uint32(0x12345678)
	binary.LittleEndian.PutUint32(buf[0x400:0x404], customMarker)

	_, err := FindHeaderWithMetaFromBytesWithOptions(buf, DiscoverOptions{MarkerSignature: customMarker})
	if err != nil {
		t.Fatalf("custom-marker userdata open failed: %v", err)
	}
}

func TestFindHeaderWithMetaFromBytes_CustomMarkerUserDataOrderingFallback(t *testing.T) {
	buf := buildArchiveWithHeader(0x800, 0)
	writeUserData(buf, 0, 0x400)
	customMarker := uint32(0x12345678)
	// Userdata-target header uses custom marker but malformed size; scanner should fallback.
	binary.LittleEndian.PutUint32(buf[0x400:0x404], customMarker)
	binary.LittleEndian.PutUint32(buf[0x404:0x408], 16)
	binary.LittleEndian.PutUint16(buf[0x40C:0x40E], 0)
	binary.LittleEndian.PutUint16(buf[0x40E:0x410], 3)
	// Keep later valid custom-marker header.
	binary.LittleEndian.PutUint32(buf[0x800:0x804], customMarker)
	binary.LittleEndian.PutUint32(buf[0x804:0x808], 32)
	binary.LittleEndian.PutUint32(buf[0x808:0x80C], uint32(len(buf)-0x800))
	binary.LittleEndian.PutUint16(buf[0x80C:0x80E], 0)
	binary.LittleEndian.PutUint16(buf[0x80E:0x810], 3)
	binary.LittleEndian.PutUint32(buf[0x810:0x814], 0x200)
	binary.LittleEndian.PutUint32(buf[0x814:0x818], 0x300)
	binary.LittleEndian.PutUint32(buf[0x818:0x81C], 1)
	binary.LittleEndian.PutUint32(buf[0x81C:0x820], 1)

	result, err := FindHeaderWithMetaFromBytesWithOptions(buf, DiscoverOptions{MarkerSignature: customMarker})
	if err != nil {
		t.Fatalf("FindHeaderWithMetaFromBytesWithOptions() error = %v", err)
	}
	if result.Header.Offset != 0x800 {
		t.Fatalf("offset = %d, want %d", result.Header.Offset, 0x800)
	}
}

func TestFindHeaderWithMetaFromBytes_MarkerUserDataMatrix(t *testing.T) {
	customMarker := uint32(0x12345678)
	tests := []struct {
		name      string
		opts      DiscoverOptions
		build     func([]byte)
		wantErr   error
		wantOff   int64
	}{
		{
			name: "custom marker userdata target wins",
			opts: DiscoverOptions{MarkerSignature: customMarker},
			build: func(buf []byte) {
				writeUserData(buf, 0, 0x400)
				binary.LittleEndian.PutUint32(buf[0x400:0x404], customMarker)
				binary.LittleEndian.PutUint32(buf[0x404:0x408], 32)
				binary.LittleEndian.PutUint32(buf[0x408:0x40C], uint32(len(buf)-0x400))
				binary.LittleEndian.PutUint16(buf[0x40C:0x40E], 0)
				binary.LittleEndian.PutUint16(buf[0x40E:0x410], 3)
				binary.LittleEndian.PutUint32(buf[0x410:0x414], 0x200)
				binary.LittleEndian.PutUint32(buf[0x414:0x418], 0x300)
				binary.LittleEndian.PutUint32(buf[0x418:0x41C], 1)
				binary.LittleEndian.PutUint32(buf[0x41C:0x420], 1)
			},
			wantOff: 0x400,
		},
		{
			name: "force v1 ignores userdata indirection",
			opts: DiscoverOptions{ForceMPQV1: true, MarkerSignature: customMarker},
			build: func(buf []byte) {
				writeUserData(buf, 0, 0x400)
				// No aligned custom marker candidate reachable without userdata.
			},
			wantErr: ErrHeaderNotFound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			buf := make([]byte, 0x2000)
			tc.build(buf)
			result, err := FindHeaderWithMetaFromBytesWithOptions(buf, tc.opts)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("error = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("FindHeaderWithMetaFromBytesWithOptions() error = %v", err)
			}
			if result.Header.Offset != tc.wantOff {
				t.Fatalf("offset = %d, want %d", result.Header.Offset, tc.wantOff)
			}
		})
	}
}

func TestFindHeaderWithMetaFromBytes_SQPMarkerVariant(t *testing.T) {
	customMarker := uint32(0x12345678)
	buf := make([]byte, 0x1000)
	binary.LittleEndian.PutUint32(buf[0:4], customMarker)
	binary.LittleEndian.PutUint32(buf[4:8], 32)
	binary.LittleEndian.PutUint32(buf[8:12], uint32(len(buf)))
	binary.LittleEndian.PutUint16(buf[28:30], 1)
	binary.LittleEndian.PutUint16(buf[30:32], 3)

	_, err := FindHeaderWithMetaFromBytesWithOptions(buf, DiscoverOptions{MarkerSignature: customMarker})
	if !errors.Is(err, ErrUnsupportedSQP) {
		t.Fatalf("error = %v, want %v", err, ErrUnsupportedSQP)
	}
}

func TestFindHeaderWithMetaWithOptions_ForceV1SuppressesSQPError(t *testing.T) {
	buf := buildArchiveWithHeader(0, 0)
	// SQP-like bytes at beginning
	binary.LittleEndian.PutUint32(buf[0:4], idMPQ)
	binary.LittleEndian.PutUint32(buf[4:8], 32)
	binary.LittleEndian.PutUint16(buf[12:14], 9)
	binary.LittleEndian.PutUint16(buf[14:16], 0)
	// Valid MPQ later
	writeHeader(buf, 0x400, 32, 0, 3, 0x200, 0x300, 1, 1)
	result, err := FindHeaderWithMetaFromBytesWithOptions(buf, DiscoverOptions{ForceMPQV1: true})
	if err != nil {
		t.Fatalf("FindHeaderWithMetaFromBytesWithOptions() error = %v", err)
	}
	if result.Header.Offset != 0x400 {
		t.Fatalf("offset = %d, want %d", result.Header.Offset, 0x400)
	}
}

func TestFindHeaderWithMetaFromBytes_MasksTableSizes(t *testing.T) {
	buf := buildArchiveWithHeader(0, 0)
	writeHeader(buf, 0, 32, 0, 3, 0x200, 0x300, 0xF0000001, 0xE0000002)

	result, err := FindHeaderWithMetaFromBytes(buf)
	if err != nil {
		t.Fatalf("FindHeaderWithMetaFromBytes() error = %v", err)
	}
	if result.Header.HashTableSize != 0x00000001 {
		t.Fatalf("hash size = %d, want %d", result.Header.HashTableSize, 0x00000001)
	}
	if result.Header.BlockTableSize != 0x00000002 {
		t.Fatalf("block size = %d, want %d", result.Header.BlockTableSize, 0x00000002)
	}
}

func TestFindHeaderWithMetaFromBytes_ClampHugeBlockTableSize(t *testing.T) {
	buf := buildArchiveWithHeader(0, 0)
	writeHeader(buf, 0, 32, 0, 3, 0x200, 0x300, 1, 0x0FFFFFFF)
	result, err := FindHeaderWithMetaFromBytes(buf)
	if err != nil {
		t.Fatalf("FindHeaderWithMetaFromBytes() error = %v", err)
	}
	if result.Header.BlockTableSize == 0x0FFFFFFF {
		t.Fatalf("expected clamped block table size, got %d", result.Header.BlockTableSize)
	}
	if !result.Header.Malformed {
		t.Fatal("expected malformed flag for clamped v1 table size")
	}
}

func TestValidateHeaderLayout_TableRangeOutOfBounds(t *testing.T) {
	header := Header{
		Offset:         0,
		HeaderSize:     32,
		FormatVersion:  0,
		SectorSizeExp:  3,
		HashTablePos:   0x3F0,
		BlockTablePos:  0x80,
		HashTableSize:  2,
		BlockTableSize: 1,
	}

	err := ValidateHeaderLayout(header, 0x400)
	if err == nil {
		t.Fatal("expected table range error")
	}
}

func TestValidateHeaderLayout_V2HighWordOffsets(t *testing.T) {
	valid := Header{
		Offset:          0,
		HeaderSize:      44,
		FormatVersion:   1,
		SectorSizeExp:   3,
		HashTablePos:    0x100,
		BlockTablePos:   0x200,
		HashTableSize:   1,
		BlockTableSize:  1,
		HashTablePosHi:  1,
		BlockTablePosHi: 1,
	}
	if err := ValidateHeaderLayout(valid, 0x200000000); err != nil {
		t.Fatalf("ValidateHeaderLayout() valid v2 error = %v", err)
	}

	invalid := valid
	invalid.HashTablePosHi = 2
	err := ValidateHeaderLayout(invalid, 0x200000000)
	if err == nil {
		t.Fatal("expected out-of-range error for high-word hash table offset")
	}
}

func TestValidateHeaderLayout_V3ExtendedTablePositions(t *testing.T) {
	header := Header{
		Offset:         0,
		HeaderSize:     68,
		FormatVersion:  2,
		SectorSizeExp:  3,
		HashTablePos:   0x100,
		BlockTablePos:  0x200,
		HashTableSize:  1,
		BlockTableSize: 1,
		HiBlockTablePos: 0x300,
		BetTablePos64:   0x400,
		HetTablePos64:   0x500,
	}
	if err := ValidateHeaderLayout(header, 0x1000); err != nil {
		t.Fatalf("ValidateHeaderLayout() valid v3 error = %v", err)
	}

	header.HetTablePos64 = 0x2000
	err := ValidateHeaderLayout(header, 0x1000)
	if err == nil {
		t.Fatal("expected out-of-range error for HET table")
	}
}

func TestFindHeaderWithMetaFromBytes_ParsesV2V3Positions(t *testing.T) {
	buf := make([]byte, 0x2000)
	writeHeader(buf, 0, 68, 2, 3, 0x100, 0x200, 1, 1)
	writeV2V3Fields(buf, 0, 0x300, 0x0, 0x0, 0x1000, 0x500, 0x600)

	result, err := FindHeaderWithMetaFromBytes(buf)
	if err != nil {
		t.Fatalf("FindHeaderWithMetaFromBytes() error = %v", err)
	}
	if result.Header.HashTablePosHi != 0x0 || result.Header.BlockTablePosHi != 0x0 {
		t.Fatalf("high word offsets not parsed: hashHi=%d blockHi=%d", result.Header.HashTablePosHi, result.Header.BlockTablePosHi)
	}
	if result.Header.HiBlockTablePos != 0x300 {
		t.Fatalf("hi block table pos = %d, want 0x300", result.Header.HiBlockTablePos)
	}
}

func TestValidateHeaderLayout_V1WrapAroundBlockPosOpenable(t *testing.T) {
	header := Header{
		Offset:         0x200,
		HeaderSize:     32,
		FormatVersion:  0,
		SectorSizeExp:  3,
		HashTablePos:   0x100,
		BlockTablePos:  0xFFFFFF00, // wraps before MPQ header in 32-bit arithmetic
		HashTableSize:  1,
		BlockTableSize: 1,
	}
	if err := ValidateHeaderLayout(header, 0x2000); err != nil {
		t.Fatalf("expected wrapped v1 position to remain openable, got %v", err)
	}
	normalized := sanitizeAndClampHeaderForValidation(normalizeHeaderForVersion(header), 0x2000)
	if !normalized.Malformed {
		t.Fatal("expected malformed flag for wrapped v1 block table position")
	}
}

func TestFindHeaderWithMetaFromBytes_UnsupportedPreferredOverForeign(t *testing.T) {
	buf := make([]byte, 0x2000)
	writeHeader(buf, 0x200, 32, 9, 3, 0xFFFFF000, 0xFFFFF100, 2, 2) // unsupported non-coercible
	// SQP-like candidate later should not change precedence.
	binary.LittleEndian.PutUint32(buf[0x800:0x804], idMPQ)
	binary.LittleEndian.PutUint32(buf[0x804:0x808], 32)
	binary.LittleEndian.PutUint32(buf[0x808:0x80C], uint32(len(buf)))
	binary.LittleEndian.PutUint16(buf[0x81C:0x81E], 1)
	binary.LittleEndian.PutUint16(buf[0x81E:0x820], 3)

	_, err := FindHeaderWithMetaFromBytes(buf)
	if err == nil || !errors.Is(err, ErrUnsupportedFormat) {
		t.Fatalf("error = %v, want %v", err, ErrUnsupportedFormat)
	}
}

func buildArchiveWithHeader(offset int, formatVersion uint16) []byte {
	if offset < 0 {
		offset = 0
	}
	size := offset + 0x1000
	buf := make([]byte, size)
	writeHeader(buf, offset, 32, formatVersion, 3, 0x200, 0x300, 1, 1)
	return buf
}

func buildArchiveWithUserData(userDataOffset, headerOffset int) []byte {
	if headerOffset <= userDataOffset {
		headerOffset = userDataOffset + 0x200
	}
	size := headerOffset + 0x1000
	buf := make([]byte, size)
	writeUserData(buf, userDataOffset, uint32(headerOffset-userDataOffset))
	writeHeader(buf, headerOffset, 32, 1, 3, 0x200, 0x300, 1, 1)
	return buf
}

func writeHeader(buf []byte, offset int, headerSize uint32, version uint16, sectorExp uint16, hashPos uint32, blockPos uint32, hashSize uint32, blockSize uint32) {
	binary.LittleEndian.PutUint32(buf[offset+0:offset+4], idMPQ)
	binary.LittleEndian.PutUint32(buf[offset+4:offset+8], headerSize)
	binary.LittleEndian.PutUint32(buf[offset+8:offset+12], uint32(len(buf)-offset))
	binary.LittleEndian.PutUint16(buf[offset+12:offset+14], version)
	binary.LittleEndian.PutUint16(buf[offset+14:offset+16], sectorExp)
	binary.LittleEndian.PutUint32(buf[offset+16:offset+20], hashPos)
	binary.LittleEndian.PutUint32(buf[offset+20:offset+24], blockPos)
	binary.LittleEndian.PutUint32(buf[offset+24:offset+28], hashSize)
	binary.LittleEndian.PutUint32(buf[offset+28:offset+32], blockSize)
}

func writeUserData(buf []byte, offset int, headerOffset uint32) {
	binary.LittleEndian.PutUint32(buf[offset+0:offset+4], idMPQUserdata)
	binary.LittleEndian.PutUint32(buf[offset+4:offset+8], 16)
	binary.LittleEndian.PutUint32(buf[offset+8:offset+12], headerOffset)
	binary.LittleEndian.PutUint32(buf[offset+12:offset+16], 16)
}

func writeV2V3Fields(buf []byte, offset int, hiBlockPos uint64, hashPosHi uint16, blockPosHi uint16, archiveSize64 uint64, betPos uint64, hetPos uint64) {
	binary.LittleEndian.PutUint64(buf[offset+32:offset+40], hiBlockPos)
	binary.LittleEndian.PutUint16(buf[offset+40:offset+42], hashPosHi)
	binary.LittleEndian.PutUint16(buf[offset+42:offset+44], blockPosHi)
	binary.LittleEndian.PutUint64(buf[offset+44:offset+52], archiveSize64)
	binary.LittleEndian.PutUint64(buf[offset+52:offset+60], betPos)
	binary.LittleEndian.PutUint64(buf[offset+60:offset+68], hetPos)
}

func writeV4Fields(buf []byte, offset int, hashSize uint64, blockSize uint64, hiBlockSize uint64, hetSize uint64, betSize uint64) {
	binary.LittleEndian.PutUint64(buf[offset+68:offset+76], hashSize)
	binary.LittleEndian.PutUint64(buf[offset+76:offset+84], blockSize)
	binary.LittleEndian.PutUint64(buf[offset+84:offset+92], hiBlockSize)
	binary.LittleEndian.PutUint64(buf[offset+92:offset+100], hetSize)
	binary.LittleEndian.PutUint64(buf[offset+100:offset+108], betSize)
}

func writeV4MD5(buf []byte, offset int, fill byte) {
	for i := 0; i < 16; i++ {
		buf[offset+192+i] = fill
	}
}

func writeV4MD5ForHeader(buf []byte, offset int) {
	sum := md5.Sum(buf[offset : offset+192])
	copy(buf[offset+192:offset+208], sum[:])
}

