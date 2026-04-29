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
	"encoding/hex"
	"errors"
	"testing"

	"github.com/ulikunitz/xz/lzma"
)

// Golden: Python bz2.compress(b'hello-bzip2-sector-payload'); first byte 0x10 = MPQ_COMPRESSION_BZIP2 per StormLib.
const bzip2SectorGoldenHex = "10425a68393141592653596cc148940000059980000210003e64dc30200031434d300053d4d3419a87a9058b0bef1c994fd42894108af8bb9229c28483660a44a0"

func TestDecompressSectorZlibGolden(t *testing.T) {
	payload := []byte(`{"ok":true}`)
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	chunk := append([]byte{mpqCompZlib}, buf.Bytes()...)
	got, err := decompressSector(chunk, uint32(len(payload)))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("got %q want %q", got, payload)
	}
}

func TestDecompressSectorBzip2Golden(t *testing.T) {
	raw, err := hex.DecodeString(bzip2SectorGoldenHex)
	if err != nil {
		t.Fatal(err)
	}
	if raw[0] != mpqCompBzip2 {
		t.Fatalf("fixture first byte got %02x", raw[0])
	}
	wantPlain := []byte("hello-bzip2-sector-payload")
	got, err := decompressSector(raw, uint32(len(wantPlain)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, wantPlain) {
		t.Fatalf("got %q want %q", got, wantPlain)
	}
}

func TestDecompressSectorLZMA(t *testing.T) {
	wantPlain := []byte("hello-lzma-sector-payload")
	var lzmaClassic bytes.Buffer
	zw, err := lzma.NewWriter(&lzmaClassic)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zw.Write(wantPlain); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	// Storm LZMA sector payload includes one filter byte before classic LZMA header.
	raw := append([]byte{mpqCompLzma, 0}, lzmaClassic.Bytes()...)
	got, err := decompressSector(raw, uint32(len(wantPlain)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, wantPlain) {
		t.Fatalf("got %q want %q", got, wantPlain)
	}
}

func TestDecompressSectorUnsupportedCodecMasks(t *testing.T) {
	// Storm MPQ_COMPRESSION_* single-byte masks (StormLib.h); multi-bit = combined pipeline via SCompDecompress — gated here.
	tests := []struct {
		name string
		mask byte
	}{
		{"unknown_mask_bit", 0x04}, // unknown/unsupported
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			raw := []byte{tc.mask, 0xAA, 0xBB}
			_, err := decompressSector(raw, 4)
			if err == nil {
				t.Fatal("expected error")
			}
			if !errors.Is(err, ErrUnsupportedCodec) {
				t.Fatalf("got %v want ErrUnsupportedCodec", err)
			}
		})
	}
}

func TestDecompressSectorSparse(t *testing.T) {
	want := []byte{0x01, 0x02, 0x00, 0x00, 0x00, 0x03}
	// Storm sparse stream: 4-byte big-endian output size, then chunk tags.
	sparse := []byte{
		0x00, 0x00, 0x00, 0x06, // output size
		0x81, 0x01, 0x02, // 2 non-zero bytes
		0x00, // 3 zeros
		0x80, 0x03, // 1 non-zero byte
	}
	raw := append([]byte{0x20}, sparse...) // MPQ_COMPRESSION_SPARSE
	got, err := decompressSector(raw, uint32(len(want)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestDecompressSectorSparseZlibCombined(t *testing.T) {
	want := []byte{0x01, 0x02, 0x00, 0x00, 0x00, 0x03}
	sparse := []byte{
		0x00, 0x00, 0x00, 0x06,
		0x81, 0x01, 0x02,
		0x00,
		0x80, 0x03,
	}
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	if _, err := zw.Write(sparse); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	raw := append([]byte{0x22}, z.Bytes()...) // sparse | zlib
	got, err := decompressSector(raw, uint32(len(want)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}
