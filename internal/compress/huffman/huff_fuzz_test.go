package huffman

import "testing"

// FuzzDecompress ensures Decompress never panics on arbitrary inputs.
func FuzzDecompress(f *testing.F) {
	f.Add([]byte{}, 0)
	f.Add([]byte{0x00}, 16)
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, 64)

	f.Fuzz(func(t *testing.T, data []byte, expected int) {
		if expected < 0 || expected > 1<<20 {
			return
		}
		out, err := Decompress(data, expected)
		if err != nil {
			return
		}
		if len(out) > expected {
			t.Fatalf("output %d exceeds expected %d", len(out), expected)
		}
	})
}

// FuzzCompressRoundtrip ensures Compress always produces output that
// Decompress can read back without panic.
func FuzzCompressRoundtrip(f *testing.F) {
	f.Add([]byte("hello world"), uint32(0))
	f.Add([]byte{}, uint32(1))
	f.Add(make([]byte, 256), uint32(0))

	f.Fuzz(func(t *testing.T, data []byte, dataType uint32) {
		if len(data) > 1<<16 {
			return
		}
		dataType &= 0x07
		enc, err := Compress(data, dataType)
		if err != nil {
			return
		}
		dec, err := Decompress(enc, len(data))
		if err != nil {
			return
		}
		if len(dec) != len(data) {
			t.Fatalf("roundtrip length mismatch: got %d want %d", len(dec), len(data))
		}
		for i := range data {
			if dec[i] != data[i] {
				t.Fatalf("roundtrip mismatch at %d", i)
			}
		}
	})
}
