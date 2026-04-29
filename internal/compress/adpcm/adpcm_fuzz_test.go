package adpcm

import "testing"

// FuzzDecompress ensures the ADPCM decoder never panics on arbitrary inputs.
func FuzzDecompress(f *testing.F) {
	f.Add([]byte{}, 1)
	f.Add([]byte{0x00, 0x00}, 1)
	f.Add([]byte{0x05, 0x00, 0x00, 0x00, 0x00, 0x00}, 2)
	f.Add(make([]byte, 64), 2)

	f.Fuzz(func(t *testing.T, data []byte, channels int) {
		if channels < 1 || channels > 2 {
			return
		}
		_, _ = Decompress(data, channels)
	})
}
