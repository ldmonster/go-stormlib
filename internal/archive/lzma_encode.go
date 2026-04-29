package archive

import (
	"bytes"
	"fmt"

	"github.com/ulikunitz/xz/lzma"
)

// lzmaEncodeBytes compresses `raw` using classic LZMA1 (the format StormLib
// expects for codec 0x12) and prepends a single zero filter byte the way
// SCompCompressLZMA does. Output is *not* wrapped with the codec mask byte;
// callers are expected to add 0x12 before this body.
func lzmaEncodeBytes(raw []byte) ([]byte, error) {
	var buf bytes.Buffer

	cfg := lzma.WriterConfig{}

	zw, err := cfg.NewWriter(&buf)
	if err != nil {
		return nil, fmt.Errorf("lzma writer: %w", err)
	}

	if _, err := zw.Write(raw); err != nil {
		return nil, fmt.Errorf("lzma write: %w", err)
	}

	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("lzma close: %w", err)
	}

	body := buf.Bytes()
	out := make([]byte, 1+len(body))
	out[0] = 0x00 // filter byte
	copy(out[1:], body)

	return out, nil
}
