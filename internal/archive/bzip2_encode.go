package archive

import (
	"bytes"
	"fmt"

	"github.com/dsnet/compress/bzip2"
)

// bzip2EncodeBytes compresses raw with the dsnet bzip2 encoder using the
// default compression level. The output is the standard bzip2 stream
// ("BZh...") that StormLib's bzip2 decoder accepts directly.
func bzip2EncodeBytes(raw []byte) ([]byte, error) {
	var buf bytes.Buffer

	w, err := bzip2.NewWriter(&buf, &bzip2.WriterConfig{Level: bzip2.DefaultCompression})
	if err != nil {
		return nil, fmt.Errorf("init bzip2 writer: %w", err)
	}

	if _, err := w.Write(raw); err != nil {
		_ = w.Close()
		return nil, fmt.Errorf("bzip2 write: %w", err)
	}

	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("bzip2 finalize: %w", err)
	}

	return buf.Bytes(), nil
}
