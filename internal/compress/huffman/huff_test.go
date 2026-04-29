package huffman

import (
	"bytes"
	"testing"
)

func TestRoundTripBinary(t *testing.T) {
	for _, dt := range []uint32{1, 2, 3} {
		input := []byte("Hello, MoPaQ! Huffman round-trip test 0123456789.")
		enc, err := Compress(input, dt)
		if err != nil {
			t.Fatalf("Compress(dt=%d) error: %v", dt, err)
		}
		dec, err := Decompress(enc, len(input))
		if err != nil {
			t.Fatalf("Decompress(dt=%d) error: %v", dt, err)
		}
		if !bytes.Equal(dec, input) {
			t.Fatalf("dt=%d: mismatch want=%q got=%q", dt, input, dec)
		}
	}
}

func TestRoundTripBinaryRandom(t *testing.T) {
	input := make([]byte, 1024)
	for i := range input {
		input[i] = byte((i*131 + 7) & 0xFF)
	}
	enc, err := Compress(input, 1)
	if err != nil {
		t.Fatalf("Compress: %v", err)
	}
	dec, err := Decompress(enc, len(input))
	if err != nil {
		t.Fatalf("Decompress: %v", err)
	}
	if !bytes.Equal(dec, input) {
		t.Fatalf("mismatch")
	}
}

func TestEmptyOutputRejected(t *testing.T) {
	if _, err := Decompress([]byte{0x01}, 0); err != ErrEmptyOutput {
		t.Fatalf("want ErrEmptyOutput, got %v", err)
	}
}

func TestTruncatedHeader(t *testing.T) {
	if _, err := Decompress(nil, 16); err != ErrTruncated {
		t.Fatalf("want ErrTruncated, got %v", err)
	}
}

func TestInvalidDataType(t *testing.T) {
	if _, err := Decompress([]byte{0x09}, 16); err != ErrInvalidType {
		t.Fatalf("want ErrInvalidType, got %v", err)
	}
}
