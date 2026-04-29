package adpcm

import (
	"encoding/binary"
	"testing"
)

func TestDecompressInvalidChannels(t *testing.T) {
	if _, err := Decompress([]byte{0, 0}, 0); err != ErrInvalidChannels {
		t.Fatal(err)
	}
	if _, err := Decompress([]byte{0, 0}, 3); err != ErrInvalidChannels {
		t.Fatal(err)
	}
}

func TestDecompressTruncatedHeader(t *testing.T) {
	if _, err := Decompress(nil, 1); err != ErrTruncatedHeader {
		t.Fatal(err)
	}
	if _, err := Decompress([]byte{0}, 1); err != ErrTruncatedHeader {
		t.Fatal(err)
	}
}

func TestDecompressInitialSamplePassThrough(t *testing.T) {
	// With no encoded samples after the initial sample, the decoder should
	// emit just the initial sample for the channel.
	in := []byte{0x00, 0x05}
	in = append(in, 0x34, 0x12) // initial sample = 0x1234
	out, err := Decompress(in, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("len=%d", len(out))
	}
	got := int16(binary.LittleEndian.Uint16(out))
	if got != 0x1234 {
		t.Fatalf("got 0x%04x want 0x1234", got)
	}
}

func TestDecompressStereoPassThrough(t *testing.T) {
	// Two-channel: emit both initial samples.
	in := []byte{0x00, 0x05, 0x01, 0x00, 0x02, 0x00}
	out, err := Decompress(in, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 4 {
		t.Fatalf("len=%d", len(out))
	}
	if int16(binary.LittleEndian.Uint16(out[0:2])) != 1 {
		t.Fatalf("ch0=%d", int16(binary.LittleEndian.Uint16(out[0:2])))
	}
	if int16(binary.LittleEndian.Uint16(out[2:4])) != 2 {
		t.Fatalf("ch1=%d", int16(binary.LittleEndian.Uint16(out[2:4])))
	}
}

func TestDecompressRepeatSample(t *testing.T) {
	// Encoded sample 0x80 repeats the previous predicted sample.
	in := []byte{0x00, 0x05, 0x10, 0x00, 0x80}
	out, err := Decompress(in, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 4 {
		t.Fatalf("len=%d", len(out))
	}
	a := int16(binary.LittleEndian.Uint16(out[0:2]))
	b := int16(binary.LittleEndian.Uint16(out[2:4]))
	if a != 0x10 || b != 0x10 {
		t.Fatalf("got %d, %d", a, b)
	}
}
