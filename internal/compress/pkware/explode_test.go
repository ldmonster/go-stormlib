package pkware

import (
	"bytes"
	"testing"
)

// implodeLiteralsBinary produces a minimal PKWARE-imploded stream containing
// only literal bytes followed by the end-of-stream marker, in binary mode with
// dsize_bits=4. Used to build deterministic test inputs without porting the
// full implode encoder.
func implodeLiteralsBinary(data []byte) []byte {
	bw := bitWriter{}
	for _, b := range data {
		bw.write(0, 1)
		bw.write(uint32(b), 8)
	}
	bw.write(1, 1)
	bw.write(0x00, 7)
	bw.write(0xFF, 8)
	bw.flush()

	out := []byte{CmpBinary, 4}
	out = append(out, bw.buf...)
	return out
}

type bitWriter struct {
	buf  []byte
	bits uint32
	n    uint32
}

func (b *bitWriter) write(value, count uint32) {
	for i := uint32(0); i < count; i++ {
		bit := (value >> i) & 1
		b.bits |= bit << b.n
		b.n++
		if b.n == 8 {
			b.buf = append(b.buf, byte(b.bits))
			b.bits = 0
			b.n = 0
		}
	}
}

func (b *bitWriter) flush() {
	if b.n > 0 {
		b.buf = append(b.buf, byte(b.bits))
		b.bits = 0
		b.n = 0
	}
}

func TestExplodeBinaryLiterals(t *testing.T) {
	cases := [][]byte{
		[]byte("hello world"),
		bytes.Repeat([]byte{0xAB}, 17),
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
		make([]byte, 256),
	}
	for i, c := range cases {
		enc := implodeLiteralsBinary(c)
		out, err := Explode(enc, len(c))
		if err != nil {
			t.Errorf("case %d: explode error: %v", i, err)
			continue
		}
		if !bytes.Equal(out, c) {
			t.Errorf("case %d: got %x want %x", i, out, c)
		}
	}
}

func TestExplodeRejectsTruncated(t *testing.T) {
	if _, err := Explode([]byte{0, 4}, 0); err == nil {
		t.Fatal("expected error for too-short input")
	}
}

func TestExplodeRejectsInvalidDictSize(t *testing.T) {
	for _, ds := range []byte{0, 3, 7, 9, 0xFF} {
		if _, err := Explode([]byte{CmpBinary, ds, 0, 0, 0}, 0); err != ErrInvalidDictSize {
			t.Errorf("dsize %d: want ErrInvalidDictSize, got %v", ds, err)
		}
	}
}

func TestExplodeRejectsInvalidMode(t *testing.T) {
	if _, err := Explode([]byte{2, 4, 0, 0, 0}, 0); err != ErrInvalidMode {
		t.Errorf("want ErrInvalidMode, got %v", err)
	}
}
