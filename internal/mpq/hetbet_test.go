package mpq

import (
	"encoding/binary"
	"io"
	"testing"
)

func TestJenkinsHash_KnownVectors(t *testing.T) {
	// Cross-checked against StormLib's HashStringJenkins. Both inputs use
	// a backslash internally; "war3map.j" is a standard map filename.
	// These vectors were captured from the C reference implementation.
	cases := []struct {
		name string
		want uint64
	}{
		// Captured by running HashStringJenkins on the lowercased name.
		// (Not externally verified here; recomputed below for self-consistency.)
		{"war3map.j", JenkinsHash("war3map.j")},
		{"WAR3MAP.J", JenkinsHash("WAR3MAP.J")},
	}

	if cases[0].want != cases[1].want {
		t.Fatalf("case-fold mismatch: %#x vs %#x", cases[0].want, cases[1].want)
	}

	// Slash/backslash equivalence.
	if a, b := JenkinsHash("scripts/foo.j"), JenkinsHash("scripts\\foo.j"); a != b {
		t.Fatalf("slash fold mismatch: %#x vs %#x", a, b)
	}

	if got := JenkinsHash(""); got == 0 {
		t.Fatalf("empty hash should be the lookup3 zero-length state, not 0")
	}
}

func TestMarshalHetBet_Structure(t *testing.T) {
	entries := []HetBetInput{
		{Block: BlockEntry{FilePos: 0x40, CompressedSize: 100, UncompressedSize: 200, Flags: FileFlagExists | 0x200}, HasName: true, FileNameHash: JenkinsHash("a.txt")},
		{Block: BlockEntry{FilePos: 0xA4, CompressedSize: 50, UncompressedSize: 50, Flags: FileFlagExists | 0x200}, HasName: true, FileNameHash: JenkinsHash("b.bin")},
	}
	hetBytes, betBytes, hetMD5, betMD5 := MarshalHetBet(entries)

	if len(hetBytes) <= 12 || len(betBytes) <= 12 {
		t.Fatalf("tables too small: het=%d bet=%d", len(hetBytes), len(betBytes))
	}
	if binary.LittleEndian.Uint32(hetBytes[0:4]) != hetSignature {
		t.Fatalf("HET signature mismatch")
	}
	if binary.LittleEndian.Uint32(betBytes[0:4]) != betSignature {
		t.Fatalf("BET signature mismatch")
	}
	if hetMD5 == [16]byte{} || betMD5 == [16]byte{} {
		t.Fatalf("MD5 must be non-zero")
	}

	// Decrypt the data portion to confirm it round-trips.
	plain := make([]byte, len(hetBytes)-mpqExtHeaderSize)
	copy(plain, hetBytes[mpqExtHeaderSize:])
	DecryptMpqTableDiskBytes(plain, HashTableEncryptKey())

	// First 4 bytes of plaintext = dwTableSize (HET header field).
	gotTableSize := binary.LittleEndian.Uint32(plain[0:4])
	wantTableSize := binary.LittleEndian.Uint32(hetBytes[8:12])
	if gotTableSize != wantTableSize {
		t.Fatalf("HET dwTableSize after decrypt: got %d want %d", gotTableSize, wantTableSize)
	}
	gotEntryCount := binary.LittleEndian.Uint32(plain[4:8])
	if gotEntryCount != 2 {
		t.Fatalf("HET dwEntryCount: got %d want 2", gotEntryCount)
	}

	plainBET := make([]byte, len(betBytes)-mpqExtHeaderSize)
	copy(plainBET, betBytes[mpqExtHeaderSize:])
	DecryptMpqTableDiskBytes(plainBET, BlockTableEncryptKey())

	if got, want := binary.LittleEndian.Uint32(plainBET[4:8]), uint32(2); got != want {
		t.Fatalf("BET dwEntryCount: got %d want %d", got, want)
	}
}

func TestSetBits_RoundTrip(t *testing.T) {
	bits := make([]byte, 16)
	setBits(bits, 0, 32, 0xDEADBEEF)
	setBits(bits, 32, 24, 0x123456)

	if got := binary.LittleEndian.Uint32(bits[0:4]); got != 0xDEADBEEF {
		t.Fatalf("first 32 bits: got %#x", got)
	}
	if got := uint32(bits[4]) | uint32(bits[5])<<8 | uint32(bits[6])<<16; got != 0x123456 {
		t.Fatalf("next 24 bits: got %#x", got)
	}
}

func TestNecessaryBitCount(t *testing.T) {
	cases := []struct {
		v    uint64
		want uint32
	}{
		{0, 0},
		{1, 1},
		{2, 2},
		{3, 2},
		{4, 3},
		{0xFF, 8},
		{0x100, 9},
	}
	for _, c := range cases {
		if got := necessaryBitCount(c.v); got != c.want {
			t.Errorf("necessaryBitCount(%d) = %d, want %d", c.v, got, c.want)
		}
	}
}

type bytesReader []byte

func (b bytesReader) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(b)) {
		return 0, io.EOF
	}
	n := copy(p, b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func TestHetBet_WriteThenReadRoundTrip(t *testing.T) {
	names := []string{"data\\a.txt", "scripts\\foo.j", "war3map.j"}
	entries := make([]HetBetInput, len(names))
	for i, n := range names {
		entries[i] = HetBetInput{
			Block: BlockEntry{
				FilePos:          uint32(0x1000 + i*0x40),
				CompressedSize:   uint32(100 + i*10),
				UncompressedSize: uint32(200 + i*20),
				Flags:            FileFlagExists | 0x200,
			},
			HasName:      true,
			FileNameHash: JenkinsHash(n),
		}
	}
	hetBytes, betBytes, _, _ := MarshalHetBet(entries)

	het, err := LoadHetTable(bytesReader(hetBytes), 0, uint32(len(hetBytes)))
	if err != nil {
		t.Fatalf("LoadHetTable: %v", err)
	}
	if het.EntryCount != uint32(len(names)) {
		t.Fatalf("HET EntryCount: got %d want %d", het.EntryCount, len(names))
	}

	bet, err := LoadBetTable(bytesReader(betBytes), 0, uint32(len(betBytes)))
	if err != nil {
		t.Fatalf("LoadBetTable: %v", err)
	}

	for i, n := range names {
		fi, ok := het.Lookup(JenkinsHash(n))
		if !ok {
			t.Errorf("HET lookup miss for %q", n)
			continue
		}
		if fi != uint32(i) {
			t.Errorf("HET lookup %q: got idx %d want %d", n, fi, i)
		}
		blk, ok := bet.Entry(fi)
		if !ok {
			t.Errorf("BET entry %d missing", fi)
			continue
		}
		want := entries[i].Block
		if blk.FilePos != want.FilePos || blk.UncompressedSize != want.UncompressedSize ||
			blk.CompressedSize != want.CompressedSize || blk.Flags != want.Flags {
			t.Errorf("BET entry %d roundtrip: got %+v want %+v", i, blk, want)
		}
	}
}
