package storm

import (
	"path/filepath"
	"testing"

	internalarchive "github.com/ldmonster/go-stormlib/internal/archive"
)

// VerifyRawData should report success on archives that don't carry raw-chunk
// MD5 trailers (RawChunkSize == 0). Our writer never populates RawChunkSize,
// so every archive we create takes this fast path regardless of format.
func TestVerifyRawData_NoRawChunkMD5(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		format uint16
	}{
		{"v1", 0},
		{"v4", 3},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			p := filepath.Join(dir, "raw.mpq")
			if err := internalarchive.CreateEmpty(p, internalarchive.CreateOptions{
				ArchiveFormat: tc.format, MaxFileCount: 4,
			}); err != nil {
				t.Fatalf("CreateEmpty: %v", err)
			}
			a, err := Open(p, OpenOptions{})
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			for _, dt := range []uint32{
				VerifyMPQHeader, VerifyHETTable, VerifyBETTable,
				VerifyHashTable, VerifyBlockTable, VerifyHiBlockTable,
			} {
				if err := a.VerifyRawData(dt, ""); err != nil {
					t.Fatalf("VerifyRawData(%d): %v", dt, err)
				}
			}
		})
	}
}

func TestSetAttributesFlags_DisableEmission(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	p := filepath.Join(dir, "noattr.mpq")
	if err := internalarchive.CreateEmpty(p, internalarchive.CreateOptions{MaxFileCount: 4}); err != nil {
		t.Fatalf("CreateEmpty: %v", err)
	}
	a, err := Open(p, OpenOptions{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	prev := a.SetAttributesFlags(0)
	if prev != (0x01 | 0x02 | 0x04) {
		t.Fatalf("SetAttributesFlags prev = %#x, want default 0x07", prev)
	}
	if got := a.GetAttributesFlags(); got != 0 {
		t.Fatalf("GetAttributesFlags = %#x, want 0", got)
	}

	if err := a.AddFile("data\\x.bin", []byte("payload"), 0x00000200); err != nil {
		t.Fatalf("AddFile: %v", err)
	}
	if err := a.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	a2, err := Open(p, OpenOptions{})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if _, err := a2.ReadFileByName("(attributes)", 0, 0); err == nil {
		t.Fatalf("(attributes) was emitted despite SetAttributesFlags(0)")
	}
}
