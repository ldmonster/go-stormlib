package archive

import (
	"bytes"
	"os"
	"testing"

	"github.com/ldmonster/go-stormlib/internal/mpq"
)

func TestCompact_RemovesGapsAndPreservesLiveData(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	p := dir + "/compact.mpq"
	if err := CreateEmpty(p, CreateOptions{ArchiveFormat: 0, MaxFileCount: 0}); err != nil {
		t.Fatalf("CreateEmpty: %v", err)
	}

	a, err := OpenWithOptions(p, OpenOptions{})
	if err != nil {
		t.Fatalf("OpenWithOptions: %v", err)
	}

	keep1 := []byte("keep-this-file-1")
	gone := bytes.Repeat([]byte("DELETE-ME-"), 200) // create a sizable hole
	keep2 := []byte("keep-this-file-2-payload")

	for _, x := range []struct {
		name    string
		payload []byte
	}{
		{"keep1.txt", keep1},
		{"gone.bin", gone},
		{"keep2.txt", keep2},
	} {
		if err := a.CreateFile(x.name, uint32(len(x.payload)), 0); err != nil {
			t.Fatalf("CreateFile(%q): %v", x.name, err)
		}
		if err := a.WriteFile(x.payload); err != nil {
			t.Fatalf("WriteFile(%q): %v", x.name, err)
		}
		if err := a.FinishFile(); err != nil {
			t.Fatalf("FinishFile(%q): %v", x.name, err)
		}
	}

	if err := a.RemoveFile("gone.bin", 0, 0); err != nil {
		t.Fatalf("RemoveFile: %v", err)
	}

	beforeStat, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat before: %v", err)
	}
	beforeSize := beforeStat.Size()

	if err := a.Compact(); err != nil {
		t.Fatalf("Compact: %v", err)
	}

	afterStat, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat after: %v", err)
	}
	if afterStat.Size() >= beforeSize {
		t.Errorf("compact did not shrink archive: before=%d after=%d", beforeSize, afterStat.Size())
	}

	a2, err := OpenWithOptions(p, OpenOptions{})
	if err != nil {
		t.Fatalf("reopen after compact: %v", err)
	}

	check := func(name string, want []byte) {
		t.Helper()
		h, err := a2.OpenIndexedFileByHash(mpq.NameHashA(name), mpq.NameHashB(name), 0, 0)
		if err != nil {
			t.Fatalf("open %q after compact: %v", name, err)
		}
		got, err := a2.ReadFile(h)
		if err != nil {
			t.Fatalf("read %q after compact: %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("file %q after compact = %q, want %q", name, got, want)
		}
	}

	check("keep1.txt", keep1)
	check("keep2.txt", keep2)

	if _, err := a2.OpenIndexedFileByHash(mpq.NameHashA("gone.bin"), mpq.NameHashB("gone.bin"), 0, 0); err == nil {
		t.Fatal("expected gone.bin to be absent after compact")
	}

	if got := len(a2.BlockTable); got != 2 {
		t.Fatalf("BlockTable len = %d, want 2", got)
	}
}

func TestCompact_V3V4_StripsHetBetAndPreservesData(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		archive uint16
	}{
		{"v3", 2},
		{"v4", 3},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			p := dir + "/compact-vN.mpq"
			if err := CreateEmpty(p, CreateOptions{ArchiveFormat: tc.archive, MaxFileCount: 4}); err != nil {
				t.Fatalf("CreateEmpty: %v", err)
			}

			a, err := OpenWithOptions(p, OpenOptions{})
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			keep := []byte("survivor-payload")
			gone := bytes.Repeat([]byte("BIG-HOLE-"), 256)

			for _, x := range []struct {
				name string
				data []byte
			}{
				{"keep.txt", keep},
				{"gone.bin", gone},
			} {
				if err := a.CreateFile(x.name, uint32(len(x.data)), 0); err != nil {
					t.Fatalf("CreateFile(%q): %v", x.name, err)
				}
				if err := a.WriteFile(x.data); err != nil {
					t.Fatalf("WriteFile(%q): %v", x.name, err)
				}
				if err := a.FinishFile(); err != nil {
					t.Fatalf("FinishFile(%q): %v", x.name, err)
				}
			}
			if err := a.RemoveFile("gone.bin", 0, 0); err != nil {
				t.Fatalf("RemoveFile: %v", err)
			}
			if err := a.Compact(); err != nil {
				t.Fatalf("Compact: %v", err)
			}

			a2, err := OpenWithOptions(p, OpenOptions{})
			if err != nil {
				t.Fatalf("reopen: %v", err)
			}
			if a2.Header.HetTablePos64 == 0 || a2.Header.BetTablePos64 == 0 {
				t.Fatalf("HET/BET missing after compact: het=%#x bet=%#x",
					a2.Header.HetTablePos64, a2.Header.BetTablePos64)
			}
			h, err := a2.OpenIndexedFileByHash(mpq.NameHashA("keep.txt"), mpq.NameHashB("keep.txt"), 0, 0)
			if err != nil {
				t.Fatalf("open keep.txt: %v", err)
			}
			got, err := a2.ReadFile(h)
			if err != nil {
				t.Fatalf("read keep.txt: %v", err)
			}
			if !bytes.Equal(got, keep) {
				t.Fatalf("keep payload mismatch: %q", got)
			}
		})
	}
}
