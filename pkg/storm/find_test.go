package storm

import (
	"path/filepath"
	"testing"

	internalarchive "github.com/ldmonster/go-stormlib/internal/archive"
)

func TestFindFiles_GlobAndEnumLocales(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	p := filepath.Join(dir, "find.mpq")
	if err := internalarchive.CreateEmpty(p, internalarchive.CreateOptions{ArchiveFormat: 0, MaxFileCount: 8}); err != nil {
		t.Fatalf("CreateEmpty: %v", err)
	}

	a, err := Open(p, OpenOptions{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	add := func(name string, body []byte) {
		t.Helper()
		if err := a.CreateFile(name, uint32(len(body)), 0); err != nil {
			t.Fatalf("CreateFile %q: %v", name, err)
		}
		if err := a.WriteFile(body); err != nil {
			t.Fatalf("WriteFile %q: %v", name, err)
		}
		if err := a.FinishFile(); err != nil {
			t.Fatalf("FinishFile %q: %v", name, err)
		}
	}

	add("data\\a.bin", []byte("aaa"))
	add("data\\b.bin", []byte("bbb"))
	add("scripts\\boot.lua", []byte("--lua"))

	if err := a.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	matches, err := a.FindFiles("data\\*.bin")
	if err != nil {
		t.Fatalf("FindFiles: %v", err)
	}
	if len(matches) != 2 {
		t.Fatalf("FindFiles got %d, want 2: %+v", len(matches), matches)
	}

	all, err := a.FindFiles("*")
	if err != nil {
		t.Fatalf("FindFiles(*): %v", err)
	}
	if len(all) < 3 {
		t.Fatalf("FindFiles(*) got %d, want >=3", len(all))
	}

	// EnumLocales for an existing file returns at least one locale row.
	rows, err := a.EnumLocales("data\\a.bin")
	if err != nil {
		t.Fatalf("EnumLocales: %v", err)
	}
	if len(rows) == 0 {
		t.Fatalf("EnumLocales returned no rows")
	}
}
