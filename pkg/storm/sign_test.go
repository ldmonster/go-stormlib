package storm

import (
	"path/filepath"
	"testing"

	internalarchive "github.com/ldmonster/go-stormlib/internal/archive"
)

func TestVerifyArchive_NoSignature(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	p := filepath.Join(dir, "unsigned.mpq")
	if err := internalarchive.CreateEmpty(p, internalarchive.CreateOptions{}); err != nil {
		t.Fatalf("CreateEmpty: %v", err)
	}

	a, err := Open(p, OpenOptions{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	got, err := a.VerifyArchive()
	if err != nil {
		t.Fatalf("VerifyArchive: %v", err)
	}
	if got != VerifyNoSignature {
		t.Fatalf("VerifyArchive = %d, want VerifyNoSignature(%d)", got, VerifyNoSignature)
	}
}

func TestVerifyV4HeaderAndTableMD5_AfterMutation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	p := filepath.Join(dir, "v4-mutated.mpq")
	if err := internalarchive.CreateEmpty(p, internalarchive.CreateOptions{ArchiveFormat: 3, MaxFileCount: 4}); err != nil {
		t.Fatalf("CreateEmpty: %v", err)
	}

	a, err := Open(p, OpenOptions{})
	if err != nil {
		t.Fatalf("Open empty: %v", err)
	}
	if err := a.CreateFile("data\\file.bin", 11, 0); err != nil {
		t.Fatalf("CreateFile: %v", err)
	}
	if err := a.WriteFile([]byte("hello-world")); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := a.FinishFile(); err != nil {
		t.Fatalf("FinishFile: %v", err)
	}

	a2, err := Open(p, OpenOptions{})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if got, err := a2.VerifyHeaderMD5(); err != nil {
		t.Fatalf("VerifyHeaderMD5: %v", err)
	} else if got != VerifyHeaderMD5OK {
		t.Fatalf("VerifyHeaderMD5 = %d, want OK(%d)", got, VerifyHeaderMD5OK)
	}
	if got, err := a2.VerifyHashTableMD5(); err != nil {
		t.Fatalf("VerifyHashTableMD5: %v", err)
	} else if got != VerifyHeaderMD5OK {
		t.Fatalf("VerifyHashTableMD5 = %d, want OK(%d)", got, VerifyHeaderMD5OK)
	}
	if got, err := a2.VerifyBlockTableMD5(); err != nil {
		t.Fatalf("VerifyBlockTableMD5: %v", err)
	} else if got != VerifyHeaderMD5OK {
		t.Fatalf("VerifyBlockTableMD5 = %d, want OK(%d)", got, VerifyHeaderMD5OK)
	}
}
