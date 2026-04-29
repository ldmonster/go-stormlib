package storm

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"hash/crc32"
	"path/filepath"
	"testing"

	internalarchive "github.com/ldmonster/go-stormlib/internal/archive"
	"github.com/ldmonster/go-stormlib/internal/mpq"
)

func writeFile(t *testing.T, a *internalarchive.Archive, name string, payload []byte) {
	t.Helper()
	if err := a.CreateFile(name, uint32(len(payload)), 0); err != nil {
		t.Fatalf("CreateFile(%q): %v", name, err)
	}
	if err := a.WriteFile(payload); err != nil {
		t.Fatalf("WriteFile(%q): %v", name, err)
	}
	if err := a.FinishFile(); err != nil {
		t.Fatalf("FinishFile(%q): %v", name, err)
	}
}

func TestVerifyFile_CRC32AndMD5MatchAttributes(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	p := filepath.Join(dir, "verify.mpq")
	if err := internalarchive.CreateEmpty(p, internalarchive.CreateOptions{ArchiveFormat: 0, MaxFileCount: 0}); err != nil {
		t.Fatalf("CreateEmpty: %v", err)
	}

	a, err := internalarchive.OpenWithOptions(p, internalarchive.OpenOptions{})
	if err != nil {
		t.Fatalf("OpenWithOptions: %v", err)
	}

	payload := []byte("verify-target-file-bytes")
	writeFile(t, a, "data\\thing.txt", payload)

	// Build (attributes) for a 2-entry block table (data file + (attributes) itself):
	// CRC32 + MD5. The first entry corresponds to BlockIndex 0 (the data file);
	// the second entry corresponds to BlockIndex 1 (the (attributes) file payload itself,
	// values are zeroed and ignored by VerifyFile).
	mdsum := md5.Sum(payload)
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, uint32(100))                       // version
	binary.Write(&buf, binary.LittleEndian, uint32(attrFlagCRC32|attrFlagMD5)) // flags
	binary.Write(&buf, binary.LittleEndian, crc32.ChecksumIEEE(payload))
	binary.Write(&buf, binary.LittleEndian, uint32(0)) // attrs entry CRC32 (placeholder)
	buf.Write(mdsum[:])
	buf.Write(make([]byte, 16)) // attrs entry MD5 (placeholder)

	// Reopen to add (attributes) as a new file.
	a2, err := internalarchive.OpenWithOptions(p, internalarchive.OpenOptions{})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	// CreateFile validates that internal names are rejected. Inject directly
	// via a minimal hash/block append by writing under a non-internal name and
	// then renaming the entry's name hashes. Simpler: temporarily rename to a
	// neutral name then mutate the hash entry to be (attributes).
	const stagingName = "__attrstaging__"
	writeFile(t, a2, stagingName, buf.Bytes())

	// Mutate hash entry so the staged file is found under "(attributes)".
	stagedA := mpq.NameHashA(stagingName)
	stagedB := mpq.NameHashB(stagingName)
	attrA := mpq.NameHashA("(attributes)")
	attrB := mpq.NameHashB("(attributes)")
	for i := range a2.HashTable {
		if a2.HashTable[i].HashA == stagedA && a2.HashTable[i].HashB == stagedB {
			a2.HashTable[i].HashA = attrA
			a2.HashTable[i].HashB = attrB
			break
		}
	}
	// Persist mutated hash table.
	if err := persistTablesForTest(a2); err != nil {
		t.Fatalf("persist tables: %v", err)
	}

	arc, err := Open(p, OpenOptions{})
	if err != nil {
		t.Fatalf("storm.Open: %v", err)
	}

	got, err := arc.VerifyFile("data\\thing.txt", VerifyFileCRC|VerifyFileMD5)
	if err != nil {
		t.Fatalf("VerifyFile: %v", err)
	}
	wantBits := VerifyFileHasChecksum | VerifyFileHasMD5
	if got != wantBits {
		t.Fatalf("VerifyFile result = 0x%04x, want 0x%04x", got, wantBits)
	}
}

// persistTablesForTest re-marshals the hash/block tables and overwrites them on disk
// using internalarchive's internal helper. Test-only shim.
func persistTablesForTest(a *internalarchive.Archive) error {
	return a.PersistHeaderAndTablesForTest(a.Header, a.HashTable, a.BlockTable)
}
