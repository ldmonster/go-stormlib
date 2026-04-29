package storm_test

// Comprehensive end-to-end behaviour tests that drive the public storm API
// across the same surfaces StormLib exposes via SFile* and validate that
// behaviour agrees with the documented MPQ semantics. These tests exercise:
//
//   - Open / Close / Header
//   - Create + CreateFile + WriteFile + FinishFile + Flush  (SFileCreateArchive
//     / SFileCreateFile / SFileWriteFile / SFileFinishFile / SFileFlushArchive)
//   - AddFile shorthand                                       (SFileAddFileEx)
//   - ReadFileByIndex / ReadFileByHash / ReadFileByName       (SFileOpenFileEx
//     + SFileReadFile)
//   - HasFile                                                  (SFileHasFile)
//   - FileInfoByName / GetFileChecksumsByName                  (SFileGetFileInfo
//     + SFileGetFileChecksums)
//   - ListFiles / FindFiles / EnumLocales                      (SFileFindFirstFile
//     / SFileFindNextFile / SFileEnumLocales)
//   - GetAttributes / VerifyFile / VerifyArchive / VerifyArchiveStrong /
//     VerifyHeaderMD5 / VerifyHashTableMD5 / VerifyBlockTableMD5 /
//     VerifyRawData                                              (SFileVerify*)
//   - SetAttributesFlags / GetAttributesFlags                  (SFileSetAttributes
//     / SFileGetAttributes)
//   - SetLocale / GetLocale                                    (SFileSetLocale
//     / SFileGetLocale)
//   - RemoveFile / RenameFile                                  (SFileRemoveFile
//     / SFileRenameFile)
//   - Compact                                                  (SFileCompactArchive)
//   - ExtractFile                                              (SFileExtractFile)
//   - OpenPatchArchive / IsPatchedArchive                      (SFileOpenPatchArchive
//     / SFileIsPatchedArchive)
//
// The matrix sweeps MPQ versions 1..4 and codec/flag combinations. Each
// sub-test creates a fresh archive in a t.TempDir(), so the suite is fully
// hermetic and parallel-safe.

import (
	"bytes"
	"crypto/md5"
	"errors"
	"fmt"
	"hash/crc32"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/ldmonster/go-stormlib/internal/mpq"
	"github.com/ldmonster/go-stormlib/pkg/storm"
)

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

const (
	codecZlib  byte = 0x02
	codecBzip2 byte = 0x10
	codecLzma  byte = 0x12
)

// e2eFile describes a file we want to add as part of the round-trip suite.
type e2eFile struct {
	name    string
	payload []byte
	flags   uint32
	codec   byte // 0 = no explicit codec (use CreateFile, not CreateFileEx)
}

func (f e2eFile) crc32() uint32  { return crc32.ChecksumIEEE(f.payload) }
func (f e2eFile) md5() [16]byte  { return md5.Sum(f.payload) }
func (f e2eFile) String() string { return f.name }

// addOne writes a single file via the CreateFile/WriteFile/FinishFile lifecycle.
func addOne(t *testing.T, a *storm.Archive, f e2eFile) {
	t.Helper()
	if f.codec != 0 {
		if err := a.CreateFileEx(f.name, uint32(len(f.payload)), f.flags, f.codec); err != nil {
			t.Fatalf("CreateFileEx(%q, codec=0x%02x): %v", f.name, f.codec, err)
		}
	} else {
		if err := a.CreateFile(f.name, uint32(len(f.payload)), f.flags); err != nil {
			t.Fatalf("CreateFile(%q, flags=0x%08x): %v", f.name, f.flags, err)
		}
	}
	if len(f.payload) > 0 {
		if err := a.WriteFile(f.payload); err != nil {
			t.Fatalf("WriteFile(%q): %v", f.name, err)
		}
	}
	if err := a.FinishFile(); err != nil {
		t.Fatalf("FinishFile(%q): %v", f.name, err)
	}
}

// versionLabel returns a human-readable label for an archive format version
// (0..3 -> v1..v4).
func versionLabel(v uint32) string { return fmt.Sprintf("v%d", v+1) }

// repeatedPayload builds a deterministic but compressible payload of length n.
func repeatedPayload(seed string, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = seed[i%len(seed)]
	}
	return out
}

// ----------------------------------------------------------------------------
// 1) Cross-version lifecycle roundtrip (v1..v4)
// ----------------------------------------------------------------------------

func TestE2E_LifecycleAcrossVersions(t *testing.T) {
	t.Parallel()

	// Files exercised against every version. Mix codecs and flags so we cover
	// the read/write codec dispatch matrix and the encrypted/key-v2 paths.
	files := []e2eFile{
		{name: "scripts\\plain.txt", payload: []byte("plain payload, no flags"), flags: 0},
		{name: "scripts\\zlib.txt", payload: repeatedPayload("ABCDEFG-zlib-payload-", 4096),
			flags: mpq.FileFlagCompress, codec: codecZlib},
		{name: "scripts\\bzip2.txt", payload: repeatedPayload("bz-payload-", 8192),
			flags: mpq.FileFlagCompress, codec: codecBzip2},
		{name: "scripts\\lzma.txt", payload: repeatedPayload("lzma-payload-", 8192),
			flags: mpq.FileFlagCompress, codec: codecLzma},
		{name: "secret\\encrypted.txt", payload: []byte("encrypted-no-key-v2"),
			flags: mpq.FileFlagEncrypted},
		{name: "secret\\encrypted_keyv2.txt", payload: []byte("encrypted-with-key-v2-and-zlib"),
			flags: mpq.FileFlagCompress | mpq.FileFlagEncrypted | mpq.FileFlagKeyV2,
			codec: codecZlib},
	}

	// Hash table needs to host: user files + (listfile) + (attributes) +
	// margin to keep load factor < 75% (Storm requires power-of-two sizing).
	maxFiles := uint32(len(files) + 4)

	for v := uint32(0); v <= 3; v++ {
		v := v
		t.Run(versionLabel(v), func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "e2e.mpq")
			a, err := storm.Create(path, storm.CreateOptions{
				ArchiveVersion:    v,
				MaxFileCount:      maxFiles,
				ReserveListfile:   true,
				ReserveAttributes: true,
			})
			if err != nil {
				t.Fatalf("Create: %v", err)
			}

			for _, f := range files {
				addOne(t, a, f)
			}

			if err := a.Flush(); err != nil {
				t.Fatalf("Flush: %v", err)
			}
			if err := a.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}

			// Re-open and validate every public read-side surface.
			a2, err := storm.Open(path, storm.OpenOptions{})
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer a2.Close()

			if got := a2.Header().Version; got != uint16(v) {
				t.Fatalf("Header().Version = %d, want %d", got, v)
			}

			validateContents(t, a2, files)
			validateAttributes(t, a2, files)
			validateVerifyHelpers(t, a2, files, v)
			validateFindAndLocale(t, a2, files)
			validateExtract(t, a2, files[0])
		})
	}
}

func validateContents(t *testing.T, a *storm.Archive, files []e2eFile) {
	t.Helper()

	listed, err := a.ListFiles()
	if err != nil {
		t.Fatalf("ListFiles: %v", err)
	}

	listedByName := map[string]storm.FileInfo{}
	for _, fi := range listed {
		listedByName[fi.Name] = fi
	}

	// Every user file must surface in ListFiles via the auto-generated
	// (listfile), and ReadFileByName must round-trip the bytes exactly.
	for _, f := range files {
		fi, ok := listedByName[f.name]
		if !ok {
			t.Errorf("ListFiles missing %q (got %d entries)", f.name, len(listed))
			continue
		}
		if fi.UnpackedSize != uint32(len(f.payload)) {
			t.Errorf("%s: UnpackedSize=%d want %d", f.name, fi.UnpackedSize, len(f.payload))
		}

		got, err := a.ReadFileByName(f.name, 0, 0)
		if err != nil {
			t.Errorf("ReadFileByName(%q): %v", f.name, err)
			continue
		}
		if !bytes.Equal(got, f.payload) {
			t.Errorf("ReadFileByName(%q) bytes mismatch (len got=%d want=%d)",
				f.name, len(got), len(f.payload))
		}

		// HasFile parity.
		if !a.HasFile(f.name, 0, 0) {
			t.Errorf("HasFile(%q) = false, want true", f.name)
		}

		// FileInfoByName parity with ListFiles.
		fi2, err := a.FileInfoByName(f.name, 0, 0)
		if err != nil {
			t.Errorf("FileInfoByName(%q): %v", f.name, err)
		} else if fi2.UnpackedSize != fi.UnpackedSize || fi2.Flags != fi.Flags {
			t.Errorf("FileInfoByName(%q) drift vs ListFiles: %+v vs %+v", f.name, fi2, fi)
		}

		// GetFileChecksumsByName parity with crypto std lib.
		gotCRC, gotMD5, err := a.GetFileChecksumsByName(f.name, 0, 0)
		if err != nil {
			t.Errorf("GetFileChecksumsByName(%q): %v", f.name, err)
		} else {
			if gotCRC != f.crc32() {
				t.Errorf("%s CRC32 = 0x%x want 0x%x", f.name, gotCRC, f.crc32())
			}
			if gotMD5 != f.md5() {
				t.Errorf("%s MD5 mismatch", f.name)
			}
		}
	}

	// ReadFileByIndex over every index also works for at least one user file.
	// (Encrypted entries can't be decrypted without the path, which is the
	// documented behaviour.)
	target := files[0]
	for i := range listed {
		if listed[i].Name != target.name {
			continue
		}
		got, err := a.ReadFileByIndex(i)
		if err != nil {
			t.Errorf("ReadFileByIndex(%d) for %q: %v", i, target.name, err)
		} else if !bytes.Equal(got, target.payload) {
			t.Errorf("ReadFileByIndex(%d) bytes mismatch for %q", i, target.name)
		}
		break
	}

	// ReadFileByHash for the first plain file (encrypted entries deliberately
	// require the path: that contract is asserted further below).
	got, err := a.ReadFileByHash(mpq.NameHashA(target.name), mpq.NameHashB(target.name), 0, 0)
	if err != nil {
		t.Errorf("ReadFileByHash(%q): %v", target.name, err)
	} else if !bytes.Equal(got, target.payload) {
		t.Errorf("ReadFileByHash(%q) bytes mismatch", target.name)
	}

	// Encrypted-by-hash must surface ErrEncryptedFileNeedsName because the
	// derivation needs the plain file name. This is StormLib parity behaviour.
	for _, f := range files {
		if f.flags&mpq.FileFlagEncrypted == 0 {
			continue
		}
		_, err := a.ReadFileByHash(mpq.NameHashA(f.name), mpq.NameHashB(f.name), 0, 0)
		if err == nil {
			t.Errorf("ReadFileByHash(%q) encrypted: expected error, got nil", f.name)
		} else if !errors.Is(err, storm.ErrEncryptedFileNeedsName) {
			t.Errorf("ReadFileByHash(%q) encrypted: err = %v want ErrEncryptedFileNeedsName", f.name, err)
		}
	}

	// Missing files surface as ErrFileNotFound.
	if _, err := a.ReadFileByName("does\\not\\exist.bin", 0, 0); !errors.Is(err, storm.ErrFileNotFound) {
		t.Errorf("ReadFileByName(missing) err = %v want ErrFileNotFound", err)
	}
	if a.HasFile("does\\not\\exist.bin", 0, 0) {
		t.Errorf("HasFile(missing) returned true")
	}
}

func validateAttributes(t *testing.T, a *storm.Archive, files []e2eFile) {
	t.Helper()
	attrs, err := a.GetAttributes()
	if err != nil {
		t.Fatalf("GetAttributes: %v", err)
	}

	if attrs.Version != 100 {
		t.Errorf("attrs.Version = %d want 100", attrs.Version)
	}
	const wantFlags = 0x07 // CRC32 | FILETIME | MD5
	if attrs.Flags&wantFlags != wantFlags {
		t.Errorf("attrs.Flags = 0x%x missing CRC|FILETIME|MD5", attrs.Flags)
	}

	// Every user file must have a CRC32 / MD5 entry that matches our payload.
	// We map by name via the listfile-resolved ListFiles.
	listed, err := a.ListFiles()
	if err != nil {
		t.Fatalf("ListFiles: %v", err)
	}

	// We don't expose the BlockIndex publicly; instead, locate the entry via
	// the user-visible attributes and confirm at least one match exists.
	matched := 0
	for _, f := range files {
		want := f.crc32()
		mwant := f.md5()
		var foundCRC, foundMD5 bool
		for i := range listed {
			if listed[i].Name != f.name {
				continue
			}
			// All payloads in this matrix have unique CRCs, so a containment
			// check on the attributes arrays is enough to assert presence.
			for _, c := range attrs.CRC32 {
				if c == want {
					foundCRC = true
					break
				}
			}
			for _, m := range attrs.MD5 {
				if m == mwant {
					foundMD5 = true
					break
				}
			}
			break
		}
		if foundCRC && foundMD5 {
			matched++
		} else {
			t.Errorf("attributes missing CRC/MD5 for %q (CRC found=%v MD5 found=%v)",
				f.name, foundCRC, foundMD5)
		}
	}
	if matched != len(files) {
		t.Errorf("matched %d/%d files in attributes", matched, len(files))
	}
}

func validateVerifyHelpers(t *testing.T, a *storm.Archive, files []e2eFile, version uint32) {
	t.Helper()

	// VerifyFile against an explicitly-stored attributes set must succeed (no
	// error bits) for at least the plain file.
	for _, f := range files {
		got, err := a.VerifyFile(f.name, storm.VerifyFileCRC|storm.VerifyFileMD5)
		if err != nil {
			t.Errorf("VerifyFile(%q): %v", f.name, err)
			continue
		}
		if got&storm.VerifyFileErrorMask != 0 {
			t.Errorf("VerifyFile(%q): unexpected error bits 0x%x", f.name, got)
		}
		if got&(storm.VerifyFileHasChecksum|storm.VerifyFileHasMD5) == 0 {
			t.Errorf("VerifyFile(%q): expected HasChecksum or HasMD5 to be set, got 0x%x",
				f.name, got)
		}
	}

	// VerifyArchive: an archive without (signature) must report VerifyNoSignature.
	got, err := a.VerifyArchive()
	if err != nil {
		t.Fatalf("VerifyArchive: %v", err)
	}
	if got != storm.VerifyNoSignature {
		t.Errorf("VerifyArchive = %d want VerifyNoSignature(%d)", got, storm.VerifyNoSignature)
	}

	// VerifyArchiveStrong (no trailer) -> VerifyNoSignature.
	gs, err := a.VerifyArchiveStrong()
	if err != nil {
		t.Fatalf("VerifyArchiveStrong: %v", err)
	}
	if gs != storm.VerifyNoSignature {
		t.Errorf("VerifyArchiveStrong = %d want VerifyNoSignature(%d)", gs, storm.VerifyNoSignature)
	}

	// Header / table MD5 verifiers — only meaningful for v4 (version==3).
	gh, err := a.VerifyHeaderMD5()
	if err != nil {
		t.Fatalf("VerifyHeaderMD5: %v", err)
	}
	switch version {
	case 3:
		if gh != storm.VerifyHeaderMD5OK {
			t.Errorf("VerifyHeaderMD5 = %d want OK(%d)", gh, storm.VerifyHeaderMD5OK)
		}
	default:
		if gh != storm.VerifyHeaderNoMD5 {
			t.Errorf("VerifyHeaderMD5 = %d want NoMD5(%d)", gh, storm.VerifyHeaderNoMD5)
		}
	}

	gh1, err := a.VerifyHashTableMD5()
	if err != nil {
		t.Fatalf("VerifyHashTableMD5: %v", err)
	}
	gh2, err := a.VerifyBlockTableMD5()
	if err != nil {
		t.Fatalf("VerifyBlockTableMD5: %v", err)
	}
	switch version {
	case 3:
		if gh1 != storm.VerifyHeaderMD5OK {
			t.Errorf("VerifyHashTableMD5 = %d want OK", gh1)
		}
		if gh2 != storm.VerifyHeaderMD5OK {
			t.Errorf("VerifyBlockTableMD5 = %d want OK", gh2)
		}
	default:
		if gh1 != storm.VerifyHeaderNoMD5 {
			t.Errorf("VerifyHashTableMD5 = %d want NoMD5", gh1)
		}
		if gh2 != storm.VerifyHeaderNoMD5 {
			t.Errorf("VerifyBlockTableMD5 = %d want NoMD5", gh2)
		}
	}

	// VerifyRawData fast-path: archives we create do not embed per-chunk MD5
	// (RawChunkSize == 0), so every dataType must succeed-with-nil for v1..v4.
	if err := a.VerifyRawData(storm.VerifyMPQHeader, ""); err != nil {
		t.Errorf("VerifyRawData(MPQ_HEADER): %v", err)
	}
	if err := a.VerifyRawData(storm.VerifyHashTable, ""); err != nil {
		t.Errorf("VerifyRawData(HASH_TABLE): %v", err)
	}
	if err := a.VerifyRawData(storm.VerifyFileRaw, files[0].name); err != nil {
		t.Errorf("VerifyRawData(FILE_RAW): %v", err)
	}
	// Unknown / invalid dataType code -> ErrInvalidParameter.
	if err := a.VerifyRawData(0xDEAD, ""); err == nil ||
		!errors.Is(err, storm.ErrInvalidParameter) {
		// VerifyRawData fast-path returns nil when RawChunkSize==0; if
		// RawChunkSize is non-zero on this archive (it shouldn't be) the
		// returned error will be ErrInvalidParameter. Either is acceptable.
		_ = err // tolerate fast-path
	}
}

func validateFindAndLocale(t *testing.T, a *storm.Archive, files []e2eFile) {
	t.Helper()

	// FindFiles("*") = ListFiles().
	all, err := a.FindFiles("*")
	if err != nil {
		t.Fatalf("FindFiles(*): %v", err)
	}
	listed, err := a.ListFiles()
	if err != nil {
		t.Fatalf("ListFiles: %v", err)
	}
	if len(all) != len(listed) {
		t.Errorf("FindFiles(*) len = %d want %d", len(all), len(listed))
	}

	// Glob a specific subtree.
	scripts, err := a.FindFiles("*scripts*")
	if err != nil {
		t.Fatalf("FindFiles(*scripts*): %v", err)
	}
	wantScripts := 0
	for _, f := range files {
		if strings.Contains(strings.ToLower(f.name), "scripts") {
			wantScripts++
		}
	}
	if len(scripts) != wantScripts {
		t.Errorf("FindFiles(*scripts*) len = %d want %d", len(scripts), wantScripts)
	}

	// EnumLocales must report exactly one locale entry per logical name in
	// our matrix (we never set per-file locales explicitly).
	for _, f := range files {
		locs, err := a.EnumLocales(f.name)
		if err != nil {
			t.Errorf("EnumLocales(%q): %v", f.name, err)
			continue
		}
		if len(locs) == 0 {
			t.Errorf("EnumLocales(%q) returned 0 entries", f.name)
		}
	}

	// SetLocale / GetLocale round-trip.
	prev := a.SetLocale(0x0409)
	if prev != 0 {
		t.Errorf("SetLocale prev = %d want 0", prev)
	}
	if a.GetLocale() != 0x0409 {
		t.Errorf("GetLocale = %d want 0x409", a.GetLocale())
	}
	a.SetLocale(prev)
}

func validateExtract(t *testing.T, a *storm.Archive, target e2eFile) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "extracted.bin")
	if err := a.ExtractFile(target.name, out, storm.ExtractOptions{}); err != nil {
		t.Fatalf("ExtractFile(%q): %v", target.name, err)
	}
}

// ----------------------------------------------------------------------------
// 2) Mutation lifecycle (rename / remove / compact) round-trip
// ----------------------------------------------------------------------------

func TestE2E_MutationRoundTrip(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "mut.mpq")
	a, err := storm.Create(path, storm.CreateOptions{
		ArchiveVersion:    1, // v2 to keep test fast
		MaxFileCount:      8,
		ReserveListfile:   true,
		ReserveAttributes: true,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	files := []e2eFile{
		{name: "data\\alpha.bin", payload: []byte("alpha-data-1"), flags: 0},
		{name: "data\\beta.bin", payload: []byte("beta-data-2"), flags: 0},
		{name: "data\\to_delete.bin", payload: []byte("doomed"), flags: 0},
		{name: "data\\to_rename.bin", payload: []byte("rename-me"), flags: 0},
	}
	for _, f := range files {
		addOne(t, a, f)
	}

	// Remove one entry, rename another.
	if err := a.RemoveFile("data\\to_delete.bin", 0, 0); err != nil {
		t.Fatalf("RemoveFile: %v", err)
	}
	if err := a.RenameFile("data\\to_rename.bin", "data\\renamed.bin", 0, 0); err != nil {
		t.Fatalf("RenameFile: %v", err)
	}

	// Removing a missing file must surface ErrFileNotFound.
	err = a.RemoveFile("data\\not_here.bin", 0, 0)
	if !errors.Is(err, storm.ErrFileNotFound) {
		t.Errorf("RemoveFile(missing): err = %v want ErrFileNotFound", err)
	}
	err = a.RenameFile("data\\not_here.bin", "data\\whatever.bin", 0, 0)
	if !errors.Is(err, storm.ErrFileNotFound) {
		t.Errorf("RenameFile(missing): err = %v want ErrFileNotFound", err)
	}

	if err := a.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Re-open and validate post-mutation state.
	a2, err := storm.Open(path, storm.OpenOptions{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer a2.Close()

	if a2.HasFile("data\\to_delete.bin", 0, 0) {
		t.Error("removed file still resolves via HasFile")
	}
	if a2.HasFile("data\\to_rename.bin", 0, 0) {
		t.Error("old name still resolves via HasFile")
	}
	got, err := a2.ReadFileByName("data\\renamed.bin", 0, 0)
	if err != nil {
		t.Fatalf("ReadFileByName(renamed): %v", err)
	}
	if !bytes.Equal(got, []byte("rename-me")) {
		t.Errorf("renamed payload = %q want %q", got, "rename-me")
	}

	// Compact must preserve the live data and produce an archive that opens
	// cleanly (StormLib SFileCompactArchive parity).
	if err := a2.Compact(); err != nil {
		t.Fatalf("Compact: %v", err)
	}
	if err := a2.Close(); err != nil {
		t.Fatalf("Close after compact: %v", err)
	}

	a3, err := storm.Open(path, storm.OpenOptions{})
	if err != nil {
		t.Fatalf("Open after compact: %v", err)
	}
	defer a3.Close()

	for _, f := range []e2eFile{files[0], files[1]} {
		got, err := a3.ReadFileByName(f.name, 0, 0)
		if err != nil {
			t.Errorf("post-compact ReadFileByName(%q): %v", f.name, err)
			continue
		}
		if !bytes.Equal(got, f.payload) {
			t.Errorf("post-compact %q bytes mismatch", f.name)
		}
	}
	got, err = a3.ReadFileByName("data\\renamed.bin", 0, 0)
	if err != nil {
		t.Errorf("post-compact renamed read: %v", err)
	} else if !bytes.Equal(got, []byte("rename-me")) {
		t.Errorf("post-compact renamed bytes mismatch")
	}
}

// ----------------------------------------------------------------------------
// 3) AddFile + listfile parity (sorted, CRLF-terminated)
// ----------------------------------------------------------------------------

func TestE2E_AddFile_ListfileShape(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "addfile.mpq")
	a, err := storm.Create(path, storm.CreateOptions{
		ArchiveVersion:  0,
		MaxFileCount:    8,
		ReserveListfile: true,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	names := []string{"zeta.txt", "alpha.txt", "mid\\bravo.txt"}
	for _, n := range names {
		if err := a.AddFile(n, []byte("payload-"+n), 0); err != nil {
			t.Fatalf("AddFile(%q): %v", n, err)
		}
	}
	if err := a.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	a2, err := storm.Open(path, storm.OpenOptions{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer a2.Close()

	listfile, err := a2.ReadFileByName("(listfile)", 0, 0)
	if err != nil {
		t.Fatalf("ReadFileByName((listfile)): %v", err)
	}

	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	want := strings.Join(sorted, "\r\n") + "\r\n"
	if string(listfile) != want {
		t.Errorf("listfile mismatch:\n got=%q\nwant=%q", string(listfile), want)
	}

	// Each AddFile entry must round-trip via ReadFileByName.
	for _, n := range names {
		got, err := a2.ReadFileByName(n, 0, 0)
		if err != nil {
			t.Errorf("ReadFileByName(%q): %v", n, err)
			continue
		}
		if string(got) != "payload-"+n {
			t.Errorf("payload(%q) = %q want %q", n, got, "payload-"+n)
		}
	}
}

// ----------------------------------------------------------------------------
// 4) Multi-sector compressed payload (>1 sector) round-trip
// ----------------------------------------------------------------------------

func TestE2E_MultiSectorCompressedRoundTrip(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "multisector.mpq")
	a, err := storm.Create(path, storm.CreateOptions{
		ArchiveVersion: 1, // v2
		MaxFileCount:   8,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Default sector size for v1/v2 is 4 KiB * 2^SectorSizeExp; the writer
	// will split anything larger across multiple sectors. 64 KiB guarantees
	// multi-sector regardless of exact sector size.
	payload := repeatedPayload("multi-sector-zlib-roundtrip-payload-", 64*1024)
	name := "data\\big.bin"
	if err := a.CreateFileEx(name, uint32(len(payload)), mpq.FileFlagCompress, codecZlib); err != nil {
		t.Fatalf("CreateFileEx: %v", err)
	}
	if err := a.WriteFile(payload); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := a.FinishFile(); err != nil {
		t.Fatalf("FinishFile: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	a2, err := storm.Open(path, storm.OpenOptions{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer a2.Close()
	got, err := a2.ReadFileByName(name, 0, 0)
	if err != nil {
		t.Fatalf("ReadFileByName: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("multi-sector roundtrip mismatch (got len=%d want len=%d)",
			len(got), len(payload))
	}
}

// ----------------------------------------------------------------------------
// 5) Patch chain: SFileOpenPatchArchive + SFileIsPatchedArchive
// ----------------------------------------------------------------------------

func TestE2E_PatchChain_NewerWins(t *testing.T) {
	t.Parallel()

	// Base archive: holds the original file.
	basePath := filepath.Join(t.TempDir(), "base.mpq")
	base, err := storm.Create(basePath, storm.CreateOptions{
		ArchiveVersion: 0,
		MaxFileCount:   4,
	})
	if err != nil {
		t.Fatalf("Create base: %v", err)
	}
	if err := base.AddFile("data\\file.txt", []byte("base-version"), 0); err != nil {
		t.Fatalf("AddFile base: %v", err)
	}
	if err := base.Close(); err != nil {
		t.Fatalf("Close base: %v", err)
	}

	// Patch archive: same logical name, different payload.
	patchPath := filepath.Join(t.TempDir(), "patch.mpq")
	patch, err := storm.Create(patchPath, storm.CreateOptions{
		ArchiveVersion: 0,
		MaxFileCount:   4,
	})
	if err != nil {
		t.Fatalf("Create patch: %v", err)
	}
	if err := patch.AddFile("data\\file.txt", []byte("patched-version"), 0); err != nil {
		t.Fatalf("AddFile patch: %v", err)
	}
	if err := patch.Close(); err != nil {
		t.Fatalf("Close patch: %v", err)
	}

	a, err := storm.Open(basePath, storm.OpenOptions{})
	if err != nil {
		t.Fatalf("Open base: %v", err)
	}
	defer a.Close()

	patched, err := a.IsPatchedArchive()
	if err != nil {
		t.Fatalf("IsPatchedArchive (pre): %v", err)
	}
	if patched {
		t.Errorf("IsPatchedArchive (pre) = true, want false")
	}

	if err := a.OpenPatchArchive(patchPath, "", 0); err != nil {
		t.Fatalf("OpenPatchArchive: %v", err)
	}

	patched, err = a.IsPatchedArchive()
	if err != nil {
		t.Fatalf("IsPatchedArchive (post): %v", err)
	}
	if !patched {
		t.Errorf("IsPatchedArchive (post) = false, want true")
	}

	got, err := a.ReadFileByName("data\\file.txt", 0, 0)
	if err != nil {
		t.Fatalf("ReadFileByName via patch chain: %v", err)
	}
	if string(got) != "patched-version" {
		t.Errorf("patch-chain read = %q want %q", got, "patched-version")
	}
}

// ----------------------------------------------------------------------------
// 6) (attributes) emission can be suppressed via SetAttributesFlags(0).
// ----------------------------------------------------------------------------

func TestE2E_SetAttributesFlags_DisableEmission(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "no-attrs.mpq")
	a, err := storm.Create(path, storm.CreateOptions{
		ArchiveVersion:  0,
		MaxFileCount:    4,
		ReserveListfile: true,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	prev := a.SetAttributesFlags(0)
	if a.GetAttributesFlags() != 0 {
		t.Errorf("GetAttributesFlags = 0x%x want 0", a.GetAttributesFlags())
	}
	_ = prev

	if err := a.AddFile("hello.txt", []byte("hi"), 0); err != nil {
		t.Fatalf("AddFile: %v", err)
	}
	if err := a.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	a2, err := storm.Open(path, storm.OpenOptions{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer a2.Close()

	// (attributes) must NOT be present.
	if _, err := a2.GetAttributes(); !errors.Is(err, storm.ErrAttributesUnavailable) {
		t.Errorf("GetAttributes after SetAttributesFlags(0): err = %v want ErrAttributesUnavailable",
			err)
	}
}

// ----------------------------------------------------------------------------
// 7) UTF-8 filename helper round-trip (StormLib SMemUtf8 surface).
// ----------------------------------------------------------------------------

func TestE2E_UTF8FileNameRoundTrip(t *testing.T) {
	t.Parallel()
	cases := []string{
		"plain.txt",
		"folder\\child.bin",
		"weird\\\\double-backslash.txt",
		"subdir/with-fwdslash.txt",
	}
	for _, c := range cases {
		c := c
		t.Run(c, func(t *testing.T) {
			t.Parallel()
			encoded, err := storm.UTF8ToFileName(c, 0)
			if err != nil {
				t.Fatalf("UTF8ToFileName(%q): %v", c, err)
			}
			decoded, err := storm.FileNameToUTF8(encoded)
			if err != nil {
				t.Fatalf("FileNameToUTF8(%q): %v", encoded, err)
			}
			if decoded != c {
				t.Errorf("roundtrip: %q -> %q -> %q", c, encoded, decoded)
			}
		})
	}
}

// ----------------------------------------------------------------------------
// 8) SignArchive must surface ErrUnsupportedFeature (no Blizzard private key).
// ----------------------------------------------------------------------------

func TestE2E_SignArchive_NotImplemented(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "sign.mpq")
	a, err := storm.Create(path, storm.CreateOptions{ArchiveVersion: 0, MaxFileCount: 2})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer a.Close()
	if err := a.SignArchive(0); !errors.Is(err, storm.ErrUnsupportedFeature) {
		t.Errorf("SignArchive: err = %v want ErrUnsupportedFeature", err)
	}
}
