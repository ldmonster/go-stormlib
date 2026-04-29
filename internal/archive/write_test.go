// Copyright 2026 go-stormlib Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package archive

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"github.com/ldmonster/go-stormlib/internal/mpq"
)

func TestWriteLifecycle_CreateWriteFinish_ReopenReadByHash(t *testing.T) {
	t.Parallel()

	p := t.TempDir() + "/write-lifecycle.mpq"
	if err := CreateEmpty(p, CreateOptions{ArchiveFormat: 0, MaxFileCount: 0}); err != nil {
		t.Fatalf("CreateEmpty() error = %v", err)
	}

	a, err := OpenWithOptions(p, OpenOptions{})
	if err != nil {
		t.Fatalf("OpenWithOptions() error = %v", err)
	}

	name := "units\\human\\footman.txt"
	payload := []byte("file-write-lifecycle-payload")
	if err := a.CreateFile(name, uint32(len(payload)), 0); err != nil {
		t.Fatalf("CreateFile() error = %v", err)
	}
	if err := a.WriteFile(payload[:10]); err != nil {
		t.Fatalf("WriteFile(first) error = %v", err)
	}
	if err := a.WriteFile(payload[10:]); err != nil {
		t.Fatalf("WriteFile(second) error = %v", err)
	}
	if err := a.FinishFile(); err != nil {
		t.Fatalf("FinishFile() error = %v", err)
	}

	a2, err := OpenWithOptions(p, OpenOptions{})
	if err != nil {
		t.Fatalf("reopen error = %v", err)
	}

	h, err := a2.OpenIndexedFileByHash(mpq.NameHashA(name), mpq.NameHashB(name), 0, 0)
	if err != nil {
		t.Fatalf("OpenIndexedFileByHash() error = %v", err)
	}
	got, err := a2.ReadFile(h)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("ReadFile() bytes mismatch: got %q want %q", got, payload)
	}
}

func TestWriteLifecycle_RejectsOverrunAndIncomplete(t *testing.T) {
	t.Parallel()

	p := t.TempDir() + "/write-errors.mpq"
	if err := CreateEmpty(p, CreateOptions{ArchiveFormat: 0, MaxFileCount: 0}); err != nil {
		t.Fatalf("CreateEmpty() error = %v", err)
	}
	a, err := OpenWithOptions(p, OpenOptions{})
	if err != nil {
		t.Fatalf("OpenWithOptions() error = %v", err)
	}

	if err := a.CreateFile("x.txt", 3, 0); err != nil {
		t.Fatalf("CreateFile() error = %v", err)
	}
	if err := a.WriteFile([]byte("abcd")); err != ErrWriteSizeExceeded {
		t.Fatalf("WriteFile(overrun) error = %v, want %v", err, ErrWriteSizeExceeded)
	}
	if err := a.FinishFile(); err != ErrWriteSizeIncomplete {
		t.Fatalf("FinishFile(incomplete) error = %v, want %v", err, ErrWriteSizeIncomplete)
	}
}

func TestWriteLifecycle_RemoveFile_PersistsAfterReopen(t *testing.T) {
	t.Parallel()

	p := t.TempDir() + "/remove.mpq"
	if err := CreateEmpty(p, CreateOptions{ArchiveFormat: 0, MaxFileCount: 0}); err != nil {
		t.Fatalf("CreateEmpty() error = %v", err)
	}
	a, err := OpenWithOptions(p, OpenOptions{})
	if err != nil {
		t.Fatalf("OpenWithOptions() error = %v", err)
	}

	name := "scripts\\remove.txt"
	payload := []byte("remove me")
	if err := a.CreateFile(name, uint32(len(payload)), 0); err != nil {
		t.Fatalf("CreateFile() error = %v", err)
	}
	if err := a.WriteFile(payload); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := a.FinishFile(); err != nil {
		t.Fatalf("FinishFile() error = %v", err)
	}
	if err := a.RemoveFile(name, 0, 0); err != nil {
		t.Fatalf("RemoveFile() error = %v", err)
	}
	if len(a.BlockTable) != 1 {
		t.Fatalf("BlockTable length = %d, want 1", len(a.BlockTable))
	}
	if got := a.BlockTable[0].Flags; got != mpqFileSingleUnit {
		t.Fatalf("removed block flags = 0x%08x, want 0x%08x", got, uint32(mpqFileSingleUnit))
	}

	a2, err := OpenWithOptions(p, OpenOptions{})
	if err != nil {
		t.Fatalf("reopen error = %v", err)
	}
	if _, err := a2.OpenIndexedFileByHash(mpq.NameHashA(name), mpq.NameHashB(name), 0, 0); err != ErrFileHashNotFound {
		t.Fatalf("OpenIndexedFileByHash(after remove) error = %v, want %v", err, ErrFileHashNotFound)
	}
}

func TestWriteLifecycle_RenameFile_PersistsAfterReopen(t *testing.T) {
	t.Parallel()

	p := t.TempDir() + "/rename.mpq"
	if err := CreateEmpty(p, CreateOptions{ArchiveFormat: 0, MaxFileCount: 0}); err != nil {
		t.Fatalf("CreateEmpty() error = %v", err)
	}
	a, err := OpenWithOptions(p, OpenOptions{})
	if err != nil {
		t.Fatalf("OpenWithOptions() error = %v", err)
	}

	oldName := "scripts\\old.txt"
	newName := "scripts\\new.txt"
	payload := []byte("rename me")
	if err := a.CreateFile(oldName, uint32(len(payload)), 0); err != nil {
		t.Fatalf("CreateFile() error = %v", err)
	}
	if err := a.WriteFile(payload); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := a.FinishFile(); err != nil {
		t.Fatalf("FinishFile() error = %v", err)
	}
	if err := a.RenameFile(oldName, newName, 0, 0); err != nil {
		t.Fatalf("RenameFile() error = %v", err)
	}
	oldHashA := mpq.NameHashA(oldName)
	oldHashB := mpq.NameHashB(oldName)
	foundDeletedOld := false
	foundNew := false
	for _, h := range a.HashTable {
		if h.HashA == oldHashA && h.HashB == oldHashB {
			t.Fatalf("old hash still present after rename: %+v", h)
		}
		if h.BlockIndex == hashEntryDeleted && h.HashA == 0xFFFFFFFF && h.HashB == 0xFFFFFFFF {
			foundDeletedOld = true
		}
		if h.HashA == mpq.NameHashA(newName) && h.HashB == mpq.NameHashB(newName) {
			foundNew = true
		}
	}
	if !foundDeletedOld {
		t.Fatal("expected deleted hash marker entry after rename")
	}
	if !foundNew {
		t.Fatal("expected new hash entry after rename")
	}

	a2, err := OpenWithOptions(p, OpenOptions{})
	if err != nil {
		t.Fatalf("reopen error = %v", err)
	}
	h, err := a2.OpenIndexedFileByHash(mpq.NameHashA(newName), mpq.NameHashB(newName), 0, 0)
	if err != nil {
		t.Fatalf("OpenIndexedFileByHash(new) error = %v", err)
	}
	got, err := a2.ReadFile(h)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("ReadFile() bytes mismatch: got %q want %q", got, payload)
	}
	if _, err := a2.OpenIndexedFileByHash(mpq.NameHashA(oldName), mpq.NameHashB(oldName), 0, 0); err != ErrFileHashNotFound {
		t.Fatalf("OpenIndexedFileByHash(old) error = %v, want %v", err, ErrFileHashNotFound)
	}
}

func TestWriteLifecycle_RenameFile_RejectsCollision(t *testing.T) {
	t.Parallel()

	p := t.TempDir() + "/rename-collision.mpq"
	if err := CreateEmpty(p, CreateOptions{ArchiveFormat: 0, MaxFileCount: 0}); err != nil {
		t.Fatalf("CreateEmpty() error = %v", err)
	}
	a, err := OpenWithOptions(p, OpenOptions{})
	if err != nil {
		t.Fatalf("OpenWithOptions() error = %v", err)
	}

	name := "scripts\\a.txt"
	payload := []byte("first")
	if err := a.CreateFile(name, uint32(len(payload)), 0); err != nil {
		t.Fatalf("CreateFile(%q) error = %v", name, err)
	}
	if err := a.WriteFile(payload); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", name, err)
	}
	if err := a.FinishFile(); err != nil {
		t.Fatalf("FinishFile(%q) error = %v", name, err)
	}

	if err := a.RenameFile(name, name, 0, 0); err != ErrRenameCollision {
		t.Fatalf("RenameFile(collision) error = %v, want %v", err, ErrRenameCollision)
	}
}

func TestWriteLifecycle_RenameFile_Encrypted_RecryptsPayload(t *testing.T) {
	t.Parallel()

	p := t.TempDir() + "/rename-encrypted-recrypt.mpq"
	if err := CreateEmpty(p, CreateOptions{ArchiveFormat: 0, MaxFileCount: 0}); err != nil {
		t.Fatalf("CreateEmpty() error = %v", err)
	}
	a, err := OpenWithOptions(p, OpenOptions{})
	if err != nil {
		t.Fatalf("OpenWithOptions() error = %v", err)
	}

	oldName := "scripts\\secure-old.txt"
	newName := "scripts\\secure-new.txt"
	payload := []byte("rename encrypted recrypt payload")
	flags := uint32(mpq.FileFlagEncrypted | mpq.FileFlagKeyV2)
	if err := a.CreateFile(oldName, uint32(len(payload)), flags); err != nil {
		t.Fatalf("CreateFile() error = %v", err)
	}
	if err := a.WriteFile(payload); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := a.FinishFile(); err != nil {
		t.Fatalf("FinishFile() error = %v", err)
	}
	if err := a.RenameFile(oldName, newName, 0, 0); err != nil {
		t.Fatalf("RenameFile() error = %v", err)
	}

	a2, err := OpenWithOptions(p, OpenOptions{})
	if err != nil {
		t.Fatalf("reopen error = %v", err)
	}
	h, err := a2.OpenIndexedFileForDecrypt(mpq.NameHashA(newName), mpq.NameHashB(newName), 0, 0, newName)
	if err != nil {
		t.Fatalf("OpenIndexedFileForDecrypt(new) error = %v", err)
	}
	got, err := a2.ReadFile(h)
	if err != nil {
		t.Fatalf("ReadFile(new) error = %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("ReadFile(new) bytes mismatch: got %q want %q", got, payload)
	}
}

func TestWriteLifecycle_RenameFile_LocalePlatformVariantOnly(t *testing.T) {
	t.Parallel()

	p := t.TempDir() + "/rename-locale-platform.mpq"
	if err := CreateEmpty(p, CreateOptions{ArchiveFormat: 0, MaxFileCount: 8}); err != nil {
		t.Fatalf("CreateEmpty() error = %v", err)
	}
	a, err := OpenWithOptions(p, OpenOptions{})
	if err != nil {
		t.Fatalf("OpenWithOptions() error = %v", err)
	}

	oldName := "scripts\\variant.txt"
	newName := "scripts\\variant-renamed.txt"
	payload := []byte("locale platform variant payload")
	if err := a.CreateFile(oldName, uint32(len(payload)), 0); err != nil {
		t.Fatalf("CreateFile() error = %v", err)
	}
	if err := a.WriteFile(payload); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := a.FinishFile(); err != nil {
		t.Fatalf("FinishFile() error = %v", err)
	}

	entry, ok := mpq.FindIndexedFileEntry(a.FileIndex, mpq.NameHashA(oldName), mpq.NameHashB(oldName), 0, 0)
	if !ok {
		t.Fatalf("FindIndexedFileEntry(neutral) failed")
	}

	hashes := make([]mpq.HashEntry, len(a.HashTable))
	copy(hashes, a.HashTable)
	slot, err := findInsertSlot(hashes, oldName)
	if err != nil {
		t.Fatalf("findInsertSlot(locale variant) error = %v", err)
	}
	hashes[slot] = mpq.HashEntry{
		HashA:      mpq.NameHashA(oldName),
		HashB:      mpq.NameHashB(oldName),
		Locale:     0x0409,
		Platform:   1,
		Flags:      0,
		BlockIndex: entry.BlockIndex,
	}
	if err := a.persistHeaderAndTables(a.Header, hashes, a.BlockTable); err != nil {
		t.Fatalf("persistHeaderAndTables(locale variant) error = %v", err)
	}
	a.HashTable = hashes
	a.FileIndex = mpq.BuildFileIndex(hashes, a.BlockTable)

	if err := a.RenameFile(oldName, newName, 0x0409, 1); err != nil {
		t.Fatalf("RenameFile(locale variant) error = %v", err)
	}

	a2, err := OpenWithOptions(p, OpenOptions{})
	if err != nil {
		t.Fatalf("reopen error = %v", err)
	}
	for _, h := range a2.HashTable {
		if h.BlockIndex == hashEntryEmpty || h.BlockIndex == hashEntryDeleted {
			continue
		}
		if h.HashA == mpq.NameHashA(oldName) && h.HashB == mpq.NameHashB(oldName) && h.Locale == 0x0409 && h.Platform == 1 {
			t.Fatalf("old locale/platform variant hash entry still present after rename")
		}
	}
	hLocaleRenamed, err := a2.OpenIndexedFileByHash(mpq.NameHashA(newName), mpq.NameHashB(newName), 0x0409, 1)
	if err != nil {
		t.Fatalf("OpenIndexedFileByHash(new locale variant) error = %v", err)
	}
	got, err := a2.ReadFile(hLocaleRenamed)
	if err != nil {
		t.Fatalf("ReadFile(new locale variant) error = %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("ReadFile(new locale variant) bytes mismatch: got %q want %q", got, payload)
	}
	if _, err := a2.OpenIndexedFileByHash(mpq.NameHashA(oldName), mpq.NameHashB(oldName), 0, 0); err != nil {
		t.Fatalf("neutral variant should remain under old name: %v", err)
	}
}

func TestWriteLifecycle_RemoveFile_LocalePlatformVariantOnly(t *testing.T) {
	t.Parallel()

	p := t.TempDir() + "/remove-locale-platform.mpq"
	if err := CreateEmpty(p, CreateOptions{ArchiveFormat: 0, MaxFileCount: 8}); err != nil {
		t.Fatalf("CreateEmpty() error = %v", err)
	}
	a, err := OpenWithOptions(p, OpenOptions{})
	if err != nil {
		t.Fatalf("OpenWithOptions() error = %v", err)
	}

	name := "scripts\\variant-remove.txt"
	payload := []byte("remove locale variant payload")
	if err := a.CreateFile(name, uint32(len(payload)), 0); err != nil {
		t.Fatalf("CreateFile() error = %v", err)
	}
	if err := a.WriteFile(payload); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := a.FinishFile(); err != nil {
		t.Fatalf("FinishFile() error = %v", err)
	}

	entry, ok := mpq.FindIndexedFileEntry(a.FileIndex, mpq.NameHashA(name), mpq.NameHashB(name), 0, 0)
	if !ok {
		t.Fatalf("FindIndexedFileEntry(neutral) failed")
	}

	hashes := make([]mpq.HashEntry, len(a.HashTable))
	copy(hashes, a.HashTable)
	slot, err := findInsertSlot(hashes, name)
	if err != nil {
		t.Fatalf("findInsertSlot(locale variant) error = %v", err)
	}
	hashes[slot] = mpq.HashEntry{
		HashA:      mpq.NameHashA(name),
		HashB:      mpq.NameHashB(name),
		Locale:     0x0409,
		Platform:   1,
		Flags:      0,
		BlockIndex: entry.BlockIndex,
	}
	if err := a.persistHeaderAndTables(a.Header, hashes, a.BlockTable); err != nil {
		t.Fatalf("persistHeaderAndTables(locale variant) error = %v", err)
	}
	a.HashTable = hashes
	a.FileIndex = mpq.BuildFileIndex(hashes, a.BlockTable)

	if err := a.RemoveFile(name, 0x0409, 1); err != nil {
		t.Fatalf("RemoveFile(locale variant) error = %v", err)
	}

	a2, err := OpenWithOptions(p, OpenOptions{})
	if err != nil {
		t.Fatalf("reopen error = %v", err)
	}
	for _, h := range a2.HashTable {
		if h.BlockIndex == hashEntryEmpty || h.BlockIndex == hashEntryDeleted {
			continue
		}
		if h.HashA == mpq.NameHashA(name) && h.HashB == mpq.NameHashB(name) && h.Locale == 0x0409 && h.Platform == 1 {
			t.Fatalf("removed locale/platform variant hash entry still present")
		}
	}
	hNeutral, err := a2.OpenIndexedFileByHash(mpq.NameHashA(name), mpq.NameHashB(name), 0, 0)
	if err != nil {
		t.Fatalf("neutral variant should remain: %v", err)
	}
	got, err := a2.ReadFile(hNeutral)
	if err != nil {
		t.Fatalf("ReadFile(neutral) error = %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("ReadFile(neutral) bytes mismatch: got %q want %q", got, payload)
	}
}

func TestWriteLifecycle_MultiFileAppend_ReopenReadByHash(t *testing.T) {
	t.Parallel()

	p := t.TempDir() + "/multi-append.mpq"
	if err := CreateEmpty(p, CreateOptions{ArchiveFormat: 0, MaxFileCount: 4}); err != nil {
		t.Fatalf("CreateEmpty() error = %v", err)
	}
	a, err := OpenWithOptions(p, OpenOptions{})
	if err != nil {
		t.Fatalf("OpenWithOptions() error = %v", err)
	}

	cases := []struct {
		name    string
		payload []byte
	}{
		{name: "scripts\\a.txt", payload: []byte("first payload")},
		{name: "scripts\\b.txt", payload: []byte("second payload")},
	}
	for _, tc := range cases {
		if err := a.CreateFile(tc.name, uint32(len(tc.payload)), 0); err != nil {
			t.Fatalf("CreateFile(%q) error = %v", tc.name, err)
		}
		if err := a.WriteFile(tc.payload); err != nil {
			t.Fatalf("WriteFile(%q) error = %v", tc.name, err)
		}
		if err := a.FinishFile(); err != nil {
			t.Fatalf("FinishFile(%q) error = %v", tc.name, err)
		}
	}

	a2, err := OpenWithOptions(p, OpenOptions{})
	if err != nil {
		t.Fatalf("reopen error = %v", err)
	}
	for _, tc := range cases {
		h, err := a2.OpenIndexedFileByHash(mpq.NameHashA(tc.name), mpq.NameHashB(tc.name), 0, 0)
		if err != nil {
			t.Fatalf("OpenIndexedFileByHash(%q) error = %v", tc.name, err)
		}
		got, err := a2.ReadFile(h)
		if err != nil {
			t.Fatalf("ReadFile(%q) error = %v", tc.name, err)
		}
		if !bytes.Equal(got, tc.payload) {
			t.Fatalf("ReadFile(%q) bytes mismatch: got %q want %q", tc.name, got, tc.payload)
		}
	}
}

func TestWriteLifecycle_CreateWriteFinish_CompressedEncrypted_RoundTrip(t *testing.T) {
	t.Parallel()

	p := t.TempDir() + "/write-compressed-encrypted.mpq"
	if err := CreateEmpty(p, CreateOptions{ArchiveFormat: 0, MaxFileCount: 4}); err != nil {
		t.Fatalf("CreateEmpty() error = %v", err)
	}
	a, err := OpenWithOptions(p, OpenOptions{})
	if err != nil {
		t.Fatalf("OpenWithOptions() error = %v", err)
	}

	name := "scripts\\secure.txt"
	payload := []byte("compressed-and-encrypted-payload")
	flags := uint32(mpqFileCompressed | mpq.FileFlagEncrypted)
	if err := a.CreateFile(name, uint32(len(payload)), flags); err != nil {
		t.Fatalf("CreateFile() error = %v", err)
	}
	if err := a.WriteFile(payload); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := a.FinishFile(); err != nil {
		t.Fatalf("FinishFile() error = %v", err)
	}

	a2, err := OpenWithOptions(p, OpenOptions{})
	if err != nil {
		t.Fatalf("reopen error = %v", err)
	}
	h, err := a2.OpenIndexedFileForDecrypt(mpq.NameHashA(name), mpq.NameHashB(name), 0, 0, name)
	if err != nil {
		t.Fatalf("OpenIndexedFileForDecrypt() error = %v", err)
	}
	got, err := a2.ReadFile(h)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("ReadFile() bytes mismatch: got %q want %q", got, payload)
	}
}

func TestWriteLifecycle_CreateWriteFinish_FlagCombinations_RoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		flags uint32
	}{
		{
			name:  "plain_single_unit",
			flags: 0,
		},
		{
			name:  "compressed",
			flags: mpqFileCompressed,
		},
		{
			name:  "encrypted",
			flags: mpq.FileFlagEncrypted,
		},
		{
			name:  "encrypted_key_v2",
			flags: mpq.FileFlagEncrypted | mpq.FileFlagKeyV2,
		},
		{
			name:  "compressed_encrypted_key_v2",
			flags: mpqFileCompressed | mpq.FileFlagEncrypted | mpq.FileFlagKeyV2,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := t.TempDir() + "/write-flags-" + tc.name + ".mpq"
			if err := CreateEmpty(p, CreateOptions{ArchiveFormat: 0, MaxFileCount: 4}); err != nil {
				t.Fatalf("CreateEmpty() error = %v", err)
			}
			a, err := OpenWithOptions(p, OpenOptions{})
			if err != nil {
				t.Fatalf("OpenWithOptions() error = %v", err)
			}

			name := "scripts\\" + tc.name + ".txt"
			payload := []byte("roundtrip-" + tc.name + "-payload")
			if err := a.CreateFile(name, uint32(len(payload)), tc.flags); err != nil {
				t.Fatalf("CreateFile() error = %v", err)
			}
			if err := a.WriteFile(payload); err != nil {
				t.Fatalf("WriteFile() error = %v", err)
			}
			if err := a.FinishFile(); err != nil {
				t.Fatalf("FinishFile() error = %v", err)
			}

			a2, err := OpenWithOptions(p, OpenOptions{})
			if err != nil {
				t.Fatalf("reopen error = %v", err)
			}
			h, err := a2.OpenIndexedFileForDecrypt(mpq.NameHashA(name), mpq.NameHashB(name), 0, 0, name)
			if err != nil {
				t.Fatalf("OpenIndexedFileForDecrypt() error = %v", err)
			}
			got, err := a2.ReadFile(h)
			if err != nil {
				t.Fatalf("ReadFile() error = %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("ReadFile() bytes mismatch: got %q want %q", got, payload)
			}
		})
	}
}

func TestWriteLifecycle_CreateFile_RejectsUnsupportedFlags(t *testing.T) {
	t.Parallel()

	p := t.TempDir() + "/write-unsupported-flags.mpq"
	if err := CreateEmpty(p, CreateOptions{ArchiveFormat: 0, MaxFileCount: 0}); err != nil {
		t.Fatalf("CreateEmpty() error = %v", err)
	}
	a, err := OpenWithOptions(p, OpenOptions{})
	if err != nil {
		t.Fatalf("OpenWithOptions() error = %v", err)
	}

	if err := a.CreateFile("x.txt", 1, 0x00000001); !errors.Is(err, ErrWriteFlagsUnsupported) {
		t.Fatalf("CreateFile(unsupported flags) error = %v, want %v", err, ErrWriteFlagsUnsupported)
	}
}

func TestWriteLifecycle_CreateFile_RejectsPseudoAndInternalNames(t *testing.T) {
	t.Parallel()

	p := t.TempDir() + "/name-guards-create.mpq"
	if err := CreateEmpty(p, CreateOptions{ArchiveFormat: 0, MaxFileCount: 0}); err != nil {
		t.Fatalf("CreateEmpty() error = %v", err)
	}
	a, err := OpenWithOptions(p, OpenOptions{})
	if err != nil {
		t.Fatalf("OpenWithOptions() error = %v", err)
	}

	if err := a.CreateFile("File00000001.txt", 1, 0); err != ErrInvalidFileName {
		t.Fatalf("CreateFile(pseudo) error = %v, want %v", err, ErrInvalidFileName)
	}
	if err := a.CreateFile("(listfile)", 1, 0); err != ErrInternalFileName {
		t.Fatalf("CreateFile(internal) error = %v, want %v", err, ErrInternalFileName)
	}
}

func TestWriteLifecycle_RemoveRename_RejectInternalNames(t *testing.T) {
	t.Parallel()

	p := t.TempDir() + "/name-guards-mutation.mpq"
	if err := CreateEmpty(p, CreateOptions{ArchiveFormat: 0, MaxFileCount: 0}); err != nil {
		t.Fatalf("CreateEmpty() error = %v", err)
	}
	a, err := OpenWithOptions(p, OpenOptions{})
	if err != nil {
		t.Fatalf("OpenWithOptions() error = %v", err)
	}

	if err := a.RemoveFile("(attributes)", 0, 0); err != ErrInternalFileName {
		t.Fatalf("RemoveFile(internal) error = %v, want %v", err, ErrInternalFileName)
	}
	if err := a.RenameFile("x.txt", "(signature)", 0, 0); err != ErrInternalFileName {
		t.Fatalf("RenameFile(internal target) error = %v, want %v", err, ErrInternalFileName)
	}
}

func TestWriteLifecycle_AddFileCallbackProgress(t *testing.T) {
	t.Parallel()

	p := t.TempDir() + "/callback-progress.mpq"
	if err := CreateEmpty(p, CreateOptions{ArchiveFormat: 0, MaxFileCount: 0}); err != nil {
		t.Fatalf("CreateEmpty() error = %v", err)
	}
	a, err := OpenWithOptions(p, OpenOptions{})
	if err != nil {
		t.Fatalf("OpenWithOptions() error = %v", err)
	}

	type event struct {
		written uint32
		total   uint32
		done    bool
	}
	var got []event
	a.SetAddFileCallback(func(written, total uint32, done bool) {
		got = append(got, event{written: written, total: total, done: done})
	})

	payload := []byte("callback")
	if err := a.CreateFile("scripts\\callback.txt", uint32(len(payload)), 0); err != nil {
		t.Fatalf("CreateFile() error = %v", err)
	}
	if err := a.WriteFile(payload[:3]); err != nil {
		t.Fatalf("WriteFile(first) error = %v", err)
	}
	if err := a.WriteFile(payload[3:]); err != nil {
		t.Fatalf("WriteFile(second) error = %v", err)
	}
	if err := a.FinishFile(); err != nil {
		t.Fatalf("FinishFile() error = %v", err)
	}

	want := []event{
		{written: 0, total: uint32(len(payload)), done: false},
		{written: 3, total: uint32(len(payload)), done: false},
		{written: uint32(len(payload)), total: uint32(len(payload)), done: false},
		{written: uint32(len(payload)), total: uint32(len(payload)), done: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("callback events = %#v, want %#v", got, want)
	}
}

func TestWriteLifecycle_MultiSectorCompressedRoundTrip(t *testing.T) {
	t.Parallel()

	p := t.TempDir() + "/multisector.mpq"
	if err := CreateEmpty(p, CreateOptions{ArchiveFormat: 0, MaxFileCount: 0}); err != nil {
		t.Fatalf("CreateEmpty: %v", err)
	}
	a, err := OpenWithOptions(p, OpenOptions{})
	if err != nil {
		t.Fatalf("OpenWithOptions: %v", err)
	}

	// Sector size for default v1 archive is 512 << 3 = 4096. Build 12 KiB payload
	// using a compressible repeating pattern so each sector shrinks.
	pattern := []byte("multi-sector-compressible-content-XXXXXX-")
	payload := bytes.Repeat(pattern, (12*1024+len(pattern)-1)/len(pattern))
	payload = payload[:12*1024]

	name := "big\\file.bin"
	if err := a.CreateFile(name, uint32(len(payload)), mpqFileCompressed); err != nil {
		t.Fatalf("CreateFile: %v", err)
	}
	if err := a.WriteFile(payload); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := a.FinishFile(); err != nil {
		t.Fatalf("FinishFile: %v", err)
	}

	a2, err := OpenWithOptions(p, OpenOptions{})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	h, err := a2.OpenIndexedFileForDecrypt(mpq.NameHashA(name), mpq.NameHashB(name), 0, 0, name)
	if err != nil {
		t.Fatalf("OpenIndexedFileForDecrypt: %v", err)
	}
	got, err := a2.ReadFile(h)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("multi-sector payload mismatch (got %d bytes, want %d)", len(got), len(payload))
	}
}

func TestWriteLifecycle_MultiSectorEncryptedRoundTrip(t *testing.T) {
	t.Parallel()

	p := t.TempDir() + "/multisector-enc.mpq"
	if err := CreateEmpty(p, CreateOptions{ArchiveFormat: 0, MaxFileCount: 0}); err != nil {
		t.Fatalf("CreateEmpty: %v", err)
	}
	a, err := OpenWithOptions(p, OpenOptions{})
	if err != nil {
		t.Fatalf("OpenWithOptions: %v", err)
	}

	pattern := []byte("encrypted-multi-sector-payload-")
	payload := bytes.Repeat(pattern, (10*1024+len(pattern)-1)/len(pattern))
	payload = payload[:10*1024]

	name := "secrets\\big.bin"
	flags := uint32(mpqFileCompressed | mpq.FileFlagEncrypted)
	if err := a.CreateFile(name, uint32(len(payload)), flags); err != nil {
		t.Fatalf("CreateFile: %v", err)
	}
	if err := a.WriteFile(payload); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := a.FinishFile(); err != nil {
		t.Fatalf("FinishFile: %v", err)
	}

	a2, err := OpenWithOptions(p, OpenOptions{})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	h, err := a2.OpenIndexedFileForDecrypt(mpq.NameHashA(name), mpq.NameHashB(name), 0, 0, name)
	if err != nil {
		t.Fatalf("OpenIndexedFileForDecrypt: %v", err)
	}
	got, err := a2.ReadFile(h)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("encrypted multi-sector payload mismatch (got %d bytes)", len(got))
	}
}

// avoid "declared and not used" reference in some builds.
var _ = reflect.DeepEqual

func TestWriteLifecycle_V3V4_MutationRoundTrip(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		format uint16
	}{
		{"v3", 2},
		{"v4", 3},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := t.TempDir() + "/mutate.mpq"
			if err := CreateEmpty(p, CreateOptions{ArchiveFormat: tc.format, MaxFileCount: 4}); err != nil {
				t.Fatalf("CreateEmpty: %v", err)
			}

			a, err := OpenWithOptions(p, OpenOptions{})
			if err != nil {
				t.Fatalf("open empty: %v", err)
			}
			payload := []byte("v3v4-mutation-roundtrip-payload-bytes")
			name := "data\\sample.bin"
			if err := a.CreateFile(name, uint32(len(payload)), 0); err != nil {
				t.Fatalf("CreateFile: %v", err)
			}
			if err := a.WriteFile(payload); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			if err := a.FinishFile(); err != nil {
				t.Fatalf("FinishFile: %v", err)
			}

			a2, err := OpenWithOptions(p, OpenOptions{})
			if err != nil {
				t.Fatalf("reopen: %v", err)
			}

			// HET/BET tables are rebuilt on mutation for v3/v4 archives so
			// StormLib HET-driven lookup keeps working.
			if a2.Header.HetTablePos64 == 0 || a2.Header.BetTablePos64 == 0 {
				t.Fatalf("HET/BET pointers missing after mutation: het=%d bet=%d",
					a2.Header.HetTablePos64, a2.Header.BetTablePos64)
			}

			h, err := a2.OpenIndexedFileByHash(mpq.NameHashA(name), mpq.NameHashB(name), 0, 0)
			if err != nil {
				t.Fatalf("OpenIndexedFileByHash: %v", err)
			}
			got, err := a2.ReadFile(h)
			if err != nil {
				t.Fatalf("ReadFile: %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("payload mismatch: got %q want %q", got, payload)
			}
		})
	}
}

func TestWriteLifecycle_AddFile_ReplaceExisting(t *testing.T) {
	t.Parallel()

	p := t.TempDir() + "/replace.mpq"
	if err := CreateEmpty(p, CreateOptions{ArchiveFormat: 0, MaxFileCount: 8}); err != nil {
		t.Fatalf("CreateEmpty: %v", err)
	}
	a, err := OpenWithOptions(p, OpenOptions{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	name := "data\\replaceme.bin"
	first := []byte("first-version-payload")
	second := []byte("SECOND-VERSION-PAYLOAD-IS-DIFFERENT")

	for _, body := range [][]byte{first, second} {
		if err := a.CreateFile(name, uint32(len(body)), 0); err != nil {
			t.Fatalf("CreateFile: %v", err)
		}
		if err := a.WriteFile(body); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if err := a.FinishFile(); err != nil {
			t.Fatalf("FinishFile: %v", err)
		}
	}

	a2, err := OpenWithOptions(p, OpenOptions{})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}

	live := 0
	for _, h := range a2.HashTable {
		if h.BlockIndex == hashEntryEmpty || h.BlockIndex == hashEntryDeleted {
			continue
		}
		if h.HashA == mpq.NameHashA(name) && h.HashB == mpq.NameHashB(name) && h.Locale == 0 && h.Platform == 0 {
			live++
		}
	}
	if live != 1 {
		t.Fatalf("expected 1 live hash entry for replaced file, got %d", live)
	}

	h, err := a2.OpenIndexedFileByHash(mpq.NameHashA(name), mpq.NameHashB(name), 0, 0)
	if err != nil {
		t.Fatalf("OpenIndexedFileByHash: %v", err)
	}
	got, err := a2.ReadFile(h)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, second) {
		t.Fatalf("payload mismatch: got %q want %q", got, second)
	}
}

func TestWriteLifecycle_Bzip2RoundTrip(t *testing.T) {
	t.Parallel()

	p := t.TempDir() + "/bzip2.mpq"
	if err := CreateEmpty(p, CreateOptions{ArchiveFormat: 0, MaxFileCount: 4}); err != nil {
		t.Fatalf("CreateEmpty: %v", err)
	}
	a, err := OpenWithOptions(p, OpenOptions{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	payload := bytes.Repeat([]byte("bzip2-roundtrip-payload-"), 64)
	if err := a.CreateFileEx("data\\big.bin", uint32(len(payload)), mpqFileCompressed, 0x10); err != nil {
		t.Fatalf("CreateFileEx: %v", err)
	}
	if err := a.WriteFile(payload); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := a.FinishFile(); err != nil {
		t.Fatalf("FinishFile: %v", err)
	}

	a2, err := OpenWithOptions(p, OpenOptions{})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	h, err := a2.OpenIndexedFileByHash(mpq.NameHashA("data\\big.bin"), mpq.NameHashB("data\\big.bin"), 0, 0)
	if err != nil {
		t.Fatalf("OpenIndexedFileByHash: %v", err)
	}
	got, err := a2.ReadFile(h)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch (got %d bytes)", len(got))
	}
}


func TestWriteLifecycle_LzmaRoundTrip(t *testing.T) {
	t.Parallel()

	p := t.TempDir() + "/lzma.mpq"
	if err := CreateEmpty(p, CreateOptions{ArchiveFormat: 3, MaxFileCount: 4}); err != nil {
		t.Fatalf("CreateEmpty: %v", err)
	}
	a, err := OpenWithOptions(p, OpenOptions{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	payload := bytes.Repeat([]byte("lzma-roundtrip-payload-"), 64)
	if err := a.CreateFileEx("data\\big.bin", uint32(len(payload)), mpqFileCompressed, 0x12); err != nil {
		t.Fatalf("CreateFileEx: %v", err)
	}
	if err := a.WriteFile(payload); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := a.FinishFile(); err != nil {
		t.Fatalf("FinishFile: %v", err)
	}

	a2, err := OpenWithOptions(p, OpenOptions{})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	h, err := a2.OpenIndexedFileByHash(mpq.NameHashA("data\\big.bin"), mpq.NameHashB("data\\big.bin"), 0, 0)
	if err != nil {
		t.Fatalf("OpenIndexedFileByHash: %v", err)
	}
	got, err := a2.ReadFile(h)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch (got %d bytes)", len(got))
	}
}
