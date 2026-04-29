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
	"testing"

	"github.com/ldmonster/go-stormlib/internal/mpq"
)

func TestIsPatchedArchive_DefaultFalse(t *testing.T) {
	t.Parallel()

	p := t.TempDir() + "/patched-false.mpq"
	if err := CreateEmpty(p, CreateOptions{ArchiveFormat: 0, MaxFileCount: 0}); err != nil {
		t.Fatalf("CreateEmpty() error = %v", err)
	}
	a, err := OpenWithOptions(p, OpenOptions{})
	if err != nil {
		t.Fatalf("OpenWithOptions() error = %v", err)
	}
	if a.IsPatchedArchive() {
		t.Fatal("IsPatchedArchive() = true, want false")
	}
}

func TestOpenPatchArchive_AttachesPatchChain(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	basePath := dir + "/base.mpq"
	patchPath := dir + "/patch.mpq"
	if err := CreateEmpty(basePath, CreateOptions{ArchiveFormat: 0, MaxFileCount: 0}); err != nil {
		t.Fatalf("CreateEmpty(base) error = %v", err)
	}
	if err := CreateEmpty(patchPath, CreateOptions{ArchiveFormat: 0, MaxFileCount: 0}); err != nil {
		t.Fatalf("CreateEmpty(patch) error = %v", err)
	}

	base, err := OpenWithOptions(basePath, OpenOptions{})
	if err != nil {
		t.Fatalf("OpenWithOptions(base) error = %v", err)
	}
	if err := base.OpenPatchArchive(patchPath, "", 0); err != nil {
		t.Fatalf("OpenPatchArchive() error = %v", err)
	}
	if !base.IsPatchedArchive() {
		t.Fatal("IsPatchedArchive() = false, want true after patch attach")
	}
}

func TestOpenPatchArchive_AppendsChainInOrder(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	basePath := dir + "/base.mpq"
	patch1Path := dir + "/patch1.mpq"
	patch2Path := dir + "/patch2.mpq"
	for _, p := range []string{basePath, patch1Path, patch2Path} {
		if err := CreateEmpty(p, CreateOptions{ArchiveFormat: 0, MaxFileCount: 0}); err != nil {
			t.Fatalf("CreateEmpty(%q) error = %v", p, err)
		}
	}

	base, err := OpenWithOptions(basePath, OpenOptions{})
	if err != nil {
		t.Fatalf("OpenWithOptions(base) error = %v", err)
	}
	if err := base.OpenPatchArchive(patch1Path, "", 0); err != nil {
		t.Fatalf("OpenPatchArchive(first) error = %v", err)
	}
	if err := base.OpenPatchArchive(patch2Path, "", 0); err != nil {
		t.Fatalf("OpenPatchArchive(second) error = %v", err)
	}

	if base.haPatch == nil || base.haPatch.Path != patch1Path {
		t.Fatalf("first patch link mismatch: got %#v", base.haPatch)
	}
	if base.haPatch.haPatch == nil || base.haPatch.haPatch.Path != patch2Path {
		t.Fatalf("second patch link mismatch: got %#v", base.haPatch.haPatch)
	}
}

func writePayloadToArchive(t *testing.T, path, name string, payload []byte) {
	t.Helper()
	a, err := OpenWithOptions(path, OpenOptions{})
	if err != nil {
		t.Fatalf("OpenWithOptions(%q): %v", path, err)
	}
	if err := a.CreateFile(name, uint32(len(payload)), 0); err != nil {
		t.Fatalf("CreateFile(%q): %v", name, err)
	}
	if err := a.WriteFile(payload); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := a.FinishFile(); err != nil {
		t.Fatalf("FinishFile: %v", err)
	}
}

func TestReadPatchedByName_NewestArchiveWins(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	basePath := dir + "/base.mpq"
	patchPath := dir + "/patch.mpq"
	for _, p := range []string{basePath, patchPath} {
		if err := CreateEmpty(p, CreateOptions{ArchiveFormat: 0, MaxFileCount: 0}); err != nil {
			t.Fatalf("CreateEmpty(%q): %v", p, err)
		}
	}

	name := "shared\\thing.txt"
	writePayloadToArchive(t, basePath, name, []byte("base-version"))
	writePayloadToArchive(t, patchPath, name, []byte("patched-version"))

	base, err := OpenWithOptions(basePath, OpenOptions{})
	if err != nil {
		t.Fatalf("OpenWithOptions(base): %v", err)
	}
	if err := base.OpenPatchArchive(patchPath, "", 0); err != nil {
		t.Fatalf("OpenPatchArchive: %v", err)
	}

	got, err := base.ReadPatchedByName(name, 0, 0)
	if err != nil {
		t.Fatalf("ReadPatchedByName: %v", err)
	}
	if !bytes.Equal(got, []byte("patched-version")) {
		t.Fatalf("ReadPatchedByName = %q, want patched-version", got)
	}
}

func TestReadPatchedByName_FallsBackToBase(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	basePath := dir + "/base.mpq"
	patchPath := dir + "/patch.mpq"
	for _, p := range []string{basePath, patchPath} {
		if err := CreateEmpty(p, CreateOptions{ArchiveFormat: 0, MaxFileCount: 0}); err != nil {
			t.Fatalf("CreateEmpty(%q): %v", p, err)
		}
	}

	name := "only-in-base.txt"
	writePayloadToArchive(t, basePath, name, []byte("base-only"))

	base, err := OpenWithOptions(basePath, OpenOptions{})
	if err != nil {
		t.Fatalf("OpenWithOptions(base): %v", err)
	}
	if err := base.OpenPatchArchive(patchPath, "", 0); err != nil {
		t.Fatalf("OpenPatchArchive: %v", err)
	}

	got, err := base.ReadPatchedByName(name, 0, 0)
	if err != nil {
		t.Fatalf("ReadPatchedByName: %v", err)
	}
	if !bytes.Equal(got, []byte("base-only")) {
		t.Fatalf("ReadPatchedByName = %q, want base-only", got)
	}
}

func TestReadPatchedByName_DeleteMarkerHidesBase(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	basePath := dir + "/base.mpq"
	patchPath := dir + "/patch.mpq"
	for _, p := range []string{basePath, patchPath} {
		if err := CreateEmpty(p, CreateOptions{ArchiveFormat: 0, MaxFileCount: 0}); err != nil {
			t.Fatalf("CreateEmpty(%q): %v", p, err)
		}
	}

	name := "doomed.txt"
	writePayloadToArchive(t, basePath, name, []byte("base-version"))
	writePayloadToArchive(t, patchPath, name, []byte("ignored"))

	// Mutate the patch's block entry to set MPQ_FILE_DELETE_MARKER.
patch, err := OpenWithOptions(patchPath, OpenOptions{})
if err != nil {
t.Fatalf("OpenWithOptions(patch): %v", err)
}
hashA := mpq.NameHashA(name)
hashB := mpq.NameHashB(name)
entry, ok := mpq.FindIndexedFileEntry(patch.FileIndex, hashA, hashB, 0, 0)
if !ok {
t.Fatal("patch entry missing")
}
patch.BlockTable[entry.BlockIndex].Flags |= mpq.FileFlagDeleteMarker
if err := patch.persistHeaderAndTables(patch.Header, patch.HashTable, patch.BlockTable); err != nil {
t.Fatalf("persistHeaderAndTables: %v", err)
}

base, err := OpenWithOptions(basePath, OpenOptions{})
if err != nil {
t.Fatalf("OpenWithOptions(base): %v", err)
}
if err := base.OpenPatchArchive(patchPath, "", 0); err != nil {
t.Fatalf("OpenPatchArchive: %v", err)
}

if _, err := base.ReadPatchedByName(name, 0, 0); err != ErrFileHashNotFound {
t.Fatalf("ReadPatchedByName = %v, want ErrFileHashNotFound", err)
}
}
