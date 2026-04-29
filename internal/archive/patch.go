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
	"errors"
	"fmt"

	"github.com/ldmonster/go-stormlib/internal/mpq"
)

// ErrPatchDeltaUnsupported is returned when a patch-chain entry carries an
// unrecognised XFRM type that we do not know how to apply.
var ErrPatchDeltaUnsupported = errors.New("patch-chain delta unsupported")

func (a *Archive) OpenPatchArchive(path, prefix string, flags uint32) error {
	_ = prefix
	_ = flags

	if a == nil {
		return fmt.Errorf("%w: nil archive", ErrArchiveWriteUnsupported)
	}

	if path == "" {
		return fmt.Errorf("%w: empty patch archive path", ErrArchiveWriteUnsupported)
	}

	patch, err := OpenWithOptions(path, OpenOptions{})
	if err != nil {
		return fmt.Errorf("open patch archive: %w", err)
	}

	cur := a
	for cur.haPatch != nil {
		cur = cur.haPatch
	}

	cur.haPatch = patch

	return nil
}

func (a *Archive) IsPatchedArchive() bool {
	if a == nil {
		return false
	}

	return a.haPatch != nil
}

// chainArchives returns archives in newest-first order (patches before base).
func (a *Archive) chainArchives() []*Archive {
	out := []*Archive{a}

	cur := a.haPatch
	for cur != nil {
		out = append(out, cur)
		cur = cur.haPatch
	}

	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}

	return out
}

// ReadPatchedByName walks the patch chain newest-first to find the newest version,
// applying any BSDIFF40/COPY patch deltas over the most recent non-delta base.
// MPQ_FILE_DELETE_MARKER terminates lookup and returns ErrFileHashNotFound.
func (a *Archive) ReadPatchedByName(name string, locale uint16, platform uint8) ([]byte, error) {
	if a == nil {
		return nil, ErrFileHashNotFound
	}

	hashA := mpq.NameHashA(name)
	hashB := mpq.NameHashB(name)

	chain := a.chainArchives() // newest-first
	// Collect deltas (newest-first) until we find a non-delta base or run out.
	var (
		deltas []*Archive
		base   *Archive
	)

	for _, ar := range chain {
		entry, ok := mpq.FindIndexedFileEntry(ar.FileIndex, hashA, hashB, locale, platform)
		if !ok {
			continue
		}

		if entry.Block.Flags&mpq.FileFlagDeleteMarker != 0 {
			return nil, ErrFileHashNotFound
		}

		if entry.Block.Flags&mpq.FileFlagPatchFile != 0 {
			deltas = append(deltas, ar)
			continue
		}

		base = ar

		break
	}

	if base == nil {
		if len(deltas) > 0 {
			return nil, fmt.Errorf("%w: %s (no base file in chain)", ErrPatchDeltaUnsupported, name)
		}

		return nil, ErrFileHashNotFound
	}

	bh, err := base.OpenIndexedFileForDecrypt(hashA, hashB, locale, platform, name)
	if err != nil {
		return nil, err
	}

	out, err := base.ReadFile(bh)
	if err != nil {
		return nil, err
	}

	// Apply deltas oldest-first (deltas slice is newest-first).
	for i := len(deltas) - 1; i >= 0; i-- {
		ar := deltas[i]

		ph, err := ar.OpenIndexedFileForDecrypt(hashA, hashB, locale, platform, name)
		if err != nil {
			return nil, err
		}

		patchBytes, err := ar.ReadFile(ph)
		if err != nil {
			return nil, err
		}

		out, err = applyMPQPatch(out, patchBytes)
		if err != nil {
			return nil, fmt.Errorf("apply patch %s: %w", name, err)
		}
	}

	return out, nil
}
