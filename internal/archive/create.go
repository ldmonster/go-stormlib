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
	"os"

	"github.com/ldmonster/go-stormlib/internal/mpq"
)

// CreateOptions controls layout for a new empty archive (read StormLib SFileCreateArchive / SFileCreateArchive2).
type CreateOptions struct {
	// ArchiveFormat is MPQ_FORMAT_VERSION_*: 0 = classic v1 header, 1 = Burning Crusade v2 header (44-byte).
	ArchiveFormat uint16
	// MaxFileCount is dwMaxFileCount; 0 uses StormLib default hash table sizing.
	MaxFileCount uint32
	// ReservedSlots counts extra hash slots for internal files when MaxFileCount > 0 (listfile/attributes/signature).
	ReservedSlots uint32
	// ReserveListfile mirrors StormLib create reserved-file accounting for (listfile).
	ReserveListfile bool
	// ReserveAttributes mirrors StormLib create reserved-file accounting for (attributes).
	ReserveAttributes bool
	// ReserveSignature mirrors StormLib create reserved-file accounting for (signature).
	ReserveSignature bool
}

// CreateEmpty writes a new minimal MPQ without user data preamble, matching StormLib empty-archive layout
// (0x200 padding, header, encrypted empty hash table, block table size 0).
func CreateEmpty(path string, opts CreateOptions) error {
	if path == "" {
		return fmt.Errorf("empty path")
	}

	layout, err := mpq.BuildEmptyArchiveLayout(
		opts.ArchiveFormat,
		opts.MaxFileCount,
		effectiveReservedSlots(opts),
	)
	if err != nil {
		return err
	}

	hdr, err := mpq.MarshalHeader(layout.Header)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("create archive: %w", err)
		}

		return fmt.Errorf("create archive: %w", err)
	}
	defer f.Close()

	pad := make([]byte, mpq.MPQCreateLeadPadding)
	if _, err := f.Write(pad); err != nil {
		return fmt.Errorf("write mpq lead padding: %w", err)
	}

	if _, err := f.Write(hdr); err != nil {
		return fmt.Errorf("write mpq header: %w", err)
	}

	if _, err := f.Write(layout.HashTableBytes); err != nil {
		return fmt.Errorf("write hash table: %w", err)
	}

	return nil
}

func effectiveReservedSlots(opts CreateOptions) uint32 {
	reserved := opts.ReservedSlots
	if opts.ReserveListfile {
		reserved++
	}

	if opts.ReserveAttributes {
		reserved++
	}

	if opts.ReserveSignature {
		reserved++
	}

	return reserved
}
