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

package storm

import (
	"fmt"
	"os"
)

// Extract search scope for [Archive.ExtractFile] (SFileOpenFileEx / SFileExtractFile, StormLib.h).
// The Go port currently implements only [ExtractSearchFromMPQ] (SFILE_OPEN_FROM_MPQ).
const (
	ExtractSearchFromMPQ     uint32 = 0x00000000 // SFILE_OPEN_FROM_MPQ
	ExtractSearchCheckExists uint32 = 0xFFFFFFFC // SFILE_OPEN_CHECK_EXISTS
	ExtractSearchLocalFile   uint32 = 0xFFFFFFFF // SFILE_OPEN_LOCAL_FILE
)

// ExtractOptions controls named lookup for [Archive.ExtractFile] (SFileExtractFile).
type ExtractOptions struct {
	Locale   uint16
	Platform uint8
	// SearchScope: use [ExtractSearchFromMPQ] (default zero). Other values return [ErrUnsupportedFeature].
	SearchScope uint32
}

// ExtractFile copies a file from the archive to a local path, matching SFileExtractFile
// (open by name, read in 0x1000-sized chunks in C; we read the full payload and write once).
func (a *Archive) ExtractFile(mpqInternalName, destPath string, opts ExtractOptions) error {
	if opts.SearchScope != ExtractSearchFromMPQ {
		return fmt.Errorf(
			"%w: extract only supports SearchScope ExtractSearchFromMPQ (0), got %#x",
			ErrUnsupportedFeature,
			opts.SearchScope,
		)
	}

	if destPath == "" {
		return fmt.Errorf("empty dest path")
	}

	payload, err := a.ReadFileByName(mpqInternalName, opts.Locale, opts.Platform)
	if err != nil {
		return err
	}

	if err := os.WriteFile(destPath, payload, 0o644); err != nil {
		return fmt.Errorf("write extracted file: %w", err)
	}

	return nil
}
