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
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ldmonster/go-stormlib/internal/mpq"
)

type Archive struct {
	Path            string
	Header          mpq.Header
	HashTable       []mpq.HashEntry
	BlockTable      []mpq.BlockEntry
	FileIndex       []mpq.IndexedFileEntry
	pendingWrite    *pendingWrite
	addFileCallback func(written, total uint32, done bool)
	haPatch         *Archive
	// blockNames maps BlockTable index to the filename used when the block was added
	// via the write lifecycle. Populated for files we ourselves wrote so Flush() can
	// emit a (listfile).
	blockNames map[uint32]string
	// blockCRC32 / blockMD5 cache StormLib (attributes) data for blocks we wrote.
	blockCRC32    map[uint32]uint32
	blockMD5      map[uint32][16]byte
	blockFiletime map[uint32]uint64
	// attributesFlags controls which sub-attributes are emitted by
	// writeAttributesFile on Flush. When attributesFlagsSet is false a
	// default of CRC32|FILETIME|MD5 is used. Set to 0 (with set=true) to
	// disable (attributes) emission entirely.
	attributesFlags    uint32
	attributesFlagsSet bool
}

type OpenOptions struct {
	ForceMPQV1      bool
	MarkerSignature uint32
}

type mapType int

const (
	mapTypeUnknown mapType = iota
	mapTypeAvi
	mapTypeStarcraft
	mapTypeWarcraft3
	mapTypeStarcraft2
)

func Open(path string) (*Archive, error) {
	return OpenWithOptions(path, OpenOptions{})
}

func OpenWithOptions(path string, opts OpenOptions) (*Archive, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open archive: %w", err)
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat archive: %w", err)
	}

	size := st.Size()
	if size < 32 {
		return nil, errors.New("file too small to be mpq")
	}

	probe := make([]byte, 0x1000)
	n, _ := f.ReadAt(probe, 0)
	probe = probe[:n]

	mt := detectMapType(path, probe)
	if mt == mapTypeAvi {
		return nil, fmt.Errorf("parse mpq header: %w", mpq.ErrAviFile)
	}

	forceV1 := opts.ForceMPQV1 || mt == mapTypeWarcraft3

	result, err := mpq.FindHeaderWithMetaWithOptions(f, size, mpq.DiscoverOptions{
		ForceMPQV1:      forceV1,
		MarkerSignature: opts.MarkerSignature,
	})
	if err != nil {
		return nil, fmt.Errorf("parse mpq header: %w", err)
	}

	h := result.Header

	hashTable, err := mpq.LoadHashTable(f, size, h)
	if err != nil {
		return nil, fmt.Errorf("load hash table: %w", err)
	}

	blockTable, err := mpq.LoadBlockTable(f, size, h)
	if err != nil {
		return nil, fmt.Errorf("load block table: %w", err)
	}

	blockTable = mpq.NormalizeBlockTableEntries(blockTable, size, h)
	fileIndex := mpq.BuildFileIndex(hashTable, blockTable)

	return &Archive{
		Path:       path,
		Header:     h,
		HashTable:  hashTable,
		BlockTable: blockTable,
		FileIndex:  fileIndex,
	}, nil
}

func detectMapType(path string, probe []byte) mapType {
	// Match C CheckMapType ordering:
	// extension-based StarCraft/SC2 are hard returns; Warcraft extension is a fallback type.
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".scm" || ext == ".scx" {
		return mapTypeStarcraft
	}

	if ext == ".s2ma" || ext == ".sc2map" || ext == ".sc2mod" {
		return mapTypeStarcraft2
	}

	typeByExtension := mapTypeUnknown
	if ext == ".w3m" || ext == ".w3x" {
		typeByExtension = mapTypeWarcraft3
	}

	// AVI signature
	if len(probe) >= 16 && string(probe[0:4]) == "RIFF" && string(probe[8:12]) == "AVI " &&
		string(probe[12:16]) == "LIST" {
		return mapTypeAvi
	}
	// Warcraft III map signature
	if len(probe) >= 8 && string(probe[0:4]) == "HM3W" && probe[4] == 0 && probe[5] == 0 &&
		probe[6] == 0 &&
		probe[7] == 0 {
		return mapTypeWarcraft3
	}
	// MIX heuristic: DLL files with MPQ overlay are treated as Warcraft III maps in C.
	if looksLikeDLL(probe) {
		return mapTypeWarcraft3
	}

	return typeByExtension
}

func looksLikeDLL(probe []byte) bool {
	if len(probe) < 0x100 {
		return false
	}

	if probe[0] != 'M' || probe[1] != 'Z' {
		return false
	}

	lfanew := int(binary.LittleEndian.Uint32(probe[0x3C:0x40]))
	if lfanew <= 0 || lfanew+24 > len(probe) {
		return false
	}

	if string(probe[lfanew:lfanew+4]) != "PE\x00\x00" {
		return false
	}
	// IMAGE_FILE_HEADER.Characteristics at +18 from IMAGE_FILE_HEADER start
	characteristics := binary.LittleEndian.Uint16(probe[lfanew+4+18 : lfanew+4+20])

	const imageFileDLL = 0x2000

	return (characteristics & imageFileDLL) != 0
}
