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

package mpq

import "testing"

func FuzzLoadHashTable(f *testing.F) {
	f.Add([]byte("seed"), uint16(0), uint32(0), uint32(1), int64(4096))
	f.Fuzz(func(t *testing.T, blob []byte, format uint16, pos uint32, count uint32, fileSize int64) {
		if fileSize < 0 {
			fileSize = 0
		}
		if int64(len(blob)) < fileSize {
			fileSize = int64(len(blob))
		}
		h := Header{
			FormatVersion: format % 2,
			HashTablePos:  pos,
			HashTableSize: count & 0x3FF,
		}
		_, _ = LoadHashTable(bytesReaderAt(blob), fileSize, h)
	})
}

func FuzzLoadBlockTable(f *testing.F) {
	f.Add([]byte("seed"), uint16(0), uint32(0), uint32(1), int64(4096))
	f.Fuzz(func(t *testing.T, blob []byte, format uint16, pos uint32, count uint32, fileSize int64) {
		if fileSize < 0 {
			fileSize = 0
		}
		if int64(len(blob)) < fileSize {
			fileSize = int64(len(blob))
		}
		h := Header{
			FormatVersion:  format % 2,
			BlockTablePos:  pos,
			BlockTableSize: count & 0x3FF,
		}
		_, _ = LoadBlockTable(bytesReaderAt(blob), fileSize, h)
	})
}

func FuzzIndexLookupNormalizeInteractions(f *testing.F) {
	f.Add([]byte("seed"), int64(4096), uint32(0x200), uint16(0))
	f.Add([]byte{
		0x71, 0, 0, 1, 0x72, 0, 0, 1, 0x09, 0x04, 0x01, 0, 0, 0, 0, 0,
		0x71, 0, 0, 1, 0x72, 0, 0, 1, 0x09, 0x04, 0x00, 0, 0, 0, 0, 1,
	}, int64(0x2000), uint32(0x200), uint16(0))
	f.Add([]byte{
		0x95, 0, 0, 1, 0x96, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
		0x00, 0x11, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x20, 0, 0, 0, 0, 2, 0, 1,
	}, int64(0x1800), uint32(0x200), uint16(0))
	f.Fuzz(func(t *testing.T, blob []byte, fileSize int64, headerOffset uint32, format uint16) {
		if fileSize < 0 {
			fileSize = 0
		}
		if int64(len(blob)) < fileSize {
			fileSize = int64(len(blob))
		}
		hashes := make([]HashEntry, len(blob)/16)
		blocks := make([]BlockEntry, len(blob)/16)
		for i := 0; i+16 <= len(blob); i += 16 {
			idx := i / 16
			hashes[idx] = HashEntry{
				HashA:      uint32(blob[i])<<24 | uint32(blob[i+1])<<16 | uint32(blob[i+2])<<8 | uint32(blob[i+3]),
				HashB:      uint32(blob[i+4])<<24 | uint32(blob[i+5])<<16 | uint32(blob[i+6])<<8 | uint32(blob[i+7]),
				Locale:     uint16(blob[i+8])<<8 | uint16(blob[i+9]),
				Platform:   blob[i+10],
				BlockIndex: uint32(blob[i+12])<<24 | uint32(blob[i+13])<<16 | uint32(blob[i+14])<<8 | uint32(blob[i+15]),
			}
			blocks[idx] = BlockEntry{
				FilePos:          uint32(blob[i])<<24 | uint32(blob[i+1])<<16 | uint32(blob[i+2])<<8 | uint32(blob[i+3]),
				CompressedSize:   uint32(blob[i+4])<<24 | uint32(blob[i+5])<<16 | uint32(blob[i+6])<<8 | uint32(blob[i+7]),
				UncompressedSize: uint32(blob[i+8])<<24 | uint32(blob[i+9])<<16 | uint32(blob[i+10])<<8 | uint32(blob[i+11]),
				Flags:            uint32(blob[i+12])<<24 | uint32(blob[i+13])<<16 | uint32(blob[i+14])<<8 | uint32(blob[i+15]),
			}
		}
		hdr := Header{Offset: int64(headerOffset), FormatVersion: format % 2}
		normalized := NormalizeBlockTableEntries(blocks, fileSize, hdr)
		index := BuildFileIndex(hashes, normalized)
		if len(index) == 0 {
			_, _ = FindIndexedFileEntry(index, 0, 0, 0, 0)
			return
		}
		probe := index[len(index)/2]
		_, _ = FindIndexedFileEntry(index, probe.Hash.HashA, probe.Hash.HashB, probe.Hash.Locale, probe.Hash.Platform)
	})
}
