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

import "errors"

var (
	ErrInvalidMPQ             = errors.New("invalid mpq archive")
	ErrUnsupportedMPQ         = errors.New("unsupported mpq format")
	ErrUnsupportedOption      = errors.New("unsupported open option")
	ErrUnsupportedFeature     = errors.New("unsupported feature")
	ErrAviFile                = errors.New("avi file")
	ErrFileNotFound           = errors.New("file not found")
	ErrOutOfRange             = errors.New("index out of range")
	ErrDecodeFailed           = errors.New("decode failed")
	ErrUnsupportedCompression = errors.New("unsupported mpq compression codec")
	ErrInvalidParameter       = errors.New("invalid parameter")
	// ErrEncryptedFileNeedsName is returned when an entry has MPQ_FILE_ENCRYPTED but the read
	// was opened without the internal file path (e.g. by index or hash only), so the key cannot be derived.
	ErrEncryptedFileNeedsName = errors.New("encrypted file requires read by internal path name")
)

type OpenOptions struct {
	ReadOnly        bool
	ForceMPQV1      bool
	MarkerSignature uint32
}

type Header struct {
	Version        uint16
	HeaderSize     uint32
	ArchiveSize32  uint32
	SectorSizeExp  uint16
	HashTablePos   uint32
	BlockTablePos  uint32
	HashTableSize  uint32
	BlockTableSize uint32
	HetTablePos64  uint64
	BetTablePos64  uint64
	HetTableSize64 uint64
	BetTableSize64 uint64
}

type FileInfo struct {
	Name           string
	CompressedSize uint32
	UnpackedSize   uint32
	Flags          uint32
}
