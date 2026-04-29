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
	"crypto/md5"
	"errors"
	"fmt"
	"hash/crc32"
	"strings"

	internalarchive "github.com/ldmonster/go-stormlib/internal/archive"
	"github.com/ldmonster/go-stormlib/internal/mpq"
)

type Archive struct {
	inner  *internalarchive.Archive
	locale uint16
}

func Open(path string, opts OpenOptions) (*Archive, error) {
	a, err := internalarchive.OpenWithOptions(path, internalarchive.OpenOptions{
		ForceMPQV1:      opts.ForceMPQV1,
		MarkerSignature: opts.MarkerSignature,
	})
	if err != nil {
		if errors.Is(err, mpq.ErrHeaderNotFound) {
			return nil, fmt.Errorf("%w: %v", ErrInvalidMPQ, err)
		}

		if errors.Is(err, mpq.ErrUnsupportedFormat) {
			return nil, fmt.Errorf("%w: %v", ErrUnsupportedMPQ, err)
		}

		if errors.Is(err, mpq.ErrAviFile) {
			return nil, fmt.Errorf("%w: %v", ErrAviFile, err)
		}

		if errors.Is(err, mpq.ErrUnsupportedForeignHeader) ||
			errors.Is(err, mpq.ErrUnsupportedMPK) ||
			errors.Is(err, mpq.ErrUnsupportedSQP) {
			return nil, fmt.Errorf("%w: %v", ErrUnsupportedOption, err)
		}

		return nil, err
	}

	return &Archive{inner: a}, nil
}

func (a *Archive) Close() error {
	// Open currently does not keep file handles open.
	return nil
}

func (a *Archive) Header() Header {
	h := a.inner.Header

	return Header{
		Version:        h.FormatVersion,
		HeaderSize:     h.HeaderSize,
		ArchiveSize32:  h.ArchiveSize32,
		SectorSizeExp:  h.SectorSizeExp,
		HashTablePos:   h.HashTablePos,
		BlockTablePos:  h.BlockTablePos,
		HashTableSize:  h.HashTableSize,
		BlockTableSize: h.BlockTableSize,
		HetTablePos64:  h.HetTablePos64,
		BetTablePos64:  h.BetTablePos64,
		HetTableSize64: h.HetTableSize64,
		BetTableSize64: h.BetTableSize64,
	}
}

func (a *Archive) ListFiles() ([]FileInfo, error) {
	nameByHash := a.resolveListfileNames()

	out := make([]FileInfo, 0, len(a.inner.FileIndex))
	for _, entry := range a.inner.FileIndex {
		name := nameByHash[[2]uint32{entry.Hash.HashA, entry.Hash.HashB}]
		if name == "" {
			name = fmt.Sprintf(
				"hash_%08x_%08x_loc_%04x_plat_%02x",
				entry.Hash.HashA,
				entry.Hash.HashB,
				entry.Hash.Locale,
				entry.Hash.Platform,
			)
		}

		out = append(out, FileInfo{
			Name:           name,
			CompressedSize: entry.Block.CompressedSize,
			UnpackedSize:   entry.Block.UncompressedSize,
			Flags:          entry.Block.Flags,
		})
	}

	return out, nil
}

func (a *Archive) ReadFileByIndex(index int) ([]byte, error) {
	h, err := a.inner.OpenIndexedFile(index)
	if err != nil {
		if errors.Is(err, internalarchive.ErrIndexOutOfRange) {
			return nil, fmt.Errorf("%w: %v", ErrOutOfRange, err)
		}

		return nil, err
	}

	b, err := a.inner.ReadFile(h)

	return wrapReadBytesErr(b, err)
}

func (a *Archive) ReadFileByHash(
	hashA, hashB uint32,
	locale uint16,
	platform uint8,
) ([]byte, error) {
	h, err := a.inner.OpenIndexedFileByHash(hashA, hashB, locale, platform)
	if err != nil {
		if errors.Is(err, internalarchive.ErrFileHashNotFound) {
			return nil, fmt.Errorf("%w: %v", ErrFileNotFound, err)
		}

		return nil, err
	}

	b, err := a.inner.ReadFile(h)

	return wrapReadBytesErr(b, err)
}

func wrapReadBytesErr(b []byte, err error) ([]byte, error) {
	if err == nil {
		return b, nil
	}

	return nil, wrapReadErrOnly(err)
}

func wrapReadErrOnly(err error) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, internalarchive.ErrUnsupportedCodec) {
		return fmt.Errorf("%w: %w", ErrUnsupportedCompression, err)
	}

	if errors.Is(err, internalarchive.ErrEncryptionNeedsPath) {
		return fmt.Errorf("%w: %w", ErrEncryptedFileNeedsName, err)
	}

	if errors.Is(err, internalarchive.ErrDecodeFailed) {
		return fmt.Errorf("%w: %v", ErrDecodeFailed, err)
	}

	return err
}

func (a *Archive) HasFile(name string, locale uint16, platform uint8) bool {
	hashA := mpq.NameHashA(name)
	hashB := mpq.NameHashB(name)
	_, err := a.inner.OpenIndexedFileByHash(hashA, hashB, locale, platform)

	return err == nil
}

func (a *Archive) ReadFileByName(name string, locale uint16, platform uint8) ([]byte, error) {
	if a.inner.IsPatchedArchive() {
		b, err := a.inner.ReadPatchedByName(name, locale, platform)
		if err == nil {
			return b, nil
		}

		if errors.Is(err, internalarchive.ErrFileHashNotFound) {
			return nil, fmt.Errorf("%w: %v", ErrFileNotFound, err)
		}

		if errors.Is(err, internalarchive.ErrPatchDeltaUnsupported) {
			return nil, fmt.Errorf("%w: %v", ErrUnsupportedFeature, err)
		}

		return nil, wrapReadErrOnly(err)
	}

	hashA := mpq.NameHashA(name)
	hashB := mpq.NameHashB(name)

	h, err := a.inner.OpenIndexedFileForDecrypt(hashA, hashB, locale, platform, name)
	if err != nil {
		if errors.Is(err, internalarchive.ErrFileHashNotFound) {
			return nil, fmt.Errorf("%w: %v", ErrFileNotFound, err)
		}

		return nil, err
	}

	b, err := a.inner.ReadFile(h)

	return wrapReadBytesErr(b, err)
}

func (a *Archive) FileInfoByName(name string, locale uint16, platform uint8) (FileInfo, error) {
	hashA := mpq.NameHashA(name)
	hashB := mpq.NameHashB(name)

	e, ok := mpq.FindIndexedFileEntry(a.inner.FileIndex, hashA, hashB, locale, platform)
	if !ok {
		return FileInfo{}, ErrFileNotFound
	}

	return FileInfo{
		Name:           name,
		CompressedSize: e.Block.CompressedSize,
		UnpackedSize:   e.Block.UncompressedSize,
		Flags:          e.Block.Flags,
	}, nil
}

func (a *Archive) GetFileChecksumsByName(
	name string,
	locale uint16,
	platform uint8,
) (uint32, [16]byte, error) {
	payload, err := a.ReadFileByName(name, locale, platform)
	if err != nil {
		return 0, [16]byte{}, err
	}

	return crc32.ChecksumIEEE(payload), md5.Sum(payload), nil
}

func (a *Archive) SignArchive(signatureType uint32) error {
	_ = signatureType
	return ErrUnsupportedFeature
}

func (a *Archive) resolveListfileNames() map[[2]uint32]string {
	listHashA := mpq.NameHashA("(listfile)")
	listHashB := mpq.NameHashB("(listfile)")

	payload, err := a.ReadFileByHash(listHashA, listHashB, 0, 0)
	if err != nil {
		return nil
	}

	out := make(map[[2]uint32]string)

	for _, line := range strings.Split(string(payload), "\n") {
		name := strings.TrimSpace(strings.TrimRight(line, "\r"))
		if name == "" {
			continue
		}

		key := [2]uint32{mpq.NameHashA(name), mpq.NameHashB(name)}
		if _, exists := out[key]; !exists {
			out[key] = name
		}
	}

	return out
}
