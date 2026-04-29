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
	"errors"
	"fmt"

	internalarchive "github.com/ldmonster/go-stormlib/internal/archive"
)

type CreateOptions struct {
	// ArchiveVersion selects the on-disk MPQ format version (StormLib MPQ_FORMAT_VERSION_*): 0..3 = v1..v4.
	ArchiveVersion uint32
	MaxFileCount   uint32
	// ReservedSlots adds extra hash slots for internal seeds when MaxFileCount > 0 (listfile, attributes, signature),
	// matching StormLib SFileCreateArchive reserved-file accounting.
	ReservedSlots uint32
	// ReserveListfile reserves one internal slot for (listfile) create parity sizing.
	ReserveListfile bool
	// ReserveAttributes reserves one internal slot for (attributes) create parity sizing.
	ReserveAttributes bool
	// ReserveSignature reserves one internal slot for (signature) create parity sizing.
	ReserveSignature bool
}

type AddFileCallback func(written, total uint32, done bool)

const (
	// CreateFlagListfile mirrors StormLib MPQ_CREATE_LISTFILE.
	CreateFlagListfile uint32 = 0x00100000
	// CreateFlagAttributes mirrors StormLib MPQ_CREATE_ATTRIBUTES.
	CreateFlagAttributes uint32 = 0x00200000
	// CreateFlagSignature mirrors StormLib MPQ_CREATE_SIGNATURE.
	CreateFlagSignature uint32 = 0x00400000
	// CreateFlagArchiveVersionMask mirrors StormLib MPQ_CREATE_ARCHIVE_VMASK.
	CreateFlagArchiveVersionMask uint32 = 0x0F000000
	// CreateFlagArchiveV1 mirrors StormLib MPQ_CREATE_ARCHIVE_V1.
	CreateFlagArchiveV1 uint32 = 0x00000000
	// CreateFlagArchiveV2 mirrors StormLib MPQ_CREATE_ARCHIVE_V2.
	CreateFlagArchiveV2 uint32 = 0x01000000
	// CreateFlagArchiveV3 mirrors StormLib MPQ_CREATE_ARCHIVE_V3.
	CreateFlagArchiveV3 uint32 = 0x02000000
	// CreateFlagArchiveV4 mirrors StormLib MPQ_CREATE_ARCHIVE_V4.
	CreateFlagArchiveV4   uint32 = 0x03000000
	createFlagFormatShift uint32 = 24
)

func Create(path string, opts CreateOptions) (*Archive, error) {
	if opts.ArchiveVersion > 3 {
		return nil, fmt.Errorf("%w: archive version %d", ErrUnsupportedMPQ, opts.ArchiveVersion)
	}

	if err := internalarchive.CreateEmpty(path, internalarchive.CreateOptions{
		ArchiveFormat:     uint16(opts.ArchiveVersion),
		MaxFileCount:      opts.MaxFileCount,
		ReservedSlots:     opts.ReservedSlots,
		ReserveListfile:   opts.ReserveListfile,
		ReserveAttributes: opts.ReserveAttributes,
		ReserveSignature:  opts.ReserveSignature,
	}); err != nil {
		return nil, err
	}

	a, err := internalarchive.OpenWithOptions(path, internalarchive.OpenOptions{})
	if err != nil {
		return nil, err
	}

	return &Archive{inner: a}, nil
}

// CreateWithFlags maps StormLib SFileCreateArchive create flags into CreateOptions.
// It keeps legacy listfile reservation behavior: when MaxFileCount > 0, listfile is always reserved.
func CreateWithFlags(path string, createFlags, maxFileCount uint32) (*Archive, error) {
	version := (createFlags & CreateFlagArchiveVersionMask) >> createFlagFormatShift

	return Create(path, CreateOptions{
		ArchiveVersion:    version,
		MaxFileCount:      maxFileCount,
		ReserveListfile:   true,
		ReserveAttributes: (createFlags & CreateFlagAttributes) != 0,
		ReserveSignature:  (createFlags & CreateFlagSignature) != 0,
	})
}

func (a *Archive) Flush() error {
	return a.inner.Flush()
}

func (a *Archive) CreateFile(name string, fileSize, flags uint32) error {
	return a.inner.CreateFile(name, fileSize, flags)
}

// CreateFileEx is the explicit-codec variant of CreateFile. The compression
// argument is the MPQ codec mask byte (e.g. 0x02 zlib, 0x10 bzip2). Zero
// selects zlib when MPQ_FILE_COMPRESS is set in flags.
func (a *Archive) CreateFileEx(name string, fileSize, flags uint32, compression byte) error {
	return a.inner.CreateFileEx(name, fileSize, flags, compression)
}

func (a *Archive) WriteFile(data []byte) error {
	return a.inner.WriteFile(data)
}

func (a *Archive) FinishFile() error {
	return a.inner.FinishFile()
}

// AddFile is a one-shot convenience for the CreateFile/WriteFile/FinishFile
// sequence. It mirrors StormLib's SFileAddFileEx for the common in-memory
// payload case.
func (a *Archive) AddFile(name string, data []byte, flags uint32) error {
	if err := a.inner.CreateFile(name, uint32(len(data)), flags); err != nil {
		return err
	}

	if len(data) > 0 {
		if err := a.inner.WriteFile(data); err != nil {
			return err
		}
	}

	return a.inner.FinishFile()
}

// SetLocale sets the default locale used for newly written files. Locale is
// stored on a per-archive basis (parity with SFileSetLocale), since the
// public CreateFile/AddFile API does not currently take an explicit locale
// argument. Returns the previous default.
func (a *Archive) SetLocale(locale uint16) uint16 {
	prev := a.locale
	a.locale = locale

	return prev
}

// GetLocale returns the current default locale set by SetLocale.
func (a *Archive) GetLocale() uint16 {
	return a.locale
}

// SetAttributesFlags overrides which sub-attributes are written into the
// (attributes) file on Flush. Returns the previously configured flags.
// Mirrors SFileSetAttributes (StormLib.h MPQ_ATTRIBUTE_*).
//
// Bits: 0x01=CRC32, 0x02=FILETIME, 0x04=MD5. Pass 0 to suppress emission.
func (a *Archive) SetAttributesFlags(flags uint32) uint32 {
	return a.inner.SetAttributesFlags(flags)
}

// GetAttributesFlags returns the bitmask currently configured for the
// (attributes) file emitted on Flush.
func (a *Archive) GetAttributesFlags() uint32 {
	return a.inner.GetAttributesFlags()
}

// UpdateFileAttributes recomputes CRC32+MD5 attributes for `name` after a
// successful write. In our writer the attribute cache is populated
// automatically inside CreateFile/WriteFile/FinishFile, so this is a thin
// no-op compatibility shim that only validates the file exists.
func (a *Archive) UpdateFileAttributes(name string) error {
	if _, ok := a.findEntryForName(name); !ok {
		return ErrFileNotFound
	}

	return nil
}

func (a *Archive) SetAddFileCallback(cb AddFileCallback) {
	if cb == nil {
		a.inner.SetAddFileCallback(nil)
		return
	}

	a.inner.SetAddFileCallback(func(written, total uint32, done bool) {
		cb(written, total, done)
	})
}

func (a *Archive) RemoveFile(name string, locale uint16, platform uint8) error {
	err := a.inner.RemoveFile(name, locale, platform)
	if err == nil {
		return nil
	}

	if errors.Is(err, internalarchive.ErrFileHashNotFound) {
		return fmt.Errorf("%w: %v", ErrFileNotFound, err)
	}

	return err
}

func (a *Archive) RenameFile(oldName, newName string, locale uint16, platform uint8) error {
	err := a.inner.RenameFile(oldName, newName, locale, platform)
	if err == nil {
		return nil
	}

	if errors.Is(err, internalarchive.ErrFileHashNotFound) {
		return fmt.Errorf("%w: %v", ErrFileNotFound, err)
	}

	return err
}

func (a *Archive) Compact() error {
	return a.inner.Compact()
}

func (a *Archive) OpenPatchArchive(path, prefix string, flags uint32) error {
	err := a.inner.OpenPatchArchive(path, prefix, flags)
	if err == nil {
		return nil
	}

	if errors.Is(err, internalarchive.ErrArchiveWriteUnsupported) {
		return ErrUnsupportedFeature
	}

	return err
}

func (a *Archive) IsPatchedArchive() (bool, error) {
	return a.inner.IsPatchedArchive(), nil
}

func (a *Archive) VerifyFileChecksumByName(
	name string,
	locale uint16,
	platform uint8,
	wantCRC uint32,
	wantMD5 [16]byte,
) (bool, error) {
	gotCRC, gotMD5, err := a.GetFileChecksumsByName(name, locale, platform)
	if err != nil {
		return false, err
	}

	if gotCRC != wantCRC {
		return false, nil
	}

	return gotMD5 == wantMD5, nil
}
