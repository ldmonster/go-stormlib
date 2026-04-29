package storm

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"

	internalarchive "github.com/ldmonster/go-stormlib/internal/archive"
	"github.com/ldmonster/go-stormlib/internal/mpq"
)

// SFileVerifyFile flags (StormLib.h SFILE_VERIFY_*).
const (
	VerifySectorCRC uint32 = 0x00000001
	VerifyFileCRC   uint32 = 0x00000002
	VerifyFileMD5   uint32 = 0x00000004
	VerifyRawMD5    uint32 = 0x00000008
	VerifyAll       uint32 = VerifySectorCRC | VerifyFileCRC | VerifyFileMD5 | VerifyRawMD5
)

// SFileVerifyFile result bits (StormLib.h VERIFY_FILE_*).
const (
	VerifyFileOpenError      uint32 = 0x0001
	VerifyFileReadError      uint32 = 0x0002
	VerifyFileHasSectorCRC   uint32 = 0x0004
	VerifyFileSectorCRCError uint32 = 0x0008
	VerifyFileHasChecksum    uint32 = 0x0010
	VerifyFileChecksumError  uint32 = 0x0020
	VerifyFileHasMD5         uint32 = 0x0040
	VerifyFileMD5Error       uint32 = 0x0080
	VerifyFileHasRawMD5      uint32 = 0x0100
	VerifyFileRawMD5Error    uint32 = 0x0200
	VerifyFileErrorMask             = VerifyFileOpenError | VerifyFileReadError |
		VerifyFileSectorCRCError | VerifyFileChecksumError |
		VerifyFileMD5Error | VerifyFileRawMD5Error
)

// MPQ_ATTRIBUTE_* flags (StormLib.h).
const (
	attrFlagCRC32    = 0x00000001
	attrFlagFiletime = 0x00000002
	attrFlagMD5      = 0x00000004
	attrFlagPatchBit = 0x00000008
)

// ArchiveAttributes captures the parsed (attributes) file payload.
type ArchiveAttributes struct {
	Version  uint32
	Flags    uint32
	CRC32    []uint32
	Filetime []uint64
	MD5      [][16]byte
	PatchBit []byte // packed bit array, len = ceil(N/8)
}

// ErrAttributesUnavailable is returned by GetAttributes when the archive does not
// contain an (attributes) file or it cannot be parsed.
var ErrAttributesUnavailable = errors.New("attributes file unavailable")

// GetAttributes returns the parsed (attributes) payload for the archive, mirroring
// SFileGetAttributes / SAttributes structure layout.
func (a *Archive) GetAttributes() (ArchiveAttributes, error) {
	payload, err := a.ReadFileByName("(attributes)", 0, 0)
	if err != nil {
		return ArchiveAttributes{}, fmt.Errorf("%w: %v", ErrAttributesUnavailable, err)
	}

	count := uint32(len(a.inner.BlockTable))

	return parseAttributes(payload, count)
}

func parseAttributes(payload []byte, count uint32) (ArchiveAttributes, error) {
	if len(payload) < 8 {
		return ArchiveAttributes{}, fmt.Errorf("%w: payload too short", ErrAttributesUnavailable)
	}

	r := bytes.NewReader(payload)

	var hdr struct {
		Version uint32
		Flags   uint32
	}
	if err := binary.Read(r, binary.LittleEndian, &hdr); err != nil {
		return ArchiveAttributes{}, fmt.Errorf("%w: read header: %v", ErrAttributesUnavailable, err)
	}

	out := ArchiveAttributes{Version: hdr.Version, Flags: hdr.Flags}

	if hdr.Flags&attrFlagCRC32 != 0 {
		out.CRC32 = make([]uint32, count)
		if err := binary.Read(r, binary.LittleEndian, &out.CRC32); err != nil {
			return ArchiveAttributes{}, fmt.Errorf("%w: CRC32: %v", ErrAttributesUnavailable, err)
		}
	}

	if hdr.Flags&attrFlagFiletime != 0 {
		out.Filetime = make([]uint64, count)
		if err := binary.Read(r, binary.LittleEndian, &out.Filetime); err != nil {
			return ArchiveAttributes{}, fmt.Errorf(
				"%w: filetime: %v",
				ErrAttributesUnavailable,
				err,
			)
		}
	}

	if hdr.Flags&attrFlagMD5 != 0 {
		out.MD5 = make([][16]byte, count)
		for i := range out.MD5 {
			if _, err := r.Read(out.MD5[i][:]); err != nil {
				return ArchiveAttributes{}, fmt.Errorf(
					"%w: md5[%d]: %v",
					ErrAttributesUnavailable,
					i,
					err,
				)
			}
		}
	}

	if hdr.Flags&attrFlagPatchBit != 0 {
		bytesNeeded := (count + 7) / 8
		out.PatchBit = make([]byte, bytesNeeded)
		// Permit short tail (StormLib tolerates one missing tail byte).
		_, _ = r.Read(out.PatchBit)
	}

	return out, nil
}

// VerifyFile returns a bitmask result mirroring SFileVerifyFile. flags is a bitmask
// of VerifySectorCRC|VerifyFileCRC|VerifyFileMD5; flags == 0 enables CRC + MD5.
//
// Sector CRC verification is not yet implemented; if VerifySectorCRC is set and the
// file has MPQ_FILE_SECTOR_CRC, only the HasSectorCRC bit is set and the actual
// check is skipped (no SectorCRCError). Raw-MD5 verification is not yet implemented.
func (a *Archive) VerifyFile(name string, flags uint32) (uint32, error) {
	if flags == 0 {
		flags = VerifyFileCRC | VerifyFileMD5 | VerifySectorCRC
	}

	hashA := mpq.NameHashA(name)
	hashB := mpq.NameHashB(name)

	entry, ok := mpq.FindIndexedFileEntry(a.inner.FileIndex, hashA, hashB, 0, 0)
	if !ok {
		return VerifyFileOpenError, fmt.Errorf("%w: %s", ErrFileNotFound, name)
	}

	payload, err := a.ReadFileByName(name, 0, 0)
	if err != nil {
		return VerifyFileReadError, err
	}

	var result uint32

	if entry.Block.Flags&mpq.FileFlagSectorCRC != 0 && flags&VerifySectorCRC != 0 {
		result |= VerifyFileHasSectorCRC
	}

	attrs, attrsErr := a.GetAttributes()
	hasAttrs := attrsErr == nil

	if hasAttrs && flags&VerifyFileCRC != 0 && entry.BlockIndex < uint32(len(attrs.CRC32)) {
		want := attrs.CRC32[entry.BlockIndex]
		if want != 0 {
			result |= VerifyFileHasChecksum

			got := crc32.ChecksumIEEE(payload)
			if got != want {
				result |= VerifyFileChecksumError
			}
		}
	}

	if hasAttrs && flags&VerifyFileMD5 != 0 && entry.BlockIndex < uint32(len(attrs.MD5)) {
		want := attrs.MD5[entry.BlockIndex]
		if want != ([16]byte{}) {
			result |= VerifyFileHasMD5

			got := md5.Sum(payload)
			if got != want {
				result |= VerifyFileMD5Error
			}
		}
	}

	return result, nil
}

// Re-export internal archive read error for test parity.
var _ = internalarchive.ErrFileHashNotFound
