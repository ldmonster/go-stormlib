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

import (
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	idMPQ            = 0x1A51504D // "MPQ\x1A"
	idMPQUserdata    = 0x1B51504D // "MPQ\x1B"
	idMPK            = 0x1A4B504D // "MPK\x1A"
	headerMinSize    = 32
	headerSizeV2     = 44
	headerSizeV3     = 68
	headerSizeV4     = 208
	mpqProbeStride   = 0x200
	maxProbeBytes    = 0x08000000
	hashEntrySize    = 16
	blockEntrySize   = 16
	userDataByteSize = 16
	blockIndexMask   = 0x0FFFFFFF
)

var (
	ErrHeaderNotFound           = errors.New("mpq header not found")
	ErrUnsupportedFormat        = errors.New("unsupported mpq format version")
	ErrUnsupportedForeignHeader = errors.New("unsupported foreign archive header")
	ErrUnsupportedMPK           = errors.New("unsupported mpk archive")
	ErrUnsupportedSQP           = errors.New("unsupported sqp archive")
	ErrAviFile                  = errors.New("avi file is not a valid mpq archive")
)

type DiscoverOptions struct {
	ForceMPQV1      bool
	MarkerSignature uint32
}

type Header struct {
	Offset           int64
	HeaderSize       uint32
	ArchiveSize32    uint32
	FormatVersion    uint16
	SectorSizeExp    uint16
	HashTablePos     uint32
	BlockTablePos    uint32
	HashTableSize    uint32
	BlockTableSize   uint32
	HiBlockTablePos  uint64
	HashTablePosHi   uint16
	BlockTablePosHi  uint16
	ArchiveSize64    uint64
	BetTablePos64    uint64
	HetTablePos64    uint64
	HashTableSize64  uint64
	BlockTableSize64 uint64
	HiBlockSize64    uint64
	HetTableSize64   uint64
	BetTableSize64   uint64
	RawChunkSize     uint32
	MD5BlockTable    [16]byte
	MD5HashTable     [16]byte
	MD5HiBlockTable  [16]byte
	MD5BetTable      [16]byte
	MD5HetTable      [16]byte
	HeaderHashRegion [192]byte
	MPQHeaderMD5     [16]byte
	Malformed        bool
}

type UserData struct {
	HeaderOffset uint32
}

type HeaderWithMeta struct {
	Header   Header
	UserData *UserData
}

func FindHeader(data []byte) (Header, error) {
	result, err := FindHeaderWithMetaFromBytes(data)
	if err != nil {
		return Header{}, err
	}

	return result.Header, nil
}

func FindHeaderWithMetaFromBytes(data []byte) (HeaderWithMeta, error) {
	return FindHeaderWithMetaFromBytesWithOptions(data, DiscoverOptions{})
}

func FindHeaderWithMetaFromBytesWithOptions(
	data []byte,
	opts DiscoverOptions,
) (HeaderWithMeta, error) {
	marker := uint32(idMPQ)
	if opts.MarkerSignature != 0 {
		marker = opts.MarkerSignature
	}

	limit := len(data)
	if limit > maxProbeBytes {
		limit = maxProbeBytes
	}

	fullSize := int64(len(data))

	var (
		unsupportedErr error
		foreignErr     error
	)

	for i := 0; i+headerMinSize <= limit; i += mpqProbeStride {
		candidateID := binary.LittleEndian.Uint32(data[i : i+4])
		if candidateID == idMPK {
			foreignErr = ErrUnsupportedMPK
			continue
		}

		if candidateID == marker {
			h, err := parseHeaderAt(data, i, marker)
			if err != nil {
				continue
			}

			if opts.ForceMPQV1 {
				h = forceV1Header(h)
			}

			if looksLikeSQPHeaderAt(data, i, marker, uint64(fullSize), opts.ForceMPQV1) {
				foreignErr = ErrUnsupportedSQP
				continue
			}

			if err := ValidateHeaderLayout(h, fullSize); err != nil {
				if errors.Is(err, ErrUnsupportedFormat) {
					if looksLikeSQPHeaderAt(data, i, marker, uint64(fullSize), opts.ForceMPQV1) {
						foreignErr = ErrUnsupportedSQP
						continue
					}

					if coerced, ok := coerceUnknownVersionToV1(h, fullSize); ok {
						return HeaderWithMeta{Header: coerced}, nil
					}

					unsupportedErr = err
				}

				continue
			}

			h = normalizeHeaderForVersion(h)
			h = sanitizeAndClampHeaderForValidation(h, fullSize)

			return HeaderWithMeta{Header: h}, nil
		}

		if candidateID != idMPQUserdata {
			continue
		}

		if opts.ForceMPQV1 {
			continue
		}

		userData, err := parseUserDataAt(data, i)
		if err != nil {
			continue
		}

		headerOffset := i + int(userData.HeaderOffset)

		h, err := parseHeaderAt(data, headerOffset, marker)
		if err != nil {
			continue
		}

		if looksLikeSQPHeaderAt(data, headerOffset, marker, uint64(fullSize), opts.ForceMPQV1) {
			foreignErr = ErrUnsupportedSQP
			continue
		}

		if err := ValidateHeaderLayout(h, fullSize); err != nil {
			if errors.Is(err, ErrUnsupportedFormat) {
				if looksLikeSQPHeaderAt(
					data,
					headerOffset,
					marker,
					uint64(fullSize),
					opts.ForceMPQV1,
				) {
					foreignErr = ErrUnsupportedSQP
					continue
				}

				if coerced, ok := coerceUnknownVersionToV1(h, fullSize); ok {
					return HeaderWithMeta{
						Header:   coerced,
						UserData: &userData,
					}, nil
				}

				unsupportedErr = err
			}

			continue
		}

		h = normalizeHeaderForVersion(h)
		h = sanitizeAndClampHeaderForValidation(h, fullSize)

		return HeaderWithMeta{
			Header:   h,
			UserData: &userData,
		}, nil
	}

	if unsupportedErr != nil {
		return HeaderWithMeta{}, unsupportedErr
	}

	if foreignErr != nil {
		return HeaderWithMeta{}, fmt.Errorf("%w: %w", ErrUnsupportedForeignHeader, foreignErr)
	}

	return HeaderWithMeta{}, ErrHeaderNotFound
}

func FindHeaderWithMeta(r io.ReaderAt, size int64) (HeaderWithMeta, error) {
	return FindHeaderWithMetaWithOptions(r, size, DiscoverOptions{})
}

func FindHeaderWithMetaWithOptions(
	r io.ReaderAt,
	size int64,
	opts DiscoverOptions,
) (HeaderWithMeta, error) {
	if size < headerMinSize {
		return HeaderWithMeta{}, ErrHeaderNotFound
	}

	marker := uint32(idMPQ)
	if opts.MarkerSignature != 0 {
		marker = opts.MarkerSignature
	}

	end := size
	if end > maxProbeBytes {
		end = maxProbeBytes
	}

	var (
		unsupportedErr error
		foreignErr     error
		aviErr         error
	)

	probe := make([]byte, userDataByteSize)
	for offset := int64(0); offset+headerMinSize <= end; offset += mpqProbeStride {
		if err := readExactAt(r, probe[:4], offset); err != nil {
			continue
		}

		if offset == 0 && looksLikeAVIHeader(r, size) {
			aviErr = ErrAviFile
			continue
		}

		candidateID := binary.LittleEndian.Uint32(probe[:4])

		switch candidateID {
		case idMPK:
			foreignErr = ErrUnsupportedMPK
			continue
		case marker:
			headerBuf, err := readHeaderBytesAt(r, offset, size)
			if err != nil {
				continue
			}

			h, err := parseHeaderAt(headerBuf, 0, marker)
			if err != nil {
				continue
			}

			h.Offset = offset
			if opts.ForceMPQV1 {
				h = forceV1Header(h)
			}

			if looksLikeSQPHeaderInReader(r, offset, marker, uint64(size), opts.ForceMPQV1) {
				foreignErr = ErrUnsupportedSQP
				continue
			}

			if err := ValidateHeaderLayout(h, size); err != nil {
				if errors.Is(err, ErrUnsupportedFormat) {
					if looksLikeSQPHeaderInReader(
						r,
						offset,
						marker,
						uint64(size),
						opts.ForceMPQV1,
					) {
						foreignErr = ErrUnsupportedSQP
						continue
					}

					if coerced, ok := coerceUnknownVersionToV1(h, size); ok {
						return HeaderWithMeta{Header: coerced}, nil
					}

					unsupportedErr = err
				}

				continue
			}

			h = normalizeHeaderForVersion(h)
			h = sanitizeAndClampHeaderForValidation(h, size)

			return HeaderWithMeta{Header: h}, nil

		case idMPQUserdata:
			if opts.ForceMPQV1 {
				continue
			}

			if err := readExactAt(r, probe, offset); err != nil {
				continue
			}

			userData, err := parseUserDataAt(probe, 0)
			if err != nil {
				continue
			}

			headerOffset := offset + int64(userData.HeaderOffset)
			if headerOffset+headerMinSize > size {
				continue
			}

			headerBuf, err := readHeaderBytesAt(r, headerOffset, size)
			if err != nil {
				continue
			}

			h, err := parseHeaderAt(headerBuf, 0, marker)
			if err != nil {
				continue
			}

			h.Offset = headerOffset
			if looksLikeSQPHeaderInReader(r, headerOffset, marker, uint64(size), opts.ForceMPQV1) {
				foreignErr = ErrUnsupportedSQP
				continue
			}

			if err := ValidateHeaderLayout(h, size); err != nil {
				if errors.Is(err, ErrUnsupportedFormat) {
					if looksLikeSQPHeaderInReader(
						r,
						headerOffset,
						marker,
						uint64(size),
						opts.ForceMPQV1,
					) {
						foreignErr = ErrUnsupportedSQP
						continue
					}

					if coerced, ok := coerceUnknownVersionToV1(h, size); ok {
						return HeaderWithMeta{
							Header:   coerced,
							UserData: &userData,
						}, nil
					}

					unsupportedErr = err
				}

				continue
			}

			h = normalizeHeaderForVersion(h)
			h = sanitizeAndClampHeaderForValidation(h, size)

			return HeaderWithMeta{
				Header:   h,
				UserData: &userData,
			}, nil
		}
	}

	if aviErr != nil {
		return HeaderWithMeta{}, aviErr
	}

	if unsupportedErr != nil {
		return HeaderWithMeta{}, unsupportedErr
	}

	if foreignErr != nil {
		return HeaderWithMeta{}, fmt.Errorf("%w: %w", ErrUnsupportedForeignHeader, foreignErr)
	}

	return HeaderWithMeta{}, ErrHeaderNotFound
}

func parseHeaderAt(data []byte, offset int, marker uint32) (Header, error) {
	if offset+headerMinSize > len(data) {
		return Header{}, ErrHeaderNotFound
	}

	raw := data[offset:]
	if binary.LittleEndian.Uint32(raw[0:4]) != marker {
		return Header{}, ErrHeaderNotFound
	}

	header := Header{
		Offset:         int64(offset),
		HeaderSize:     binary.LittleEndian.Uint32(raw[4:8]),
		ArchiveSize32:  binary.LittleEndian.Uint32(raw[8:12]),
		FormatVersion:  binary.LittleEndian.Uint16(raw[12:14]),
		SectorSizeExp:  binary.LittleEndian.Uint16(raw[14:16]),
		HashTablePos:   binary.LittleEndian.Uint32(raw[16:20]),
		BlockTablePos:  binary.LittleEndian.Uint32(raw[20:24]),
		HashTableSize:  binary.LittleEndian.Uint32(raw[24:28]),
		BlockTableSize: binary.LittleEndian.Uint32(raw[28:32]),
		ArchiveSize64:  uint64(binary.LittleEndian.Uint32(raw[8:12])),
	}

	if header.HeaderSize < headerMinSize {
		return Header{}, fmt.Errorf("mpq header too small: %d", header.HeaderSize)
	}

	if len(raw) >= headerSizeV2 {
		header.HiBlockTablePos = binary.LittleEndian.Uint64(raw[32:40])
		header.HashTablePosHi = binary.LittleEndian.Uint16(raw[40:42])
		header.BlockTablePosHi = binary.LittleEndian.Uint16(raw[42:44])
	}

	if len(raw) >= headerSizeV3 {
		header.ArchiveSize64 = binary.LittleEndian.Uint64(raw[44:52])
		header.BetTablePos64 = binary.LittleEndian.Uint64(raw[52:60])
		header.HetTablePos64 = binary.LittleEndian.Uint64(raw[60:68])
	}

	if len(raw) >= 108 {
		header.HashTableSize64 = binary.LittleEndian.Uint64(raw[68:76])
		header.BlockTableSize64 = binary.LittleEndian.Uint64(raw[76:84])
		header.HiBlockSize64 = binary.LittleEndian.Uint64(raw[84:92])
		header.HetTableSize64 = binary.LittleEndian.Uint64(raw[92:100])
		header.BetTableSize64 = binary.LittleEndian.Uint64(raw[100:108])
	}

	if len(raw) >= 112 {
		header.RawChunkSize = binary.LittleEndian.Uint32(raw[108:112])
	}

	if len(raw) >= headerSizeV4 {
		copy(header.MD5BlockTable[:], raw[112:128])
		copy(header.MD5HashTable[:], raw[128:144])
		copy(header.MD5HiBlockTable[:], raw[144:160])
		copy(header.MD5BetTable[:], raw[160:176])
		copy(header.MD5HetTable[:], raw[176:192])
		copy(header.HeaderHashRegion[:], raw[0:192])
		copy(header.MPQHeaderMD5[:], raw[192:208])
	}

	return header, nil
}

func parseUserDataAt(data []byte, offset int) (UserData, error) {
	if offset+userDataByteSize > len(data) {
		return UserData{}, ErrHeaderNotFound
	}

	raw := data[offset:]
	if binary.LittleEndian.Uint32(raw[0:4]) != idMPQUserdata {
		return UserData{}, ErrHeaderNotFound
	}

	userDataSize := binary.LittleEndian.Uint32(raw[4:8])
	headerOffset := binary.LittleEndian.Uint32(raw[8:12])
	userDataHeaderSize := binary.LittleEndian.Uint32(raw[12:16])

	if userDataHeaderSize > userDataSize || userDataSize > headerOffset {
		return UserData{}, fmt.Errorf("invalid mpq userdata layout")
	}

	return UserData{HeaderOffset: headerOffset}, nil
}

func ValidateHeaderLayout(h Header, fileSize int64) error {
	h = normalizeHeaderForVersion(h)
	h = sanitizeAndClampHeaderForValidation(h, fileSize)

	if h.Offset < 0 || h.Offset >= fileSize {
		return fmt.Errorf("header offset out of range: %d", h.Offset)
	}

	if h.SectorSizeExp == 0 {
		return errors.New("invalid sector size exponent: 0")
	}

	if h.FormatVersion > 3 {
		return fmt.Errorf("%w: %d", ErrUnsupportedFormat, h.FormatVersion)
	}

	fileSizeU := uint64(fileSize)

	if h.FormatVersion == 3 {
		if h.HeaderSize < headerSizeV4 {
			return fmt.Errorf("v4 header too small: %d", h.HeaderSize)
		}

		if h.ArchiveSize64 == 0 || h.Offset+int64(h.ArchiveSize64) > fileSize {
			return fmt.Errorf("v4 archive size out of range")
		}

		if !verifyTandemTablePositions(
			h.Offset,
			uint64(h.HashTablePos),
			h.HashTableSize64,
			uint64(h.BlockTablePos),
			h.BlockTableSize64,
			fileSizeU,
		) &&
			!verifyTandemTablePositions(
				h.Offset,
				h.HetTablePos64,
				h.HetTableSize64,
				h.BetTablePos64,
				h.BetTableSize64,
				fileSizeU,
			) {
			return fmt.Errorf("v4 tandem table positions invalid")
		}

		if !isValidHeaderMD5(h.MPQHeaderMD5) {
			return fmt.Errorf("v4 header md5 missing or invalid")
		}

		if !verifyHeaderMD5(h.HeaderHashRegion, h.MPQHeaderMD5) {
			return fmt.Errorf("v4 header md5 mismatch")
		}
	}

	hashPos64 := uint64(h.HashTablePos)
	blockPos64 := uint64(h.BlockTablePos)

	tableBase := h.Offset
	if h.FormatVersion == 0 {
		hashPos64 = wrapV1Offset(h.Offset, h.HashTablePos)
		blockPos64 = wrapV1Offset(h.Offset, h.BlockTablePos)
		tableBase = 0
	} else if h.FormatVersion >= 1 {
		hashPos64 = makeOffset64(h.HashTablePosHi, h.HashTablePos)
		blockPos64 = makeOffset64(h.BlockTablePosHi, h.BlockTablePos)
	}

	hashEnd, ok := tableRange64(tableBase, hashPos64, h.HashTableSize, hashEntrySize)
	if !ok || hashEnd > fileSizeU {
		return fmt.Errorf("hash table out of range")
	}

	blockEnd, ok := tableRange64(tableBase, blockPos64, h.BlockTableSize, blockEntrySize)
	if !ok || blockEnd > fileSizeU {
		return fmt.Errorf("block table out of range")
	}

	if h.FormatVersion >= 2 {
		if h.HiBlockTablePos > fileSizeU {
			return fmt.Errorf("hi block table out of range")
		}

		if h.BetTablePos64 > fileSizeU {
			return fmt.Errorf("bet table out of range")
		}

		if h.HetTablePos64 > fileSizeU {
			return fmt.Errorf("het table out of range")
		}
	}

	return nil
}

func readExactAt(r io.ReaderAt, dst []byte, offset int64) error {
	_, err := r.ReadAt(dst, offset)
	return err
}

func coerceUnknownVersionToV1(h Header, fileSize int64) (Header, bool) {
	if h.FormatVersion <= 3 {
		return Header{}, false
	}

	coerced := h
	coerced.FormatVersion = 0
	coerced.HeaderSize = headerMinSize

	coerced.Malformed = true
	if err := ValidateHeaderLayout(coerced, fileSize); err != nil {
		return Header{}, false
	}

	return coerced, true
}

func normalizeHeaderForVersion(h Header) Header {
	switch h.FormatVersion {
	case 0:
		// C path for v1 fixes malformed header size to 0x20.
		if h.HeaderSize != headerMinSize {
			h.Malformed = true
		}

		h.HeaderSize = headerMinSize
	case 1:
		// C path for malformed v2 falls back to v1 semantics.
		if h.HeaderSize != headerSizeV2 {
			h.FormatVersion = 0
			h.HeaderSize = headerMinSize
			h.Malformed = true
		}
	case 2:
		// C accepts smaller optional v3 headers and caps to v3 max.
		if h.HeaderSize > headerSizeV3 {
			h.Malformed = true
			h.HeaderSize = headerSizeV3
		}
	case 3:
		// C normalizes v4 header size to 0xD0.
		if h.HeaderSize != headerSizeV4 {
			h.Malformed = true
		}

		h.HeaderSize = headerSizeV4
	}

	return h
}

func sanitizeAndClampHeaderForValidation(h Header, fileSize int64) Header {
	// StormLib masks both table sizes to prevent overflow-prone values.
	h.HashTableSize &= blockIndexMask

	h.BlockTableSize &= blockIndexMask
	if fileSize <= 0 {
		return h
	}
	// C keeps malformed archives open by clamping oversized v1 block table count.
	if h.FormatVersion == 0 {
		start := wrapV1Offset(h.Offset, h.BlockTablePos)
		if start < uint64(h.Offset) {
			h.Malformed = true
		}

		if start < uint64(fileSize) {
			remaining := uint64(fileSize) - start

			maxCount := uint32(remaining / blockEntrySize)
			if h.BlockTableSize > maxCount {
				h.BlockTableSize = maxCount
				h.Malformed = true
			}
		}
	}

	return h
}

func tableRange64(
	baseOffset int64,
	tablePos uint64,
	tableCount uint32,
	entrySize uint64,
) (uint64, bool) {
	base := uint64(baseOffset)
	pos := tablePos

	start := base + pos
	if start < base {
		return 0, false
	}

	sizeBytes := uint64(tableCount) * entrySize

	end := start + sizeBytes
	if end < start {
		return 0, false
	}

	return end, true
}

func makeOffset64(hi uint16, lo uint32) uint64 {
	return (uint64(hi) << 32) | uint64(lo)
}

func wrapV1Offset(baseOffset int64, rel uint32) uint64 {
	return uint64(uint32(baseOffset) + rel)
}

func readHeaderBytesAt(r io.ReaderAt, offset, fileSize int64) ([]byte, error) {
	var base [headerMinSize]byte
	if err := readExactAt(r, base[:], offset); err != nil {
		return nil, err
	}

	format := binary.LittleEndian.Uint16(base[12:14])

	needed := requiredHeaderReadSize(format)
	if needed <= headerMinSize {
		return base[:], nil
	}

	if offset+int64(needed) > fileSize {
		return nil, io.ErrUnexpectedEOF
	}

	buf := make([]byte, needed)
	copy(buf, base[:])

	if err := readExactAt(r, buf[headerMinSize:], offset+headerMinSize); err != nil {
		return nil, err
	}

	return buf, nil
}

func requiredHeaderReadSize(format uint16) int {
	switch format {
	case 0:
		return headerMinSize
	case 1:
		return headerSizeV2
	case 2:
		return headerSizeV3
	case 3:
		return headerSizeV4
	default:
		return headerMinSize
	}
}

func verifyTandemTablePositions(baseOffset int64, pos1, size1, pos2, size2, fileSize uint64) bool {
	if pos1 == 0 && pos2 == 0 {
		return false
	}

	start1 := uint64(baseOffset) + pos1

	start2 := uint64(baseOffset) + pos2
	if start1 < uint64(baseOffset) || start2 < uint64(baseOffset) {
		return false
	}

	end1 := start1 + size1

	end2 := start2 + size2
	if end1 < start1 || end2 < start2 {
		return false
	}

	if end1 > fileSize || end2 > fileSize {
		return false
	}

	return start2 >= end1
}

func forceV1Header(h Header) Header {
	h.FormatVersion = 0
	h.HeaderSize = headerMinSize
	h.Malformed = true

	return h
}

func isValidHeaderMD5(md5sum [16]byte) bool {
	for _, b := range md5sum {
		if b != 0 {
			return true
		}
	}

	return false
}

func verifyHeaderMD5(region [192]byte, expected [16]byte) bool {
	sum := md5.Sum(region[:])
	return sum == expected
}

func looksLikeSQPHeaderAt(
	data []byte,
	offset int,
	marker uint32,
	fileSize uint64,
	forceV1 bool,
) bool {
	if forceV1 {
		return false
	}

	if offset < 0 || offset+headerMinSize > len(data) {
		return false
	}

	return looksLikeSQPHeaderRaw(data[offset:offset+headerMinSize], marker, fileSize)
}

func looksLikeSQPHeaderInReader(
	r io.ReaderAt,
	offset int64,
	marker uint32,
	fileSize uint64,
	forceV1 bool,
) bool {
	if forceV1 || offset < 0 {
		return false
	}

	var raw [headerMinSize]byte
	if err := readExactAt(r, raw[:], offset); err != nil {
		return false
	}

	return looksLikeSQPHeaderRaw(raw[:], marker, fileSize)
}

func looksLikeSQPHeaderRaw(raw []byte, marker uint32, fileSize uint64) bool {
	// ConvertSqpHeaderToFormat4 checks translated header fields:
	// signature, TSQP header size (0x20), archive size equals file size,
	// and fixed SQP values wFormatVersion==1 and wSectorSize==3 (from bytes 0x1C..0x1F).
	if len(raw) < headerMinSize {
		return false
	}

	if binary.LittleEndian.Uint32(raw[0:4]) != marker {
		return false
	}

	if binary.LittleEndian.Uint32(raw[4:8]) != headerMinSize {
		return false
	}

	if uint64(binary.LittleEndian.Uint32(raw[8:12])) != fileSize {
		return false
	}

	if binary.LittleEndian.Uint16(raw[28:30]) != 1 {
		return false
	}

	if binary.LittleEndian.Uint16(raw[30:32]) != 3 {
		return false
	}

	return true
}

func looksLikeAVIHeader(r io.ReaderAt, fileSize int64) bool {
	if fileSize < 16 {
		return false
	}

	var hdr [16]byte
	if err := readExactAt(r, hdr[:], 0); err != nil {
		return false
	}

	return string(hdr[0:4]) == "RIFF" && string(hdr[8:12]) == "AVI " && string(hdr[12:16]) == "LIST"
}
