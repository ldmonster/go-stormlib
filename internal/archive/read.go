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
	"bytes"
	"compress/bzip2"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/adler32"
	"io"
	"os"

	"github.com/ulikunitz/xz/lzma"

	"github.com/ldmonster/go-stormlib/internal/compress/adpcm"
	"github.com/ldmonster/go-stormlib/internal/compress/huffman"
	"github.com/ldmonster/go-stormlib/internal/compress/pkware"
	"github.com/ldmonster/go-stormlib/internal/mpq"
)

// ErrSectorChecksum reports an adler32 mismatch on a stored sector.
var ErrSectorChecksum = errors.New("sector checksum mismatch")

const (
	mpqFileSingleUnit = 0x01000000
	mpqFileCompressed = 0x00000200
	mpqFileSectorCRC  = 0x04000000
	// Sector compression masks (StormLib.h MPQ_COMPRESSION_*); first sector byte is the mask for single-method streams.
	mpqCompZlib  = 0x02 // MPQ_COMPRESSION_ZLIB
	mpqCompBzip2 = 0x10 // MPQ_COMPRESSION_BZIP2
	mpqCompLzma  = 0x12 // MPQ_COMPRESSION_LZMA
)

var (
	ErrIndexOutOfRange  = errors.New("file index out of range")
	ErrFileHashNotFound = errors.New("file hash entry not found")
	ErrDecodeFailed     = errors.New("decode failed")
	// ErrUnsupportedCodec is returned when the sector compression mask uses a codec not implemented yet (pkware, huffman, ...).
	ErrUnsupportedCodec = errors.New("unsupported mpq sector compression codec")
	// ErrEncryptionNeedsPath is returned for MPQ_FILE_ENCRYPTED entries when no internal path was supplied for DecryptFileKey (open-by-hash/index cannot derive the key).
	ErrEncryptionNeedsPath = errors.New(
		"encrypted mpq entry requires opening by internal file path for decryption key",
	)
)

type FileHandle struct {
	Entry            mpqIndexedEntry
	DecryptKeySource string // Storm DecryptFileKey path string; empty when opened by hash/index only.
}

type mpqIndexedEntry struct {
	BlockIndex uint32
	FilePos    uint32
	CSize      uint32
	FSize      uint32
	Flags      uint32
}

func (a *Archive) OpenIndexedFile(index int) (FileHandle, error) {
	if index < 0 || index >= len(a.FileIndex) {
		return FileHandle{}, fmt.Errorf("%w: %d", ErrIndexOutOfRange, index)
	}

	e := a.FileIndex[index]

	return FileHandle{
		Entry: mpqIndexedEntry{
			BlockIndex: e.BlockIndex,
			FilePos:    e.Block.FilePos,
			CSize:      e.Block.CompressedSize,
			FSize:      e.Block.UncompressedSize,
			Flags:      e.Block.Flags,
		},
		DecryptKeySource: "",
	}, nil
}

// OpenIndexedFileForDecrypt opens by hash table entry but supplies the MPQ-internal path string
// required to derive Storm DecryptFileKey when MPQ_FILE_ENCRYPTED is set.
func (a *Archive) OpenIndexedFileForDecrypt(
	hashA, hashB uint32,
	locale uint16,
	platform uint8,
	pathForDecryptKey string,
) (FileHandle, error) {
	e, ok := mpq.FindIndexedFileEntry(a.FileIndex, hashA, hashB, locale, platform)
	if !ok {
		return FileHandle{}, ErrFileHashNotFound
	}

	return FileHandle{
		Entry: mpqIndexedEntry{
			BlockIndex: e.BlockIndex,
			FilePos:    e.Block.FilePos,
			CSize:      e.Block.CompressedSize,
			FSize:      e.Block.UncompressedSize,
			Flags:      e.Block.Flags,
		},
		DecryptKeySource: pathForDecryptKey,
	}, nil
}

func (a *Archive) OpenIndexedFileByHash(
	hashA, hashB uint32,
	locale uint16,
	platform uint8,
) (FileHandle, error) {
	e, ok := mpq.FindIndexedFileEntry(a.FileIndex, hashA, hashB, locale, platform)
	if !ok {
		return FileHandle{}, ErrFileHashNotFound
	}

	return FileHandle{
		Entry: mpqIndexedEntry{
			BlockIndex: e.BlockIndex,
			FilePos:    e.Block.FilePos,
			CSize:      e.Block.CompressedSize,
			FSize:      e.Block.UncompressedSize,
			Flags:      e.Block.Flags,
		},
		DecryptKeySource: "",
	}, nil
}

func (a *Archive) ReadFile(h FileHandle) ([]byte, error) {
	f, err := osOpenFile(a.Path)
	if err != nil {
		return nil, fmt.Errorf("open archive for read: %w", err)
	}
	defer f.Close()

	b, err := readFileData(
		f,
		a.Header,
		h.Entry.FilePos,
		h.Entry.CSize,
		h.Entry.FSize,
		h.Entry.Flags,
		h.DecryptKeySource,
	)
	if err != nil {
		if errors.Is(err, ErrUnsupportedCodec) || errors.Is(err, ErrEncryptionNeedsPath) {
			return nil, err
		}

		return nil, fmt.Errorf("%w: %v", ErrDecodeFailed, err)
	}

	return b, nil
}

var osOpenFile = os.Open

func readFileData(
	r io.ReaderAt,
	h mpq.Header,
	filePos, csize, fsize, flags uint32,
	decryptKeySource string,
) ([]byte, error) {
	if fsize == 0 {
		return []byte{}, nil
	}

	encrypted := flags&mpq.FileFlagEncrypted != 0
	if encrypted && decryptKeySource == "" {
		return nil, ErrEncryptionNeedsPath
	}

	var fileKey uint32
	if encrypted {
		fileKey = mpq.DecryptFileKey(decryptKeySource, uint64(filePos), fsize, flags)
	}

	start := fileDataOffset(h, filePos)

	if flags&mpqFileSingleUnit != 0 {
		if flags&mpqFileCompressed == 0 {
			raw, err := readAt(r, start, uint64(fsize))
			if err != nil {
				return nil, err
			}

			decryptFileSector(raw, encrypted, fileKey, 0)

			return raw, nil
		}

		chunk, err := readAt(r, start, uint64(csize))
		if err != nil {
			return nil, err
		}

		decryptFileSector(chunk, encrypted, fileKey, 0)

		return decompressSector(chunk, fsize)
	}

	if flags&mpqFileCompressed != 0 {
		return readCompressedBySectors(
			r,
			start,
			csize,
			fsize,
			512<<h.SectorSizeExp,
			encrypted,
			fileKey,
			flags&mpqFileSectorCRC != 0,
		)
	}

	return readUncompressedBySectors(
		r,
		start,
		csize,
		fsize,
		512<<h.SectorSizeExp,
		encrypted,
		fileKey,
		flags&mpqFileSectorCRC != 0,
	)
}

func decryptFileSector(data []byte, encrypted bool, baseKey, sectorIndex uint32) {
	if !encrypted || len(data) == 0 {
		return
	}

	mpq.DecryptMpqFileBytes(data, baseKey+sectorIndex)
}

// verifySectorCRCs validates per-sector adler32 checksums (StormLib MPQ_FILE_SECTOR_CRC).
// The CRC table sits after the data sectors at offsets[sectorCount]..offsets[sectorCount+1]
// and stores sectorCount*4 bytes of little-endian adler32 values, possibly zlib-compressed.
// Zero or 0xFFFFFFFF values disable the check for that sector (matches StormLib semantics).
func verifySectorCRCs(
	r io.ReaderAt,
	start uint64,
	sectorSize uint32,
	offsets []uint32,
	sectorCount uint32,
	csize uint32,
	rawSectors [][]byte,
) error {
	if uint32(len(offsets)) < sectorCount+2 {
		return nil
	}

	crcOffset := offsets[sectorCount]

	crcEnd := offsets[sectorCount+1]
	if crcEnd < crcOffset || crcEnd > csize {
		return nil
	}

	crcCompressed := crcEnd - crcOffset
	expected := sectorCount * 4
	// StormLib ignores CRC tables that are too small or too large.
	if crcCompressed < 4 || crcCompressed > sectorSize {
		return nil
	}

	chunk, err := readAt(r, start+uint64(crcOffset), uint64(crcCompressed))
	if err != nil {
		return fmt.Errorf("read sector CRC table: %w", err)
	}

	var crcRaw []byte
	if crcCompressed >= expected {
		crcRaw = chunk[:expected]
	} else {
		crcRaw, err = decompressSector(chunk, expected)
		if err != nil {
			// Mismatched/unreadable CRC table is non-fatal (StormLib behavior).
			return nil
		}
	}

	for i := uint32(0); i < sectorCount; i++ {
		want := binary.LittleEndian.Uint32(crcRaw[i*4 : i*4+4])
		if want == 0 || want == 0xFFFFFFFF {
			continue
		}

		got := adler32.Checksum(rawSectors[i])
		if got != want {
			return fmt.Errorf(
				"%w: sector %d adler32 0x%08x != 0x%08x",
				ErrSectorChecksum,
				i,
				got,
				want,
			)
		}
	}

	return nil
}

func readUncompressedBySectors(
	r io.ReaderAt,
	start uint64,
	csize, fsize, sectorSize uint32,
	encrypted bool,
	fileKey uint32,
	hasCRC bool,
) ([]byte, error) {
	if sectorSize == 0 {
		return nil, fmt.Errorf("invalid sector size")
	}

	sectorCount := (fsize + sectorSize - 1) / sectorSize

	tableEntries := sectorCount + 1
	if hasCRC {
		tableEntries++
	}

	tableBytes := tableEntries * 4
	if tableBytes > csize {
		return nil, fmt.Errorf("sector table exceeds file block")
	}

	tableRaw, err := readAt(r, start, uint64(tableBytes))
	if err != nil {
		return nil, fmt.Errorf("read sector table: %w", err)
	}

	if encrypted {
		mpq.DecryptMpqFileBytes(tableRaw, fileKey-1)
	}

	offsets := make([]uint32, tableEntries)
	for i := range offsets {
		offsets[i] = binary.LittleEndian.Uint32(tableRaw[i*4 : i*4+4])
	}

	if offsets[0] != tableBytes {
		return nil, fmt.Errorf("invalid first sector offset")
	}

	out := make([]byte, 0, fsize)
	rawSectors := make([][]byte, sectorCount)

	for i := uint32(0); i < sectorCount; i++ {
		if offsets[i+1] < offsets[i] || offsets[i+1] > csize {
			return nil, fmt.Errorf("invalid sector offsets")
		}

		span := offsets[i+1] - offsets[i]

		sectorData, err := readAt(r, start+uint64(offsets[i]), uint64(span))
		if err != nil {
			return nil, fmt.Errorf("read sector %d: %w", i, err)
		}

		decryptFileSector(sectorData, encrypted, fileKey, i)
		rawSectors[i] = sectorData
		out = append(out, sectorData...)
	}

	if hasCRC {
		if err := verifySectorCRCs(
			r,
			start,
			sectorSize,
			offsets,
			sectorCount,
			csize,
			rawSectors,
		); err != nil {
			return nil, err
		}
	}

	if uint32(len(out)) < fsize {
		return nil, fmt.Errorf("decoded file too small")
	}

	return out[:fsize], nil
}

func readCompressedBySectors(
	r io.ReaderAt,
	start uint64,
	csize, fsize, sectorSize uint32,
	encrypted bool,
	fileKey uint32,
	hasCRC bool,
) ([]byte, error) {
	if sectorSize == 0 {
		return nil, fmt.Errorf("invalid sector size")
	}

	sectorCount := (fsize + sectorSize - 1) / sectorSize

	tableEntries := sectorCount + 1
	if hasCRC {
		tableEntries++
	}

	tableBytes := tableEntries * 4
	if tableBytes > csize {
		return nil, fmt.Errorf("sector table exceeds file block")
	}

	tableRaw, err := readAt(r, start, uint64(tableBytes))
	if err != nil {
		return nil, fmt.Errorf("read sector table: %w", err)
	}

	if encrypted {
		mpq.DecryptMpqFileBytes(tableRaw, fileKey-1)
	}

	offsets := make([]uint32, tableEntries)
	for i := range offsets {
		offsets[i] = binary.LittleEndian.Uint32(tableRaw[i*4 : i*4+4])
	}

	if offsets[0] != tableBytes {
		return nil, fmt.Errorf("invalid first sector offset")
	}

	out := make([]byte, 0, fsize)
	rawSectors := make([][]byte, sectorCount)

	for i := uint32(0); i < sectorCount; i++ {
		if offsets[i+1] < offsets[i] || offsets[i+1] > csize {
			return nil, fmt.Errorf("invalid sector offsets")
		}

		span := offsets[i+1] - offsets[i]

		chunk, err := readAt(r, start+uint64(offsets[i]), uint64(span))
		if err != nil {
			return nil, fmt.Errorf("read compressed sector %d: %w", i, err)
		}

		decryptFileSector(chunk, encrypted, fileKey, i)
		rawSectors[i] = chunk

		remaining := fsize - uint32(len(out))

		expected := sectorSize
		if remaining < expected {
			expected = remaining
		}

		// Per SCompDecompress: when the on-disk sector size equals or exceeds the
		// unpacked sector size, the sector is stored uncompressed (no method byte).
		if uint32(len(chunk)) >= expected {
			out = append(out, chunk[:expected]...)
			continue
		}

		sectorData, err := decompressSector(chunk, expected)
		if err != nil {
			return nil, fmt.Errorf("decompress sector %d: %w", i, err)
		}

		out = append(out, sectorData...)
	}

	if hasCRC {
		if err := verifySectorCRCs(
			r,
			start,
			sectorSize,
			offsets,
			sectorCount,
			csize,
			rawSectors,
		); err != nil {
			return nil, err
		}
	}

	if uint32(len(out)) < fsize {
		return nil, fmt.Errorf("decoded file too small")
	}

	return out[:fsize], nil
}

func decompressSector(chunk []byte, expected uint32) ([]byte, error) {
	if len(chunk) == 0 {
		return nil, fmt.Errorf("empty sector")
	}

	typ := chunk[0]
	payload := chunk[1:]

	if typ == mpqCompLzma {
		// Storm LZMA blocks contain one extra filter byte (must be zero) before
		// the classic LZMA header+stream expected by lzma.NewReader.
		if len(payload) < 2 {
			return nil, fmt.Errorf("lzma payload too short")
		}

		if payload[0] != 0 {
			return nil, fmt.Errorf("lzma filter byte unsupported: %d", payload[0])
		}

		lzmaReader, err := lzma.NewReader(bytes.NewReader(payload[1:]))
		if err != nil {
			return nil, err
		}

		out, err := io.ReadAll(lzmaReader)
		if err != nil {
			return nil, err
		}

		if uint32(len(out)) != expected {
			return nil, fmt.Errorf(
				"unexpected decompressed size: got %d want %d",
				len(out),
				expected,
			)
		}

		return out, nil
	}

	if unsupported := firstUnsupportedCompressionMask(typ); unsupported != 0 {
		return nil, fmt.Errorf("%w: 0x%02x", ErrUnsupportedCodec, unsupported)
	}

	// Apply codecs in Storm reverse-mask order: bzip2 -> pkware -> zlib -> sparse.
	// (StormLib's SCompDecompressInternal applies the inner-most codec first.)
	out := payload

	if typ&mpqCompBzip2 != 0 {
		var err error

		out, err = decompressBzip2Block(out)
		if err != nil {
			return nil, err
		}
	}

	if typ&mpqCompPkware != 0 {
		var err error

		out, err = pkware.Explode(out, int(expected))
		if err != nil {
			return nil, err
		}
	}

	if typ&mpqCompHuffman != 0 {
		var err error

		out, err = huffman.Decompress(out, int(expected))
		if err != nil {
			return nil, err
		}
	}

	if typ&mpqCompZlib != 0 {
		var err error

		out, err = decompressZlibBlock(out)
		if err != nil {
			return nil, err
		}
	}

	if typ&mpqCompSparse != 0 {
		var err error

		out, err = decompressSparseBlock(out, expected)
		if err != nil {
			return nil, err
		}
	}

	if typ&mpqCompAdpcmStereo != 0 {
		var err error

		out, err = adpcm.Decompress(out, 2)
		if err != nil {
			return nil, err
		}
	} else if typ&mpqCompAdpcmMono != 0 {
		var err error

		out, err = adpcm.Decompress(out, 1)
		if err != nil {
			return nil, err
		}
	}

	if uint32(len(out)) != expected {
		return nil, fmt.Errorf(
			"unexpected decompressed size: got %d want %d",
			len(out),
			expected,
		)
	}

	return out, nil
}

func decompressZlibBlock(payload []byte) ([]byte, error) {
	zr, err := zlib.NewReader(bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	return io.ReadAll(zr)
}

func decompressBzip2Block(payload []byte) ([]byte, error) {
	br := bzip2.NewReader(bytes.NewReader(payload))
	return io.ReadAll(br)
}

func firstUnsupportedCompressionMask(mask byte) byte {
	knownSupported := byte(
		mpqCompZlib |
			mpqCompBzip2 |
			mpqCompSparse |
			mpqCompPkware |
			mpqCompHuffman |
			mpqCompAdpcmMono |
			mpqCompAdpcmStereo,
	)
	if unknown := mask &^ knownSupported; unknown != 0 {
		for i := 0; i < 8; i++ {
			bit := byte(1 << i)
			if unknown&bit != 0 {
				return bit
			}
		}
	}

	return 0
}

const (
	mpqCompSparse      = 0x20
	mpqCompPkware      = 0x08
	mpqCompHuffman     = 0x01
	mpqCompAdpcmMono   = 0x40
	mpqCompAdpcmStereo = 0x80
)

func decompressSparseBlock(payload []byte, expected uint32) ([]byte, error) {
	if len(payload) < 5 {
		return nil, fmt.Errorf("sparse payload too short")
	}

	outLen := uint32(
		payload[0],
	)<<24 | uint32(
		payload[1],
	)<<16 | uint32(
		payload[2],
	)<<8 | uint32(
		payload[3],
	)
	if outLen > expected {
		return nil, fmt.Errorf("sparse output size %d exceeds expected %d", outLen, expected)
	}

	out := make([]byte, outLen)
	outPos := uint32(0)

	inPos := 4
	for inPos < len(payload) && outPos < outLen {
		tag := payload[inPos]
		inPos++

		if tag&0x80 != 0 {
			chunk := uint32(tag&0x7F) + 1
			if inPos+int(chunk) > len(payload) {
				return nil, fmt.Errorf("sparse nonzero chunk overruns input")
			}

			if outPos+chunk > outLen {
				chunk = outLen - outPos
			}

			copy(out[outPos:outPos+chunk], payload[inPos:inPos+int(chunk)])
			inPos += int(chunk)
			outPos += chunk

			continue
		}

		chunk := uint32(tag&0x7F) + 3
		if outPos+chunk > outLen {
			chunk = outLen - outPos
		}

		for i := uint32(0); i < chunk; i++ {
			out[outPos+i] = 0
		}

		outPos += chunk
	}

	if outPos != outLen {
		return nil, fmt.Errorf("sparse decoded length mismatch")
	}

	return out, nil
}

func fileDataOffset(h mpq.Header, rel uint32) uint64 {
	if h.FormatVersion == 0 {
		return uint64(uint32(h.Offset) + rel)
	}

	return uint64(h.Offset) + uint64(rel)
}

func readAt(r io.ReaderAt, off, n uint64) ([]byte, error) {
	buf := make([]byte, n)
	_, err := r.ReadAt(buf, int64(off))

	return buf, err
}
