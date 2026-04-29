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
	"compress/zlib"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/ldmonster/go-stormlib/internal/mpq"
)

const (
	hashEntryEmpty   = 0xFFFFFFFF
	hashEntryDeleted = 0xFFFFFFFE
	mpqFileExists    = 0x80000000
)

var (
	ErrWriteInProgress         = errors.New("mpq file write already in progress")
	ErrNoWriteInProgress       = errors.New("mpq file write not started")
	ErrWriteSizeExceeded       = errors.New("mpq file write exceeds declared size")
	ErrWriteSizeIncomplete     = errors.New("mpq file write incomplete")
	ErrWriteFlagsUnsupported   = errors.New("unsupported mpq file write flags")
	ErrArchiveWriteUnsupported = errors.New("archive write shape unsupported")
	ErrRenameCollision         = errors.New("rename target already exists")
	ErrInvalidFileName         = errors.New("invalid mpq file name")
	ErrInternalFileName        = errors.New("internal mpq file name")
	ErrUnsupportedCodecWrite   = errors.New("unsupported mpq codec for write")
)

type pendingWrite struct {
	name        string
	size        uint32
	flags       uint32
	buf         []byte
	compression byte // codec mask byte (0 = default zlib when mpqFileCompressed set)
}

func (a *Archive) SetAddFileCallback(cb func(written, total uint32, done bool)) {
	a.addFileCallback = cb
}

// CreateFile begins a minimal write lifecycle similar to SFileCreateFile.
// Current parity scope is intentionally narrow: uncompressed single-unit writes.
func (a *Archive) CreateFile(name string, fileSize, flags uint32) error {
	return a.CreateFileEx(name, fileSize, flags, 0)
}

// CreateFileEx is the explicit-codec variant of CreateFile. The compression
// argument is the MPQ codec mask byte (e.g. 0x02 zlib, 0x10 bzip2). Zero
// selects the implementation default when MPQ_FILE_COMPRESS is set.
func (a *Archive) CreateFileEx(name string, fileSize, flags uint32, compression byte) error {
	if a.pendingWrite != nil {
		return ErrWriteInProgress
	}

	if name == "" {
		return ErrInvalidFileName
	}

	if isPseudoFileName(name) {
		return ErrInvalidFileName
	}

	if isInternalMpqFileName(name) {
		return ErrInternalFileName
	}

	if flags&^allowedCreateFileFlags() != 0 {
		return fmt.Errorf("%w: 0x%08x", ErrWriteFlagsUnsupported, flags)
	}

	a.pendingWrite = &pendingWrite{
		name:        name,
		size:        fileSize,
		flags:       flags,
		buf:         make([]byte, 0, fileSize),
		compression: compression,
	}
	a.emitAddFileProgress(0, fileSize, false)

	return nil
}

// WriteFile appends bytes for the pending write lifecycle, similar to SFileWriteFile.
func (a *Archive) WriteFile(data []byte) error {
	p := a.pendingWrite
	if p == nil {
		return ErrNoWriteInProgress
	}

	if uint64(len(p.buf))+uint64(len(data)) > uint64(p.size) {
		return ErrWriteSizeExceeded
	}

	p.buf = append(p.buf, data...)
	a.emitAddFileProgress(uint32(len(p.buf)), p.size, false)

	return nil
}

// FinishFile persists the pending file and updates MPQ tables/header, similar to SFileFinishFile.
func (a *Archive) FinishFile() error {
	p := a.pendingWrite
	if p == nil {
		return ErrNoWriteInProgress
	}

	defer func() { a.pendingWrite = nil }()

	if uint32(len(p.buf)) != p.size {
		return ErrWriteSizeIncomplete
	}

	if err := a.persistWrite(p); err != nil {
		return err
	}

	a.emitAddFileProgress(p.size, p.size, true)

	return nil
}

func (a *Archive) persistWrite(p *pendingWrite) error {
	sectorSize := uint32(512) << uint32(a.Header.SectorSizeExp)
	// Use sectored layout when the file exceeds one sector AND the caller requested
	// compressed or unencrypted-default layout. Single-unit single-sector remains the
	// default for tiny payloads (parity with StormLib SFileAddFile heuristics).
	if sectorSize == 0 || p.size <= sectorSize {
		return a.persistSingleUnitWrite(p)
	}

	return a.persistSectoredWrite(p, sectorSize)
}

func (a *Archive) emitAddFileProgress(written, total uint32, done bool) {
	if a.addFileCallback != nil {
		a.addFileCallback(written, total, done)
	}
}

func (a *Archive) persistSingleUnitWrite(p *pendingWrite) error {
	if a.Header.HashTableSize == 0 {
		return fmt.Errorf("%w: missing hash table", ErrArchiveWriteUnsupported)
	}

	hashes := make([]mpq.HashEntry, len(a.HashTable))
	copy(hashes, a.HashTable)

	// Replace-existing semantics (MPQ_FILE_REPLACEEXISTING is StormLib's
	// default): mark any prior live entry for the same (name, locale=0,
	// platform=0) tuple as deleted so its slot is reusable and we do not emit
	// two live entries for the same logical file.
	markExistingForReplace(hashes, p.name, 0, 0)

	slot, err := findInsertSlot(hashes, p.name)
	if err != nil {
		return err
	}

	blockIndex := uint32(len(a.BlockTable))
	filePos := a.Header.ArchiveSize32
	blockFlags := mpqFileSingleUnit | mpqFileExists | (p.flags & allowedCreateFileFlags())

	storedPayload, err := encodeWritePayload(
		p.buf,
		p.name,
		filePos,
		p.size,
		blockFlags,
		p.compression,
	)
	if err != nil {
		return err
	}

	compressedSize := uint32(len(storedPayload))

	hashes[slot] = mpq.HashEntry{
		HashA:      mpq.NameHashA(p.name),
		HashB:      mpq.NameHashB(p.name),
		Locale:     0,
		Platform:   0,
		Flags:      0,
		BlockIndex: blockIndex,
	}

	blocks := make([]mpq.BlockEntry, len(a.BlockTable), len(a.BlockTable)+1)
	copy(blocks, a.BlockTable)
	blocks = append(blocks, mpq.BlockEntry{
		FilePos:          filePos,
		CompressedSize:   compressedSize,
		UncompressedSize: p.size,
		Flags:            blockFlags,
	})

	nextHeader := a.Header
	nextHeader.BlockTableSize = uint32(len(blocks))
	nextHeader.BlockTablePos = filePos + compressedSize

	nextHeader.ArchiveSize32 = nextHeader.BlockTablePos + uint32(
		len(blocks),
	)*uint32(
		mpqBlockEntrySize,
	)
	if nextHeader.FormatVersion >= 2 {
		nextHeader.ArchiveSize64 = uint64(nextHeader.ArchiveSize32)
	}

	if nextHeader.FormatVersion >= 3 {
		nextHeader.HashTableSize64 = uint64(nextHeader.HashTableSize) * uint64(mpqHashEntrySize)
		nextHeader.BlockTableSize64 = uint64(nextHeader.BlockTableSize) * uint64(mpqBlockEntrySize)
	}

	if err := a.persistHeaderAndTables(nextHeader, hashes, blocks); err != nil {
		return err
	}

	if err := a.writePayload(filePos, storedPayload); err != nil {
		return fmt.Errorf("write file payload: %w", err)
	}

	a.Header = nextHeader
	a.HashTable = hashes
	a.BlockTable = blocks
	a.FileIndex = mpq.BuildFileIndex(hashes, blocks)
	a.recordBlockName(blockIndex, p.name)
	a.recordBlockAttributes(blockIndex, p.buf)

	return nil
}

func allowedCreateFileFlags() uint32 {
	return mpqFileCompressed | mpq.FileFlagEncrypted | mpq.FileFlagKeyV2
}

func encodeWritePayload(
	plain []byte,
	name string,
	filePos uint32,
	uncompressedSize uint32,
	blockFlags uint32,
	codec byte,
) ([]byte, error) {
	out := make([]byte, len(plain))
	copy(out, plain)

	if blockFlags&mpqFileCompressed != 0 {
		mask := codec
		if mask == 0 {
			mask = 0x02 // default zlib
		}

		compressed, err := compressSingleUnit(out, mask)
		if err != nil {
			return nil, err
		}

		// If compression does not shrink the payload, keep the compressed
		// result anyway (zero-codec passthrough; the read path handles this).
		out = compressed
	}

	if blockFlags&mpq.FileFlagEncrypted != 0 {
		key := mpq.DecryptFileKey(name, uint64(filePos), uncompressedSize, blockFlags)
		mpq.EncryptMpqFileBytes(out, key)
	}

	return out, nil
}

// compressSingleUnit compresses `raw` using the supplied codec mask and
// returns the on-disk byte sequence (codec byte followed by codec-specific
// payload).
func compressSingleUnit(raw []byte, codec byte) ([]byte, error) {
	switch codec {
	case 0x02: // zlib
		var compressed bytes.Buffer

		zw := zlib.NewWriter(&compressed)
		if _, err := zw.Write(raw); err != nil {
			return nil, fmt.Errorf("zlib compress payload: %w", err)
		}

		if err := zw.Close(); err != nil {
			return nil, fmt.Errorf("zlib finalize payload: %w", err)
		}

		body := compressed.Bytes()
		out := make([]byte, 1+len(body))
		out[0] = 0x02
		copy(out[1:], body)

		return out, nil
	case 0x10: // bzip2
		body, err := bzip2EncodeBytes(raw)
		if err != nil {
			return nil, fmt.Errorf("bzip2 compress payload: %w", err)
		}

		out := make([]byte, 1+len(body))
		out[0] = 0x10
		copy(out[1:], body)

		return out, nil
	case 0x12: // lzma
		body, err := lzmaEncodeBytes(raw)
		if err != nil {
			return nil, fmt.Errorf("lzma compress payload: %w", err)
		}

		out := make([]byte, 1+len(body))
		out[0] = 0x12
		copy(out[1:], body)

		return out, nil
	default:
		return nil, fmt.Errorf("%w: 0x%02x", ErrUnsupportedCodecWrite, codec)
	}
}

// persistSectoredWrite splits the pending payload into fixed-size sectors, optionally
// compressing each sector with zlib (storing the compressed bytes only when shorter
// than the raw sector to match SFileAddFile parity), encrypting per-sector with the
// derived file key, and emitting a leading sector-offset table.
func (a *Archive) persistSectoredWrite(p *pendingWrite, sectorSize uint32) error {
	if a.Header.HashTableSize == 0 {
		return fmt.Errorf("%w: missing hash table", ErrArchiveWriteUnsupported)
	}

	hashes := make([]mpq.HashEntry, len(a.HashTable))
	copy(hashes, a.HashTable)

	// Replace-existing parity for the sectored write path; see
	// persistSingleUnitWrite for the rationale.
	markExistingForReplace(hashes, p.name, 0, 0)

	slot, err := findInsertSlot(hashes, p.name)
	if err != nil {
		return err
	}

	blockIndex := uint32(len(a.BlockTable))
	filePos := a.Header.ArchiveSize32
	// Sectored files are not single-unit; compression bit is required when any sector
	// is compressed. Set MPQ_FILE_COMPRESS unconditionally for the sectored path.
	blockFlags := mpqFileCompressed | mpqFileExists | (p.flags & allowedCreateFileFlags() & ^uint32(mpqFileSingleUnit))

	sectorCount := (p.size + sectorSize - 1) / sectorSize
	encrypted := blockFlags&mpq.FileFlagEncrypted != 0

	var fileKey uint32
	if encrypted {
		fileKey = mpq.DecryptFileKey(p.name, uint64(filePos), p.size, blockFlags)
	}

	// Encode each sector: zlib-compress when shorter than raw, otherwise store raw.
	sectorData := make([][]byte, sectorCount)
	for i := uint32(0); i < sectorCount; i++ {
		start := i * sectorSize

		end := start + sectorSize
		if end > p.size {
			end = p.size
		}

		raw := p.buf[start:end]

		codec := p.compression
		if codec == 0 {
			codec = 0x02
		}

		stored, err := compressSingleUnit(raw, codec)
		if err != nil {
			return fmt.Errorf("compress sector %d: %w", i, err)
		}
		// Store raw when compression doesn't actually shrink the sector.
		if len(stored) >= len(raw) {
			stored = make([]byte, len(raw))
			copy(stored, raw)
		}

		if encrypted {
			mpq.EncryptMpqFileBytes(stored, fileKey+i)
		}

		sectorData[i] = stored
	}

	// Build the sector offset table. Offsets are relative to the start of the file
	// block (offset 0 = offset table itself).
	offsets := make([]uint32, sectorCount+1)

	offsets[0] = (sectorCount + 1) * 4
	for i := uint32(0); i < sectorCount; i++ {
		offsets[i+1] = offsets[i] + uint32(len(sectorData[i]))
	}

	tableRaw := make([]byte, (sectorCount+1)*4)
	for i, off := range offsets {
		binary.LittleEndian.PutUint32(tableRaw[i*4:i*4+4], off)
	}

	if encrypted {
		// Storm encrypts the sector-offset table with key-1.
		mpq.EncryptMpqFileBytes(tableRaw, fileKey-1)
	}

	// Concatenate stored payload (offset table + sectors).
	storedPayload := make([]byte, 0, offsets[sectorCount])

	storedPayload = append(storedPayload, tableRaw...)
	for _, s := range sectorData {
		storedPayload = append(storedPayload, s...)
	}

	compressedSize := uint32(len(storedPayload))

	hashes[slot] = mpq.HashEntry{
		HashA:      mpq.NameHashA(p.name),
		HashB:      mpq.NameHashB(p.name),
		Locale:     0,
		Platform:   0,
		Flags:      0,
		BlockIndex: blockIndex,
	}

	blocks := make([]mpq.BlockEntry, len(a.BlockTable), len(a.BlockTable)+1)
	copy(blocks, a.BlockTable)
	blocks = append(blocks, mpq.BlockEntry{
		FilePos:          filePos,
		CompressedSize:   compressedSize,
		UncompressedSize: p.size,
		Flags:            blockFlags,
	})

	nextHeader := a.Header
	nextHeader.BlockTableSize = uint32(len(blocks))
	nextHeader.BlockTablePos = filePos + compressedSize

	nextHeader.ArchiveSize32 = nextHeader.BlockTablePos + uint32(
		len(blocks),
	)*uint32(
		mpqBlockEntrySize,
	)
	if nextHeader.FormatVersion >= 2 {
		nextHeader.ArchiveSize64 = uint64(nextHeader.ArchiveSize32)
	}

	if nextHeader.FormatVersion >= 3 {
		nextHeader.HashTableSize64 = uint64(nextHeader.HashTableSize) * uint64(mpqHashEntrySize)
		nextHeader.BlockTableSize64 = uint64(nextHeader.BlockTableSize) * uint64(mpqBlockEntrySize)
	}

	if err := a.persistHeaderAndTables(nextHeader, hashes, blocks); err != nil {
		return err
	}

	if err := a.writePayload(filePos, storedPayload); err != nil {
		return fmt.Errorf("write file payload: %w", err)
	}

	a.Header = nextHeader
	a.HashTable = hashes
	a.BlockTable = blocks
	a.FileIndex = mpq.BuildFileIndex(hashes, blocks)
	a.recordBlockName(blockIndex, p.name)
	a.recordBlockAttributes(blockIndex, p.buf)

	return nil
}

func (a *Archive) recordBlockName(blockIndex uint32, name string) {
	if a.blockNames == nil {
		a.blockNames = make(map[uint32]string)
	}

	a.blockNames[blockIndex] = name
}

// RemoveFile marks a hash entry as deleted and clears its block table row.
func (a *Archive) RemoveFile(name string, locale uint16, platform uint8) error {
	if name == "" {
		return ErrInvalidFileName
	}

	if isInternalMpqFileName(name) {
		return ErrInternalFileName
	}

	hashA := mpq.NameHashA(name)
	hashB := mpq.NameHashB(name)

	entry, ok := mpq.FindIndexedFileEntry(a.FileIndex, hashA, hashB, locale, platform)
	if !ok {
		return ErrFileHashNotFound
	}

	hashes := make([]mpq.HashEntry, len(a.HashTable))
	copy(hashes, a.HashTable)
	blocks := make([]mpq.BlockEntry, len(a.BlockTable))
	copy(blocks, a.BlockTable)

	markHashEntryDeleted(&hashes[entry.HashIndex])
	blocks[entry.BlockIndex].Flags &^= mpqFileExists

	if err := a.persistHeaderAndTables(a.Header, hashes, blocks); err != nil {
		return err
	}

	a.HashTable = hashes
	a.BlockTable = blocks
	a.FileIndex = mpq.BuildFileIndex(hashes, blocks)

	return nil
}

// RenameFile updates hash A/B for the selected locale/platform variant.
func (a *Archive) RenameFile(oldName, newName string, locale uint16, platform uint8) error {
	if oldName == "" || newName == "" {
		return ErrInvalidFileName
	}

	if isInternalMpqFileName(oldName) || isInternalMpqFileName(newName) {
		return ErrInternalFileName
	}

	oldHashA := mpq.NameHashA(oldName)
	oldHashB := mpq.NameHashB(oldName)

	entry, ok := mpq.FindIndexedFileEntry(a.FileIndex, oldHashA, oldHashB, locale, platform)
	if !ok {
		return ErrFileHashNotFound
	}

	newHashA := mpq.NameHashA(newName)
	newHashB := mpq.NameHashB(newName)

	for _, h := range a.HashTable {
		if h.BlockIndex == hashEntryEmpty || h.BlockIndex == hashEntryDeleted {
			continue
		}

		if h.HashA == newHashA && h.HashB == newHashB && h.Locale == locale &&
			h.Platform == platform {
			return ErrRenameCollision
		}
	}

	hashes := make([]mpq.HashEntry, len(a.HashTable))
	copy(hashes, a.HashTable)
	oldHash := hashes[entry.HashIndex]
	markHashEntryDeleted(&hashes[entry.HashIndex])

	newSlot, err := findInsertSlot(hashes, newName)
	if err != nil {
		return err
	}

	hashes[newSlot] = mpq.HashEntry{
		HashA:      newHashA,
		HashB:      newHashB,
		Locale:     oldHash.Locale,
		Platform:   oldHash.Platform,
		Flags:      oldHash.Flags,
		BlockIndex: oldHash.BlockIndex,
	}

	if err := a.recryptRenamedFileData(entry, oldName, newName); err != nil {
		return err
	}

	if err := a.persistHeaderAndTables(a.Header, hashes, a.BlockTable); err != nil {
		return err
	}

	a.HashTable = hashes
	a.FileIndex = mpq.BuildFileIndex(hashes, a.BlockTable)

	return nil
}

func (a *Archive) recryptRenamedFileData(
	entry mpq.IndexedFileEntry,
	oldName, newName string,
) error {
	flags := entry.Block.Flags
	if flags&mpq.FileFlagEncrypted == 0 {
		return nil
	}

	payload, err := a.readPayload(entry.Block.FilePos, entry.Block.CompressedSize)
	if err != nil {
		return fmt.Errorf("read encrypted payload for rename: %w", err)
	}

	oldKey := mpq.DecryptFileKey(
		oldName,
		uint64(entry.Block.FilePos),
		entry.Block.UncompressedSize,
		flags,
	)

	newKey := mpq.DecryptFileKey(
		newName,
		uint64(entry.Block.FilePos),
		entry.Block.UncompressedSize,
		flags,
	)
	if oldKey == newKey {
		return nil
	}

	mpq.DecryptMpqFileBytes(payload, oldKey)
	mpq.EncryptMpqFileBytes(payload, newKey)

	if err := a.writePayload(entry.Block.FilePos, payload); err != nil {
		return fmt.Errorf("write recrypted payload: %w", err)
	}

	return nil
}

func (a *Archive) readPayload(filePos, payloadSize uint32) ([]byte, error) {
	f, err := os.Open(a.Path)
	if err != nil {
		return nil, fmt.Errorf("open archive for payload read: %w", err)
	}
	defer f.Close()

	off := int64(fileDataOffset(a.Header, filePos))

	buf := make([]byte, payloadSize)
	if _, err := f.ReadAt(buf, off); err != nil {
		return nil, err
	}

	return buf, nil
}

func (a *Archive) persistHeaderAndTables(
	header mpq.Header,
	hashes []mpq.HashEntry,
	blocks []mpq.BlockEntry,
) error {
	hashRaw := marshalHashTable(hashes)
	mpq.EncryptMpqTableDiskBytes(hashRaw, mpq.HashTableEncryptKey())

	blockRaw := marshalBlockTable(blocks)
	mpq.EncryptMpqTableDiskBytes(blockRaw, mpq.BlockTableEncryptKey())

	// Strip the HiBlock extension on every mutation — we never produce file
	// positions exceeding 4 GiB. StormLib treats a zero HiBlock pointer as
	// "no hi-block table".
	header.HiBlockTablePos = 0
	header.HiBlockSize64 = 0
	header.MD5HiBlockTable = [16]byte{}

	// HET/BET tables are rebuilt for v3+ archives so callers that key off the
	// HET pointer (StormLib's GetFileIndex_Het) keep seeing live data rather
	// than stale bytes from the prior table region. v1/v2 archives use only
	// the classic hash/block tables.
	var hetRaw, betRaw []byte

	if header.FormatVersion >= 2 {
		inputs := make([]mpq.HetBetInput, len(blocks))
		for i, b := range blocks {
			inputs[i].Block = b
			if name, ok := a.blockNames[uint32(i)]; ok {
				inputs[i].HasName = true
				inputs[i].FileNameHash = mpq.JenkinsHash(name)
			}
		}

		var hetMD5, betMD5 [16]byte

		hetRaw, betRaw, hetMD5, betMD5 = mpq.MarshalHetBet(inputs)

		// HET sits immediately after the block table; BET immediately after HET.
		hetPos := uint64(header.BlockTablePos) + uint64(len(blockRaw))
		betPos := hetPos + uint64(len(hetRaw))

		header.HetTablePos64 = hetPos
		header.HetTableSize64 = uint64(len(hetRaw))
		header.BetTablePos64 = betPos
		header.BetTableSize64 = uint64(len(betRaw))
		header.MD5HetTable = hetMD5
		header.MD5BetTable = betMD5

		newSize := betPos + uint64(len(betRaw))
		header.ArchiveSize32 = uint32(newSize)
		header.ArchiveSize64 = newSize
	}

	// For v4, the header carries MD5 digests of each on-disk (encrypted)
	// table. Compute them from the bytes we are about to write so the header
	// integrity check (VerifyHashTableMD5/VerifyBlockTableMD5) succeeds after
	// mutation.
	if header.FormatVersion >= 3 {
		header.MD5HashTable = md5.Sum(hashRaw)
		header.MD5BlockTable = md5.Sum(blockRaw)
	}

	headerRaw, err := mpq.MarshalHeader(header)
	if err != nil {
		return fmt.Errorf("marshal updated header: %w", err)
	}

	f, err := os.OpenFile(a.Path, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open archive for write: %w", err)
	}
	defer f.Close()

	if _, err := f.WriteAt(headerRaw, header.Offset); err != nil {
		return fmt.Errorf("write header: %w", err)
	}

	if _, err := f.WriteAt(
		hashRaw,
		int64(uint64(header.Offset)+uint64(header.HashTablePos)),
	); err != nil {
		return fmt.Errorf("write hash table: %w", err)
	}

	if _, err := f.WriteAt(
		blockRaw,
		int64(uint64(header.Offset)+uint64(header.BlockTablePos)),
	); err != nil {
		return fmt.Errorf("write block table: %w", err)
	}

	if hetRaw != nil {
		if _, err := f.WriteAt(
			hetRaw,
			int64(uint64(header.Offset)+header.HetTablePos64),
		); err != nil {
			return fmt.Errorf("write het table: %w", err)
		}
	}

	if betRaw != nil {
		if _, err := f.WriteAt(
			betRaw,
			int64(uint64(header.Offset)+header.BetTablePos64),
		); err != nil {
			return fmt.Errorf("write bet table: %w", err)
		}
	}

	return nil
}

func (a *Archive) writePayload(filePos uint32, payload []byte) error {
	f, err := os.OpenFile(a.Path, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open archive for write: %w", err)
	}
	defer f.Close()

	if _, err := f.WriteAt(payload, int64(uint64(a.Header.Offset)+uint64(filePos))); err != nil {
		return err
	}

	return nil
}

const (
	mpqHashEntrySize  = 16
	mpqBlockEntrySize = 16
)

func findInsertSlot(table []mpq.HashEntry, name string) (int, error) {
	mask := uint32(len(table) - 1)
	if len(table) == 0 || uint32(len(table))&(uint32(len(table))-1) != 0 {
		return 0, fmt.Errorf("%w: hash table size is not power of two", ErrArchiveWriteUnsupported)
	}

	start := mpq.NameHashIndex(name) & mask
	for i := uint32(0); i < uint32(len(table)); i++ {
		idx := int((start + i) & mask)
		if table[idx].BlockIndex == hashEntryEmpty || table[idx].BlockIndex == hashEntryDeleted {
			return idx, nil
		}
	}

	return 0, fmt.Errorf("hash table full")
}

// markExistingForReplace deletes any non-deleted hash entry that matches
// (hashA, hashB, locale, platform) for the supplied name, returning the
// updated table. This implements MPQ_FILE_REPLACEEXISTING semantics: writing
// the same logical name twice with the same locale/platform replaces the
// previous entry rather than producing a duplicate live row.
func markExistingForReplace(table []mpq.HashEntry, name string, locale uint16, platform uint8) {
	if len(table) == 0 {
		return
	}

	mask := uint32(len(table) - 1)
	if uint32(len(table))&(uint32(len(table))-1) != 0 {
		return
	}

	hashA := mpq.NameHashA(name)
	hashB := mpq.NameHashB(name)
	start := mpq.NameHashIndex(name) & mask

	for i := uint32(0); i < uint32(len(table)); i++ {
		idx := int((start + i) & mask)

		entry := table[idx]
		if entry.BlockIndex == hashEntryEmpty {
			return
		}

		if entry.BlockIndex == hashEntryDeleted {
			continue
		}

		if entry.HashA == hashA && entry.HashB == hashB && entry.Locale == locale &&
			entry.Platform == platform {
			markHashEntryDeleted(&table[idx])
			return
		}
	}
}

func marshalHashTable(entries []mpq.HashEntry) []byte {
	out := make([]byte, len(entries)*mpqHashEntrySize)
	for i, e := range entries {
		base := i * mpqHashEntrySize
		binary.LittleEndian.PutUint32(out[base:base+4], e.HashA)
		binary.LittleEndian.PutUint32(out[base+4:base+8], e.HashB)
		binary.LittleEndian.PutUint16(out[base+8:base+10], e.Locale)
		out[base+10] = e.Platform
		out[base+11] = e.Flags
		binary.LittleEndian.PutUint32(out[base+12:base+16], e.BlockIndex)
	}

	return out
}

func marshalBlockTable(entries []mpq.BlockEntry) []byte {
	out := make([]byte, len(entries)*mpqBlockEntrySize)
	for i, e := range entries {
		base := i * mpqBlockEntrySize
		binary.LittleEndian.PutUint32(out[base:base+4], e.FilePos)
		binary.LittleEndian.PutUint32(out[base+4:base+8], e.CompressedSize)
		binary.LittleEndian.PutUint32(out[base+8:base+12], e.UncompressedSize)
		binary.LittleEndian.PutUint32(out[base+12:base+16], e.Flags)
	}

	return out
}

func markHashEntryDeleted(h *mpq.HashEntry) {
	h.HashA = 0xFFFFFFFF
	h.HashB = 0xFFFFFFFF
	h.Locale = 0xFFFF
	h.Platform = 0xFF
	h.Flags = 0xFF
	h.BlockIndex = hashEntryDeleted
}

func isInternalMpqFileName(name string) bool {
	return strings.EqualFold(name, "(listfile)") ||
		strings.EqualFold(name, "(attributes)") ||
		strings.EqualFold(name, "(signature)")
}

func isPseudoFileName(name string) bool {
	if len(name) < 13 || !strings.EqualFold(name[:4], "File") {
		return false
	}

	for i := 4; i < 12; i++ {
		if name[i] < '0' || name[i] > '9' {
			return false
		}
	}

	return name[12] == '.'
}

// Flush serialises the (listfile) for the current archive state. It is safe to
// call multiple times; existing internal entries are first marked deleted so the
// new payload occupies a fresh slot/block.
func (a *Archive) Flush() error {
	if a.pendingWrite != nil {
		return ErrWriteInProgress
	}

	if len(a.blockNames) == 0 {
		return nil
	}

	// Gather user-visible filenames (skip internal mpq files).
	seen := make(map[string]struct{}, len(a.blockNames))

	names := make([]string, 0, len(a.blockNames))
	for _, n := range a.blockNames {
		if isInternalMpqFileName(n) {
			continue
		}

		if _, dup := seen[n]; dup {
			continue
		}

		seen[n] = struct{}{}
		names = append(names, n)
	}

	sort.Strings(names)

	var buf bytes.Buffer
	for _, n := range names {
		buf.WriteString(n)
		buf.WriteString("\r\n")
	}

	if err := a.writeInternalNamedFile("(listfile)", buf.Bytes(), mpqFileCompressed); err != nil {
		return fmt.Errorf("flush listfile: %w", err)
	}

	return a.writeAttributesFile()
}

// writeInternalNamedFile drives the same persistence pipeline as the public
// CreateFile/WriteFile/FinishFile cycle but accepts internal mpq filenames and
// removes any pre-existing hash slot for the same name first.
func (a *Archive) writeInternalNamedFile(name string, data []byte, flags uint32) error {
	if a.pendingWrite != nil {
		return ErrWriteInProgress
	}

	a.dropExistingHashEntry(name)

	a.pendingWrite = &pendingWrite{
		name:  name,
		size:  uint32(len(data)),
		flags: flags,
		buf:   append([]byte(nil), data...),
	}

	defer func() { a.pendingWrite = nil }()

	return a.persistWrite(a.pendingWrite)
}

func (a *Archive) dropExistingHashEntry(name string) {
	hashA := mpq.NameHashA(name)
	hashB := mpq.NameHashB(name)

	for i := range a.HashTable {
		h := &a.HashTable[i]
		if h.HashA == hashA && h.HashB == hashB &&
			h.BlockIndex != hashEntryEmpty && h.BlockIndex != hashEntryDeleted {
			markHashEntryDeleted(h)
		}
	}
}

// writeAttributesFile serialises a v100 (attributes) payload with CRC32, FILETIME
// and MD5 entries for every block (including the (attributes) block we are about
// to add). Blocks whose data we did not write get zero-filled entries.
func (a *Archive) writeAttributesFile() error {
	flags := uint32(0x01 | 0x02 | 0x04) // CRC32 | FILETIME | MD5
	if a.attributesFlagsSet {
		flags = a.attributesFlags
	}

	if flags == 0 {
		// SetAttributes(0) — caller asked us not to emit (attributes).
		return nil
	}

	a.dropExistingHashEntry("(attributes)")

	count := uint32(len(a.BlockTable)) + 1

	buf := binary.LittleEndian.AppendUint32(nil, 100)
	buf = binary.LittleEndian.AppendUint32(buf, flags)

	if flags&0x01 != 0 {
		for i := uint32(0); i < count; i++ {
			buf = binary.LittleEndian.AppendUint32(buf, a.blockCRC32[i])
		}
	}

	if flags&0x02 != 0 {
		for i := uint32(0); i < count; i++ {
			buf = binary.LittleEndian.AppendUint64(buf, a.blockFiletime[i])
		}
	}

	if flags&0x04 != 0 {
		var zero [16]byte

		for i := uint32(0); i < count; i++ {
			if v, ok := a.blockMD5[i]; ok {
				buf = append(buf, v[:]...)
			} else {
				buf = append(buf, zero[:]...)
			}
		}
	}

	return a.writeInternalNamedFile("(attributes)", buf, mpqFileCompressed)
}

// SetAttributesFlags overrides the bitmask used by Flush when emitting an
// (attributes) file. Returns the previous value. Pass 0 to suppress
// (attributes) emission entirely. Bits: 0x01=CRC32, 0x02=FILETIME, 0x04=MD5.
func (a *Archive) SetAttributesFlags(flags uint32) uint32 {
	prev := uint32(0x01 | 0x02 | 0x04)
	if a.attributesFlagsSet {
		prev = a.attributesFlags
	}

	a.attributesFlags = flags
	a.attributesFlagsSet = true

	return prev
}

// GetAttributesFlags returns the configured (attributes) flags, defaulting to
// CRC32|FILETIME|MD5 when SetAttributesFlags has not been called.
func (a *Archive) GetAttributesFlags() uint32 {
	if a.attributesFlagsSet {
		return a.attributesFlags
	}

	return 0x01 | 0x02 | 0x04
}

// recordBlockAttributes caches StormLib (attributes) data for a freshly-written
// block. Called from persistSingleUnitWrite / persistSectoredWrite with the
// plaintext payload bytes.
func (a *Archive) recordBlockAttributes(blockIndex uint32, plaintext []byte) {
	if a.blockCRC32 == nil {
		a.blockCRC32 = make(map[uint32]uint32)
	}

	if a.blockMD5 == nil {
		a.blockMD5 = make(map[uint32][16]byte)
	}

	if a.blockFiletime == nil {
		a.blockFiletime = make(map[uint32]uint64)
	}

	a.blockCRC32[blockIndex] = crc32.ChecksumIEEE(plaintext)
	a.blockMD5[blockIndex] = md5.Sum(plaintext)
	a.blockFiletime[blockIndex] = unixToFiletime(time.Now())
}

func unixToFiletime(t time.Time) uint64 {
	const epochDelta = 116444736000000000
	return uint64(t.UnixNano()/100) + epochDelta
}
