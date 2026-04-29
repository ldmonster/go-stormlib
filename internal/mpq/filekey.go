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
	"strings"
)

// MPQ file flags (StormLib.h) used by DecryptFileKey / open-by-name decryption
// and by read/write/verify code paths.
const (
	FileFlagImplode      = 0x00000100 // MPQ_FILE_IMPLODE
	FileFlagCompress     = 0x00000200 // MPQ_FILE_COMPRESS
	FileFlagEncrypted    = 0x00010000 // MPQ_FILE_ENCRYPTED
	FileFlagKeyV2        = 0x00020000 // MPQ_FILE_KEY_V2 (a.k.a. FIX_KEY)
	FileFlagPatchFile    = 0x00100000 // MPQ_FILE_PATCH_FILE
	FileFlagSingleUnit   = 0x01000000 // MPQ_FILE_SINGLE_UNIT
	FileFlagDeleteMarker = 0x02000000 // MPQ_FILE_DELETE_MARKER
	FileFlagSectorCRC    = 0x04000000 // MPQ_FILE_SECTOR_CRC
	FileFlagExists       = 0x80000000 // MPQ_FILE_EXISTS
)

// DecryptFileKey matches StormLib DecryptFileKey (SBaseCommon.cpp): key from plain file name,
// optional MPQ_FILE_KEY_V2 adjustment using byte offset and unpacked size.
func DecryptFileKey(nameInMpq string, byteOffset uint64, unpackedSize, flags uint32) uint32 {
	plain := plainFileNameForKey(nameInMpq)

	initCryptTable()

	key := hashString(plain, mpqHashFileKey)
	if flags&FileFlagKeyV2 != 0 {
		key = (key + uint32(byteOffset)) ^ unpackedSize
	}

	return key
}

// plainFileNameForKey matches Storm GetPlainFileName (StormCommon.h): last path segment using
// '/' or '\\' as separators — independent of OS filepath rules (Windows MPQ names on Unix).
func plainFileNameForKey(path string) string {
	path = strings.TrimSpace(path)

	plain := path
	for i := 0; i < len(path); i++ {
		if path[i] == '/' || path[i] == '\\' {
			plain = path[i+1:]
		}
	}

	return plain
}

// DecryptMpqFileBytes decrypts MPQ file data in place (DecryptMpqBlock on little-endian layout).
func DecryptMpqFileBytes(data []byte, key uint32) {
	mpqDecryptBlockStorm(data, key)
}

// EncryptMpqFileBytes encrypts MPQ file data in place (EncryptMpqBlock); used for building test fixtures.
func EncryptMpqFileBytes(data []byte, key uint32) {
	mpqEncryptBlockStorm(data, key)
}
