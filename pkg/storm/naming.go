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
	"github.com/ldmonster/go-stormlib/internal/naming"
)

// UTF-8 / file-name conversion flags (SFILE_UTF8_*).
const (
	UTF8ReplaceInvalidName = naming.UTF8ReplaceInvalid
	UTF8KeepInvalidFCH     = naming.UTF8KeepInvalidFCH
)

// ErrNoUnicodeTranslation is returned when conversion matches StormLib ERROR_NO_UNICODE_TRANSLATION (1007).
var ErrNoUnicodeTranslation = naming.ErrNoUnicodeTranslation

// UTF8ToFileName converts a UTF-8 MPQ path segment to a cross-platform file-name-safe form (SMemUTF8ToFileName, narrow).
func UTF8ToFileName(s string, flags uint32) (string, error) {
	return naming.UTF8ToFileName(s, flags)
}

// FileNameToUTF8 reverses UTF8ToFileName escapes into UTF-8 (SMemFileNameToUTF8, narrow).
func FileNameToUTF8(s string) (string, error) {
	return naming.FileNameToUTF8(s)
}
