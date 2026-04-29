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
	"testing"
)

func TestDecryptFileKey_IgnoresDirectory(t *testing.T) {
	k1 := DecryptFileKey(`maps\foo\bar.txt`, 0x400, 99, 0)
	k2 := DecryptFileKey("bar.txt", 0x400, 99, 0)
	if k1 != k2 {
		t.Fatalf("DecryptFileKey directory mismatch: %08x vs %08x", k1, k2)
	}
}

func TestDecryptFileKey_KeyV2DependsOnOffsetAndSize(t *testing.T) {
	flags := uint32(FileFlagEncrypted | FileFlagKeyV2)
	a := DecryptFileKey("x.bin", 100, 50, flags)
	b := DecryptFileKey("x.bin", 200, 50, flags)
	if a == b {
		t.Fatal("expected different keys for different byte offsets under KEY_V2")
	}
	c := DecryptFileKey("x.bin", 100, 51, flags)
	if a == c {
		t.Fatal("expected different keys for different unpacked sizes under KEY_V2")
	}
}
