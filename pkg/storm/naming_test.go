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

package storm_test

import (
	"errors"
	"testing"

	"github.com/ldmonster/go-stormlib/pkg/storm"
)

func TestUTF8ToFileNameSlashEscape(t *testing.T) {
	out, err := storm.UTF8ToFileName("a/b", 0)
	if err != nil {
		t.Fatal(err)
	}
	if out != "a%2fb" {
		t.Fatalf("got %q", out)
	}
	back, err := storm.FileNameToUTF8(out)
	if err != nil {
		t.Fatal(err)
	}
	if back != "a/b" {
		t.Fatalf("roundtrip got %q", back)
	}
}

func TestErrNoUnicodeTranslationSingleInvalidByte(t *testing.T) {
	_, err := storm.UTF8ToFileName("\xff", 0)
	if !errors.Is(err, storm.ErrNoUnicodeTranslation) {
		t.Fatalf("got %v", err)
	}
}
