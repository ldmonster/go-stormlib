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

package naming

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func hexEqual(t *testing.T, label, got, want string) {
	t.Helper()
	if got != want {
		t.Fatalf("%s: got %q hex=%s want %q hex=%s", label, got, hex.EncodeToString([]byte(got)), want, hex.EncodeToString([]byte(want)))
	}
}

func TestUTF8ToFileNameStormGolden(t *testing.T) {
	// Vectors from tools/utf8name_golden/main.c + StormLib SMemUTF8ToFileName (narrow).
	cases := []struct {
		name    string
		in      string
		flags   uint32
		want    string
		wantErr bool
	}{
		{"ascii", "hello.mpq", 0, "hello.mpq", false},
		{"czech", "\u010cesk\u00fd.mpq", 0, "\u010cesk\u00fd.mpq", false},
		{"invalid_byte_no_replace", "\xff", 0, "%ff", true},
		{"invalid_byte_replace", "\xff", UTF8ReplaceInvalid, "\uFFFD", false},
		{"quote_escape", "x\"y", 0, "x%22y", false},
		{"quote_keep", "x\"y", UTF8KeepInvalidFCH, "x\"y", false},
		{"slashes_escape", "units/Orc/HealingWard/Rune2.blp", 0, "units%2fOrc%2fHealingWard%2fRune2.blp", false},
		{"slashes_keep", "units/Orc/HealingWard/Rune2.blp", UTF8KeepInvalidFCH, "units/Orc/HealingWard/Rune2.blp", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := UTF8ToFileName(tc.in, tc.flags)
			if tc.wantErr {
				if err == nil || !errors.Is(err, ErrNoUnicodeTranslation) {
					t.Fatalf("want ErrNoUnicodeTranslation, got %v", err)
				}
			} else if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			hexEqual(t, "utf8ToFileName", got, tc.want)
		})
	}
}

func TestFileNameToUTF8RoundTripGolden(t *testing.T) {
	pairs := []struct {
		utf8       string
		flags      uint32
		wantSafe   string
		wantErrEnc bool
	}{
		{"hello.mpq", 0, "hello.mpq", false},
		{"\u010cesk\u00fd.mpq", 0, "\u010cesk\u00fd.mpq", false},
		{"x\"y", 0, "x%22y", false},
		{"units/Orc/HealingWard/Rune2.blp", 0, "units%2fOrc%2fHealingWard%2fRune2.blp", false},
	}
	for _, p := range pairs {
		safe, err := UTF8ToFileName(p.utf8, p.flags)
		if p.wantErrEnc {
			if err == nil {
				t.Fatalf("want encode error")
			}
			continue
		}
		if err != nil {
			t.Fatalf("UTF8ToFileName: %v", err)
		}
		if safe != p.wantSafe {
			t.Fatalf("safe got %q want %q", safe, p.wantSafe)
		}
		back, err := FileNameToUTF8(safe)
		if err != nil {
			t.Fatalf("FileNameToUTF8: %v", err)
		}
		if back != p.utf8 {
			t.Fatalf("roundtrip got %q want %q", back, p.utf8)
		}
	}
}

func TestInvalidUTF8PercentEncoding(t *testing.T) {
	out, err := UTF8ToFileName("\xff", 0)
	if err == nil || !errors.Is(err, ErrNoUnicodeTranslation) {
		t.Fatalf("err: %v", err)
	}
	if out != "%ff" {
		t.Fatalf("got %q", out)
	}
	back, err := FileNameToUTF8(out)
	if err != nil {
		t.Fatal(err)
	}
	if back != "\xff" {
		t.Fatalf("FileNameToUTF8 roundtrip: got %q hex=%s", back, hex.EncodeToString([]byte(back)))
	}
}

func TestManyInvalidCharsFlushesPercentUBracket(t *testing.T) {
	// Stack hits maxInvalidChars → flush produces %u[ hex ] (Storm multi-byte escape).
	var b strings.Builder
	for i := 0; i < 130; i++ {
		b.WriteByte('\xff')
	}
	out, err := UTF8ToFileName(b.String(), 0)
	if err == nil || !errors.Is(err, ErrNoUnicodeTranslation) {
		t.Fatalf("want ErrNoUnicodeTranslation, got %v", err)
	}
	if strings.Count(out, "%u[") < 1 || !strings.Contains(out, "]") {
		t.Fatalf("expected %%u[...] escape segment, got len=%d tail=%q", len(out), out[max(0, len(out)-48):])
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
