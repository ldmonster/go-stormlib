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

package parity

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/ldmonster/go-stormlib/internal/mpq"
	"github.com/ldmonster/go-stormlib/pkg/storm"
)

// StormLib ignores block entries without MPQ_FILE_EXISTS for find/open-by-name; Go still reads them from tables.
// Parity fixtures set EXISTS so stormlib-parity-c enumerates the same logical files as Go.
const (
	mpqFileExistsStorm  = uint32(0x80000000)
	blockFlagsStormData = mpqFileExistsStorm | uint32(0x01000000) // EXISTS | SINGLE_UNIT
	blockFlagsStormZlib = mpqFileExistsStorm | uint32(0x01000200) // EXISTS | fixture zlib+single-unit
)

func TestUnknownVersionFallbackParity(t *testing.T) {
	runParityCase(t, "coercible-unknown", makeArchive(t, func(b []byte) {
		writeHeader(b, 0x200, 32, 9, 3, 0x200, 0x300, 1, 1)
	}), true)
	runParityCase(t, "noncoercible-unknown", makeArchive(t, func(b []byte) {
		writeHeader(b, 0x200, 32, 9, 3, 0xFFFFF000, 0xFFFFF100, 2, 2)
	}), false)
	runParityCase(t, "mixed-candidate-scan", makeArchive(t, func(b []byte) {
		writeHeader(b, 0x200, 32, 9, 3, 0xFFFFF000, 0xFFFFF100, 2, 2)
		writeHeader(b, 0x800, 32, 1, 3, 0x200, 0x300, 1, 1)
	}), true, false) // Storm C locks first converted header then fails loads; Go scans to 0x800 (see compatibility.md).
}

func TestUserDataOverlayLargeParity(t *testing.T) {
	runParityCase(t, "userdata-overlay-large", makeArchive(t, func(b []byte) {
		writeUserData(b, 0x200, 0x400)
		writeHeader(b, 0x600, 32, 1, 3, 0x01000000, 0x01000200, 1, 1)
	}), true)
}

func TestAviRejectParity(t *testing.T) {
	path := makeArchive(t, func(b []byte) {
		copy(b[0:4], []byte("RIFF"))
		copy(b[8:12], []byte("AVI "))
		copy(b[12:16], []byte("LIST"))
	})
	if _, err := storm.Open(path, storm.OpenOptions{}); err == nil {
		t.Fatal("expected go avi reject")
	}
}

func TestForceMPQV1Parity(t *testing.T) {
	path := makeArchive(t, func(b []byte) {
		writeUserData(b, 0x200, 0x400)
		writeHeader(b, 0x600, 32, 9, 3, 0x200, 0x300, 1, 1)
	})
	if _, err := storm.Open(path, storm.OpenOptions{ForceMPQV1: true}); err != nil {
		t.Fatalf("force-v1 go open failed: %v", err)
	}
	parityCmd := os.Getenv("STORMLIB_PARITY_CMD")
	if parityCmd == "" {
		t.Skip("set STORMLIB_PARITY_CMD to enable C parity execution")
	}
	cmd := exec.Command(parityCmd, "--force-v1", path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("force-v1 parity command failed: %v (%s)", err, string(out))
	}
	if strings.TrimSpace(string(out)) != "open-ok" {
		t.Fatalf("force-v1 parity mismatch got %q want %q", strings.TrimSpace(string(out)), "open-ok")
	}
}

func TestForeignHeaderPrecedenceParity(t *testing.T) {
	runParityCase(t, "foreign-then-mpq", makeArchive(t, func(b []byte) {
		writeMpkHeader(b, 0x0)
		writeHeader(b, 0x400, 32, 0, 3, 0x200, 0x300, 1, 1)
	}), true, false) // Storm C honors MPK at scan start; Go skips unsupported foreign and finds MPQ (see compatibility.md).
	runParityCase(t, "mpk-only-unsupported", makeArchive(t, func(b []byte) {
		writeMpkHeader(b, 0x0)
	}), false)
}

func TestErrorPrecedenceParityMatrix(t *testing.T) {
	runParityCase(t, "unsupported-over-foreign", makeArchive(t, func(b []byte) {
		writeHeader(b, 0x200, 32, 9, 3, 0xFFFFF000, 0xFFFFF100, 2, 2)
		writeMpkHeader(b, 0x800)
	}), false)

	runParityCase(t, "foreign-over-not-found", makeArchive(t, func(b []byte) {
		writeMpkHeader(b, 0x0)
	}), false)
	runParityCase(t, "not-found", makeArchive(t, func(b []byte) {
		// no candidate headers
	}), false)
	runParityCase(t, "avi-precedence", makeArchive(t, func(b []byte) {
		copy(b[0:4], []byte("RIFF"))
		copy(b[8:12], []byte("AVI "))
		copy(b[12:16], []byte("LIST"))
	}), false)
}

func TestMarkerUserDataFallbackParity(t *testing.T) {
	customMarker := uint32(0x12345678)
	path := makeArchive(t, func(b []byte) {
		writeUserData(b, 0x200, 0x400)
		// Invalid custom-marker header at userdata target.
		put32(b, 0x400+0, customMarker)
		put32(b, 0x400+4, 16)
		put16(b, 0x400+12, 0)
		put16(b, 0x400+14, 3)
		// Valid custom-marker header later should win.
		writeHeaderWithMarker(b, 0x800, customMarker, 32, 0, 3, 0x200, 0x300, 1, 1)
	})
	if _, err := storm.Open(path, storm.OpenOptions{MarkerSignature: customMarker}); err != nil {
		t.Fatalf("marker userdata fallback go open failed: %v", err)
	}

	parityCmd := os.Getenv("STORMLIB_PARITY_CMD")
	if parityCmd == "" {
		t.Skip("set STORMLIB_PARITY_CMD to enable C parity execution")
	}
	cmd := exec.Command(parityCmd, "--marker", "0x12345678", path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("marker userdata parity command failed: %v (%s)", err, string(out))
	}
	if strings.TrimSpace(string(out)) != "open-ok" {
		t.Fatalf("marker userdata parity mismatch got %q want %q", strings.TrimSpace(string(out)), "open-ok")
	}
}

func TestMarkerUserDataMixedCandidatesParity(t *testing.T) {
	customMarker := uint32(0x12345678)
	path := makeArchive(t, func(b []byte) {
		writeUserData(b, 0x200, 0x400)
		// userdata points to malformed custom marker candidate
		put32(b, 0x400+0, customMarker)
		put32(b, 0x400+4, 16)
		put16(b, 0x400+12, 0)
		put16(b, 0x400+14, 3)
		// valid default marker candidate and later valid custom marker candidate
		writeHeader(b, 0x800, 32, 0, 3, 0x200, 0x300, 1, 1)
		writeHeaderWithMarker(b, 0xA00, customMarker, 32, 0, 3, 0x200, 0x300, 1, 1)
	})
	if _, err := storm.Open(path, storm.OpenOptions{MarkerSignature: customMarker}); err != nil {
		t.Fatalf("marker userdata mixed-candidate go open failed: %v", err)
	}
	parityCmd := os.Getenv("STORMLIB_PARITY_CMD")
	if parityCmd == "" {
		t.Skip("set STORMLIB_PARITY_CMD to enable C parity execution")
	}
	cmd := exec.Command(parityCmd, "--marker", "0x12345678", path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("marker userdata mixed-candidate parity command failed: %v (%s)", err, string(out))
	}
	if strings.TrimSpace(string(out)) != "open-ok" {
		t.Fatalf("marker userdata mixed-candidate parity mismatch got %q want %q", strings.TrimSpace(string(out)), "open-ok")
	}
}

func TestSQPParityMatrix(t *testing.T) {
	runParityCase(t, "sqp-positive-default-marker", makeArchive(t, func(b []byte) {
		writeHeader(b, 0x0, 32, 0, 0, 0, 0, 0, 0)
		put16(b, 0x1C, 1)
		put16(b, 0x1E, 3)
		put32(b, 0x08, uint32(len(b)))
	}), false)
	runParityCase(t, "sqp-negative-malformed-lookalike", makeArchive(t, func(b []byte) {
		writeHeader(b, 0x0, 16, 9, 0, 0, 0, 0, 0)
	}), false)

	customMarker := uint32(0x12345678)
	path := makeArchive(t, func(b []byte) {
		writeHeaderWithMarker(b, 0x0, customMarker, 32, 0, 0, 0, 0, 0, 0)
		put16(b, 0x1C, 1)
		put16(b, 0x1E, 3)
		put32(b, 0x08, uint32(len(b)))
	})
	if _, err := storm.Open(path, storm.OpenOptions{MarkerSignature: customMarker}); err == nil {
		t.Fatal("expected go sqp-marker reject")
	}
	parityCmd := os.Getenv("STORMLIB_PARITY_CMD")
	if parityCmd == "" {
		t.Skip("set STORMLIB_PARITY_CMD to enable C parity execution")
	}
	cmd := exec.Command(parityCmd, "--marker", "0x12345678", path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sqp marker parity command failed: %v (%s)", err, string(out))
	}
	if strings.TrimSpace(string(out)) != "open-fail" {
		t.Fatalf("sqp marker parity mismatch got %q want %q", strings.TrimSpace(string(out)), "open-fail")
	}
}

func TestCheckMapTypeForceV1Parity(t *testing.T) {
	pathExt := makeArchive(t, func(b []byte) {
		writeHeader(b, 0x200, 32, 9, 3, 0x200, 0x300, 1, 1)
	})
	renamedExt := pathExt + ".w3x"
	if err := os.Rename(pathExt, renamedExt); err != nil {
		t.Fatalf("rename ext fixture: %v", err)
	}
	if _, err := storm.Open(renamedExt, storm.OpenOptions{}); err != nil {
		t.Fatalf("w3x force-v1 go open failed: %v", err)
	}

	pathContent := makeArchive(t, func(b []byte) {
		copy(b[0:4], []byte("HM3W"))
		writeHeader(b, 0x200, 32, 9, 3, 0x200, 0x300, 1, 1)
	})
	if _, err := storm.Open(pathContent, storm.OpenOptions{}); err != nil {
		t.Fatalf("hm3w force-v1 go open failed: %v", err)
	}

	// StarCraft extension wins over conflicting AVI-like content.
	pathScx := makeArchive(t, func(b []byte) {
		copy(b[0:4], []byte("RIFF"))
		copy(b[8:12], []byte("AVI "))
		copy(b[12:16], []byte("LIST"))
		writeHeader(b, 0x200, 32, 0, 3, 0x200, 0x300, 1, 1)
	})
	renamedScx := pathScx + ".scx"
	if err := os.Rename(pathScx, renamedScx); err != nil {
		t.Fatalf("rename scx fixture: %v", err)
	}
	if _, err := storm.Open(renamedScx, storm.OpenOptions{}); err != nil {
		t.Fatalf("scx extension parity go open failed: %v", err)
	}
}

func TestMalformedV1ParityFixtures(t *testing.T) {
	runParityCase(t, "v1-wrapped-negative-block-pos", makeArchive(t, func(b []byte) {
		writeHeader(b, 0x200, 32, 0, 3, 0x200, 0xFFFFFF00, 1, 1)
	}), true)
	runParityCase(t, "v1-oversized-table-clamp", makeArchive(t, func(b []byte) {
		writeHeader(b, 0x200, 32, 0, 3, 0x200, 0x300, 1, 0x0FFFFFFF)
	}), true)
}

func TestOpenListReadBaselineFixtureParity(t *testing.T) {
	path := makeArchive(t, func(b []byte) {
		writeHeader(b, 0x200, 32, 0, 3, 0x200, 0x300, 0, 0)
	})
	runParityCase(t, "open-list-read-baseline", path, true)

	a, err := storm.Open(path, storm.OpenOptions{})
	if err != nil {
		t.Fatalf("go open failed: %v", err)
	}
	files, err := a.ListFiles()
	if err != nil {
		t.Fatalf("go list failed: %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("file count = %d, want 0", len(files))
	}
	if _, err := a.ReadFileByIndex(0); !strings.Contains(fmt.Sprint(err), "out of range") {
		t.Fatalf("expected out-of-range read failure, got: %v", err)
	}
}

func TestNormalizationOpenReadParityFixtures(t *testing.T) {
	path := makeArchive(t, func(b []byte) {
		writeHeader(b, 0x200, 32, 0, 3, 0x400, 0x700, 1, 1)
		payload := []byte("parity-normalized-read")
		copy(b[0x200+0x1100:0x200+0x1100+len(payload)], payload)

		hashPlain := make([]byte, 16)
		put32(hashPlain, 0, 0xABCD1001)
		put32(hashPlain, 4, 0xEF021001)
		put32(hashPlain, 12, 0)
		mpq.EncryptMpqTableDiskBytes(hashPlain, mpq.HashTableEncryptKey())
		copy(b[0x200+0x400:0x200+0x400+len(hashPlain)], hashPlain)

		blockPlain := make([]byte, 16)
		put32(blockPlain, 0, 0x1100)
		put32(blockPlain, 4, 0xFFFFFFFF) // malformed oversize -> normalized clamp
		put32(blockPlain, 8, uint32(len(payload)))
		put32(blockPlain, 12, blockFlagsStormData)
		mpq.EncryptMpqTableDiskBytes(blockPlain, mpq.BlockTableEncryptKey())
		copy(b[0x200+0x700:0x200+0x700+len(blockPlain)], blockPlain)
	})

	runParityCase(t, "normalization-open-read", path, true)
	a, err := storm.Open(path, storm.OpenOptions{})
	if err != nil {
		t.Fatalf("go open failed: %v", err)
	}
	got, err := a.ReadFileByHash(0xABCD1001, 0xEF021001, 0, 0)
	if err != nil {
		t.Fatalf("go read failed: %v", err)
	}
	if string(got) != "parity-normalized-read" {
		t.Fatalf("go read payload mismatch: got %q", string(got))
	}
}

func TestLookupCollisionMatrixParity(t *testing.T) {
	tests := []struct {
		name     string
		wantData string
		locale   uint16
		platform uint8
	}{
		{name: "exact", wantData: "exact", locale: 0x0409, platform: 1},
		{name: "locale-neutral-platform", wantData: "locale-neutral-platform", locale: 0x0409, platform: 9},
		{name: "neutral-locale-platform", wantData: "neutral-locale-platform", locale: 0x0411, platform: 1},
		{name: "fully-neutral", wantData: "fully-neutral", locale: 0x0411, platform: 9},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			path := makeLookupCollisionArchive(t)
			runParityCase(t, "lookup-collision-"+tc.name, path, true)
			a, err := storm.Open(path, storm.OpenOptions{})
			if err != nil {
				t.Fatalf("go open failed: %v", err)
			}
			got, err := a.ReadFileByHash(0x71000001, 0x72000001, tc.locale, tc.platform)
			if err != nil {
				t.Fatalf("go lookup read failed: %v", err)
			}
			if string(got) != tc.wantData {
				t.Fatalf("go lookup mismatch: got %q want %q", string(got), tc.wantData)
			}
			expectedTier := "fully-neutral"
			switch tc.name {
			case "exact":
				expectedTier = "exact"
			case "locale-neutral-platform":
				expectedTier = "locale-neutral-platform"
			case "neutral-locale-platform":
				expectedTier = "neutral-locale-platform"
			}
			assertParityLookupReport(t, path, 0x71000001, 0x72000001, tc.locale, tc.platform, "ok", tc.wantData, expectedTier)
		})
	}
}

func TestLookupTieBreakAndOrderParity(t *testing.T) {
	path := makeLookupTieBreakArchive(t)
	runParityCase(t, "lookup-tiebreak-order", path, true)

	a, err := storm.Open(path, storm.OpenOptions{})
	if err != nil {
		t.Fatalf("go open failed: %v", err)
	}
	got, err := a.ReadFileByHash(0x81000001, 0x82000001, 0x0409, 0)
	if err != nil {
		t.Fatalf("go read failed: %v", err)
	}
	if string(got) != "winner-low-block-index" {
		t.Fatalf("tie-break mismatch: got %q", string(got))
	}
	assertParityLookupReport(t, path, 0x81000001, 0x82000001, 0x0409, 0, "ok", "winner-low-block-index", "exact")
}

func TestNormalizationVariantParityFixtures(t *testing.T) {
	tests := []struct {
		name     string
		build    func([]byte)
		wantOpen bool
		wantRead bool
		expect   string
		hashA    uint32
		hashB    uint32
	}{
		{
			name: "v1-wrapped-offset-clamp-uncompressed",
			build: func(b []byte) {
				writeHeader(b, 0x200, 32, 0, 3, 0x400, 0x700, 1, 1)
				payload := []byte("v1-clamped")
				copy(b[0x200+0x1100:0x200+0x1100+len(payload)], payload)
				writeOneEntryTables(b, 0x400, 0x700, 0x91000001, 0x92000001, 0x1100, 0xFFFFFFFF, uint32(len(payload)), blockFlagsStormData)
			},
			wantOpen: true, wantRead: true, expect: "v1-clamped", hashA: 0x91000001, hashB: 0x92000001,
		},
		{
			name: "v2-absolute-beyond-eof-zeroed",
			build: func(b []byte) {
				writeHeader(b, 0x200, 44, 1, 3, 0x400, 0x700, 1, 1)
				writeOneEntryTables(b, 0x400, 0x700, 0x93000001, 0x94000001, 0x00010000, 0x80, 0x80, blockFlagsStormData)
			},
			wantOpen: true, wantRead: true, expect: strings.Repeat("\x00", 0x80), hashA: 0x93000001, hashB: 0x94000001,
		},
		{
			name: "compressed-clamp-zlib-invalid",
			build: func(b []byte) {
				writeHeader(b, 0x200, 32, 0, 3, 0x400, 0x700, 1, 1)
				blob := []byte{0x02, 0x01, 0x02, 0x03}
				copy(b[0x200+0x1100:0x200+0x1100+len(blob)], blob)
				writeOneEntryTables(b, 0x400, 0x700, 0x95000001, 0x96000001, 0x1100, 0xFFFFFFFF, 32, blockFlagsStormZlib)
			},
			wantOpen: true, wantRead: false, expect: "", hashA: 0x95000001, hashB: 0x96000001,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			path := makeArchive(t, tc.build)
			runParityCase(t, "normalization-"+tc.name, path, tc.wantOpen)
			if !tc.wantOpen {
				return
			}
			a, err := storm.Open(path, storm.OpenOptions{})
			if err != nil {
				t.Fatalf("go open failed: %v", err)
			}
			got, err := a.ReadFileByHash(tc.hashA, tc.hashB, 0, 0)
			goOutcome, goPayload := classifyGoReadOutcome(got, err)
			if tc.wantRead {
				if err != nil {
					t.Fatalf("go read failed: %v", err)
				}
				if string(got) != tc.expect {
					t.Fatalf("go read mismatch: got %q want %q", string(got), tc.expect)
				}
			} else if err == nil {
				t.Fatalf("expected go read failure, got payload %q", string(got))
			}
			assertParityReadReport(t, path, tc.hashA, tc.hashB, 0, 0, goOutcome, goPayload)
		})
	}
}

func TestReadReportParity_NotFound(t *testing.T) {
	path := makeLookupCollisionArchive(t)
	runParityCase(t, "read-report-not-found", path, true)
	a, err := storm.Open(path, storm.OpenOptions{})
	if err != nil {
		t.Fatalf("go open failed: %v", err)
	}
	_, err = a.ReadFileByHash(0xDEAD1001, 0xBEEF1001, 0, 0)
	if err == nil {
		t.Fatal("expected go read not-found error")
	}
	assertParityReadReport(t, path, 0xDEAD1001, 0xBEEF1001, 0, 0, "not-found", "")
}

func TestReadReportParity_Unsupported(t *testing.T) {
	// Non-MPQ fixture to force command-side unsupported outcome category.
	path := makeArchive(t, func(b []byte) {
		copy(b[0:4], []byte("NOPE"))
	})
	assertParityReadReport(t, path, 0x1, 0x2, 0, 0, "unsupported", "")
}

func TestLookupCollisionMatrixParity_NoMatch(t *testing.T) {
	path := makeArchive(t, func(b []byte) {
		writeHeader(b, 0x200, 32, 0, 3, 0x200, 0x300, 0, 0)
	})
	runParityCase(t, "lookup-collision-no-match", path, true)
	a, err := storm.Open(path, storm.OpenOptions{})
	if err != nil {
		t.Fatalf("go open failed: %v", err)
	}
	_, err = a.ReadFileByHash(0x710000FF, 0x720000FF, 0x0409, 1)
	if err == nil {
		t.Fatal("expected go no-match read failure")
	}
	assertParityLookupReport(t, path, 0x710000FF, 0x720000FF, 0x0409, 1, "not-found", "", "")
}

func TestListfileCollisionNamingAndOrderingParity(t *testing.T) {
	path := makeArchive(t, func(b []byte) {
		writeHeader(b, 0x200, 32, 0, 3, 0x400, 0x900, 3, 3)
		named := "maps\\collision.txt"
		listfileName := "(listfile)"
		hashes := []struct {
			hashA, hashB uint32
			locale       uint16
			platform     uint8
			blockIndex   uint32
		}{
			{nameHashAForTest(named), nameHashBForTest(named), 0, 0, 0},
			{0xEE000001, 0xEE000002, 0, 0, 1},
			{nameHashAForTest(listfileName), nameHashBForTest(listfileName), 0, 0, 2},
		}
		payloads := [][]byte{
			[]byte("named-payload"),
			[]byte("unnamed-payload"),
			[]byte(named + "\n" + listfileName + "\n"),
		}
		filePos := []uint32{0x1200, 0x1300, 0x1400}
		hashPlain := make([]byte, 16*len(hashes))
		blockPlain := make([]byte, 16*len(hashes))
		for i := range hashes {
			base := i * 16
			put32(hashPlain, base+0, hashes[i].hashA)
			put32(hashPlain, base+4, hashes[i].hashB)
			put16(hashPlain, base+8, hashes[i].locale)
			hashPlain[base+10] = hashes[i].platform
			put32(hashPlain, base+12, hashes[i].blockIndex)

			put32(blockPlain, base+0, filePos[i])
			put32(blockPlain, base+4, uint32(len(payloads[i])))
			put32(blockPlain, base+8, uint32(len(payloads[i])))
			put32(blockPlain, base+12, blockFlagsStormData)
			copy(b[0x200+int(filePos[i]):0x200+int(filePos[i])+len(payloads[i])], payloads[i])
		}
		mpq.EncryptMpqTableDiskBytes(hashPlain, mpq.HashTableEncryptKey())
		mpq.EncryptMpqTableDiskBytes(blockPlain, mpq.BlockTableEncryptKey())
		copy(b[0x200+0x400:0x200+0x400+len(hashPlain)], hashPlain)
		copy(b[0x200+0x900:0x200+0x900+len(blockPlain)], blockPlain)
	})
	runParityCase(t, "listfile-collision-ordering", path, true)
	a, err := storm.Open(path, storm.OpenOptions{})
	if err != nil {
		t.Fatalf("go open failed: %v", err)
	}
	files, err := a.ListFiles()
	if err != nil {
		t.Fatalf("go list failed: %v", err)
	}
	if len(files) != 3 {
		t.Fatalf("file count = %d, want 3", len(files))
	}
	if files[0].Name != "hash_ee000001_ee000002_loc_0000_plat_00" || files[1].Name != "(listfile)" || files[2].Name != "maps\\collision.txt" {
		t.Fatalf("unexpected named ordering: %+v", files)
	}
	assertParityLookupReport(t, path, nameHashAForTest("maps\\collision.txt"), nameHashBForTest("maps\\collision.txt"), 0, 0, "ok", "unnamed-payload", "exact")
}

// parityCmdIsStormLibC returns true when STORMLIB_PARITY_CMD points at the C StormLib
// harness (basename stormlib-parity-c), which follows SFileOpenArchive discovery exactly.
func parityCmdIsStormLibC(cmd string) bool {
	base := filepath.Base(cmd)
	base = strings.TrimSuffix(base, ".exe")
	return base == "stormlib-parity-c"
}

func runParityCase(t *testing.T, name, archivePath string, goShouldOpen bool, stormCMatchesGo ...bool) {
	t.Helper()
	if goShouldOpen {
		if _, err := storm.Open(archivePath, storm.OpenOptions{}); err != nil {
			t.Fatalf("%s: go open failed: %v", name, err)
		}
	} else {
		if _, err := storm.Open(archivePath, storm.OpenOptions{}); err == nil {
			t.Fatalf("%s: expected go open to fail", name)
		}
	}

	parityCmd := os.Getenv("STORMLIB_PARITY_CMD")
	if parityCmd == "" {
		t.Skip("set STORMLIB_PARITY_CMD to enable C parity execution")
	}
	cmd := exec.Command(parityCmd, archivePath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s: parity command failed: %v (%s)", name, err, string(out))
	}
	wantOpen := goShouldOpen
	if len(stormCMatchesGo) > 0 && parityCmdIsStormLibC(parityCmd) {
		wantOpen = stormCMatchesGo[0]
	}
	expected := "open-fail"
	if wantOpen {
		expected = "open-ok"
	}
	if strings.TrimSpace(string(out)) != expected {
		t.Fatalf("%s: parity mismatch got %q want %q", name, strings.TrimSpace(string(out)), expected)
	}
}

func makeArchive(t *testing.T, populate func([]byte)) string {
	t.Helper()
	caseName := strings.ReplaceAll(t.Name(), "/", "_")
	path := filepath.Join(t.TempDir(), fmt.Sprintf("case-%s.mpq", caseName))
	buf := make([]byte, 0x1200000)
	populate(buf)
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}

func writeHeader(buf []byte, offset int, headerSize uint32, version uint16, sectorExp uint16, hashPos uint32, blockPos uint32, hashSize uint32, blockSize uint32) {
	writeHeaderWithMarker(buf, offset, 0x1A51504D, headerSize, version, sectorExp, hashPos, blockPos, hashSize, blockSize)
}

func writeHeaderWithMarker(buf []byte, offset int, marker uint32, headerSize uint32, version uint16, sectorExp uint16, hashPos uint32, blockPos uint32, hashSize uint32, blockSize uint32) {
	base := offset
	put32(buf, base+0, marker)
	put32(buf, base+4, headerSize)
	put32(buf, base+8, uint32(len(buf)-offset))
	put16(buf, base+12, version)
	put16(buf, base+14, sectorExp)
	put32(buf, base+16, hashPos)
	put32(buf, base+20, blockPos)
	put32(buf, base+24, hashSize)
	put32(buf, base+28, blockSize)
}

func writeUserData(buf []byte, offset int, headerOffset uint32) {
	base := offset
	buf[base+0] = 'M'
	buf[base+1] = 'P'
	buf[base+2] = 'Q'
	buf[base+3] = 0x1B
	put32(buf, base+4, 16)
	put32(buf, base+8, headerOffset)
	put32(buf, base+12, 16)
}

func put16(buf []byte, off int, v uint16) {
	buf[off+0] = byte(v)
	buf[off+1] = byte(v >> 8)
}

func put32(buf []byte, off int, v uint32) {
	buf[off+0] = byte(v)
	buf[off+1] = byte(v >> 8)
	buf[off+2] = byte(v >> 16)
	buf[off+3] = byte(v >> 24)
}

func writeMpkHeader(buf []byte, offset int) {
	base := offset
	buf[base+0] = 'M'
	buf[base+1] = 'P'
	buf[base+2] = 'K'
	buf[base+3] = 0x1A
}

func writeOneEntryTables(buf []byte, hashOff, blockOff int, hashA, hashB, filePos, csize, fsize, flags uint32) {
	hashPlain := make([]byte, 16)
	put32(hashPlain, 0, hashA)
	put32(hashPlain, 4, hashB)
	put32(hashPlain, 12, 0)
	mpq.EncryptMpqTableDiskBytes(hashPlain, mpq.HashTableEncryptKey())
	copy(buf[0x200+hashOff:0x200+hashOff+len(hashPlain)], hashPlain)

	blockPlain := make([]byte, 16)
	put32(blockPlain, 0, filePos)
	put32(blockPlain, 4, csize)
	put32(blockPlain, 8, fsize)
	put32(blockPlain, 12, flags)
	mpq.EncryptMpqTableDiskBytes(blockPlain, mpq.BlockTableEncryptKey())
	copy(buf[0x200+blockOff:0x200+blockOff+len(blockPlain)], blockPlain)
}

func makeLookupCollisionArchive(t *testing.T) string {
	return makeArchive(t, func(b []byte) {
		writeHeader(b, 0x200, 32, 0, 3, 0x400, 0x800, 4, 4)
		entries := []struct {
			hashA, hashB uint32
			locale       uint16
			platform     uint8
			blockIndex   uint32
			payload      string
			filePos      uint32
		}{
			{0x71000001, 0x72000001, 0x0409, 1, 0, "exact", 0x1100},
			{0x71000001, 0x72000001, 0x0409, 0, 1, "locale-neutral-platform", 0x1200},
			{0x71000001, 0x72000001, 0, 1, 2, "neutral-locale-platform", 0x1300},
			{0x71000001, 0x72000001, 0, 0, 3, "fully-neutral", 0x1400},
		}
		hashPlain := make([]byte, 16*len(entries))
		blockPlain := make([]byte, 16*len(entries))
		for i, e := range entries {
			baseH := i * 16
			baseB := i * 16
			put32(hashPlain, baseH+0, e.hashA)
			put32(hashPlain, baseH+4, e.hashB)
			put16(hashPlain, baseH+8, e.locale)
			hashPlain[baseH+10] = e.platform
			put32(hashPlain, baseH+12, e.blockIndex)
			put32(blockPlain, baseB+0, e.filePos)
			put32(blockPlain, baseB+4, uint32(len(e.payload)))
			put32(blockPlain, baseB+8, uint32(len(e.payload)))
			put32(blockPlain, baseB+12, blockFlagsStormData)
			copy(b[0x200+int(e.filePos):0x200+int(e.filePos)+len(e.payload)], []byte(e.payload))
		}
		mpq.EncryptMpqTableDiskBytes(hashPlain, mpq.HashTableEncryptKey())
		mpq.EncryptMpqTableDiskBytes(blockPlain, mpq.BlockTableEncryptKey())
		copy(b[0x200+0x400:0x200+0x400+len(hashPlain)], hashPlain)
		copy(b[0x200+0x800:0x200+0x800+len(blockPlain)], blockPlain)
	})
}

func makeLookupTieBreakArchive(t *testing.T) string {
	return makeArchive(t, func(b []byte) {
		writeHeader(b, 0x200, 32, 0, 3, 0x400, 0x900, 2, 2)
		hashPlain := make([]byte, 32)
		// Same hash/locale/platform but reversed block index order in hash table to probe tie-break.
		put32(hashPlain, 0, 0x81000001)
		put32(hashPlain, 4, 0x82000001)
		put16(hashPlain, 8, 0x0409)
		hashPlain[10] = 0
		put32(hashPlain, 12, 1)

		put32(hashPlain, 16, 0x81000001)
		put32(hashPlain, 20, 0x82000001)
		put16(hashPlain, 24, 0x0409)
		hashPlain[26] = 0
		put32(hashPlain, 28, 0)

		blockPlain := make([]byte, 32)
		put32(blockPlain, 0, 0x1200)
		put32(blockPlain, 4, 22)
		put32(blockPlain, 8, 22)
		put32(blockPlain, 12, blockFlagsStormData)
		put32(blockPlain, 16, 0x1300)
		put32(blockPlain, 20, 25)
		put32(blockPlain, 24, 25)
		put32(blockPlain, 28, blockFlagsStormData)

		copy(b[0x200+0x1200:0x200+0x1200+22], []byte("winner-low-block-index"))
		copy(b[0x200+0x1300:0x200+0x1300+25], []byte("loser-high-block-index----"))

		mpq.EncryptMpqTableDiskBytes(hashPlain, mpq.HashTableEncryptKey())
		mpq.EncryptMpqTableDiskBytes(blockPlain, mpq.BlockTableEncryptKey())
		copy(b[0x200+0x400:0x200+0x400+len(hashPlain)], hashPlain)
		copy(b[0x200+0x900:0x200+0x900+len(blockPlain)], blockPlain)
	})
}

func assertParityLookupReport(t *testing.T, archivePath string, hashA, hashB uint32, locale uint16, platform uint8, expectedOutcome, expectedPayload, expectedTier string) {
	t.Helper()
	parityCmd := os.Getenv("STORMLIB_PARITY_CMD")
	if parityCmd == "" {
		return
	}
	args := []string{"--report-lookup", fmt.Sprintf("0x%x", locale), fmt.Sprintf("%d", platform), archivePath}
	out, strictSkip := runStructuredReportMode(t, parityCmd, args...)
	if strictSkip {
		return
	}
	var report struct {
		Outcome string `json:"outcome"`
		Payload string `json:"payload"`
		Tier    string `json:"tier"`
	}
	if err := json.Unmarshal(out, &report); err != nil {
		if strictReportModeEnabled() {
			t.Fatalf("lookup parity JSON parse failed in strict mode: %v", err)
		}
		return
	}
	if err := validateLookupReport(report.Outcome, report.Payload, report.Tier, expectedOutcome, expectedPayload, expectedTier); err != nil {
		t.Fatalf("lookup report validation failed (hashA=%#x hashB=%#x): %v", hashA, hashB, err)
	}
}

func assertParityReadReport(t *testing.T, archivePath string, hashA, hashB uint32, locale uint16, platform uint8, expectedOutcome, expectedPayload string) {
	t.Helper()
	parityCmd := os.Getenv("STORMLIB_PARITY_CMD")
	if parityCmd == "" {
		return
	}
	args := []string{
		"--report-read",
		fmt.Sprintf("0x%x", hashA),
		fmt.Sprintf("0x%x", hashB),
		fmt.Sprintf("0x%x", locale),
		fmt.Sprintf("%d", platform),
		archivePath,
	}
	out, strictSkip := runStructuredReportMode(t, parityCmd, args...)
	if strictSkip {
		return
	}
	var report struct {
		Outcome string `json:"outcome"`
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(out, &report); err != nil {
		if strictReportModeEnabled() {
			t.Fatalf("read parity JSON parse failed in strict mode: %v", err)
		}
		return
	}
	if err := validateReadReport(report.Outcome, report.Payload, expectedOutcome, expectedPayload); err != nil {
		t.Fatalf("read report validation failed: %v", err)
	}
}

func runStructuredReportMode(t *testing.T, parityCmd string, args ...string) ([]byte, bool) {
	t.Helper()
	out, skipped, err := evaluateStructuredReportMode(parityCmd, strictReportModeEnabled(), args...)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return out, skipped
}

func evaluateStructuredReportMode(parityCmd string, strict bool, args ...string) ([]byte, bool, error) {
	cmd := exec.Command(parityCmd, args...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return out, false, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 2 && strings.TrimSpace(string(out)) == "unsupported report mode" {
		if strict {
			return nil, false, fmt.Errorf("structured report mode explicitly unsupported in strict mode: %s (%s)", strings.Join(args, " "), string(out))
		}
		return nil, true, nil
	}
	if strict {
		return nil, false, fmt.Errorf("structured report mode failed in strict mode: %v (%s)", err, string(out))
	}
	if strings.Contains(string(out), "unknown option") || strings.Contains(string(out), "usage") {
		return nil, true, nil
	}
	return nil, false, fmt.Errorf("structured report mode failed: %v (%s)", err, string(out))
}

func TestParityCommandCapabilityPreflight(t *testing.T) {
	parityCmd := os.Getenv("STORMLIB_PARITY_CMD")
	if parityCmd == "" {
		if strictReportModeEnabled() {
			t.Fatal("strict mode requires STORMLIB_PARITY_CMD to be configured")
		}
		t.Skip("set STORMLIB_PARITY_CMD to enable C parity execution")
	}
	fingerprint := parityCommandFingerprint(parityCmd)
	if !strings.Contains(fingerprint, "path=") || !strings.Contains(fingerprint, "version=") {
		t.Fatalf("invalid parity fingerprint format: %q", fingerprint)
	}
	t.Logf("parity command fingerprint: %s", fingerprint)
	path := makeArchive(t, func(b []byte) {
		writeHeader(b, 0x200, 32, 0, 3, 0x200, 0x300, 0, 0)
	})

	lookupOut, lookupSkip := runStructuredReportMode(t, parityCmd, "--report-lookup", "0x409", "0", path)
	if !lookupSkip {
		var report struct {
			Outcome string `json:"outcome"`
		}
		if err := json.Unmarshal(lookupOut, &report); err != nil {
			t.Fatalf("lookup preflight JSON parse failed: %v", err)
		}
		if report.Outcome == "" {
			t.Fatal("lookup preflight report missing outcome")
		}
		if report.Outcome == "ok" {
			var withTier struct {
				Tier string `json:"tier"`
			}
			_ = json.Unmarshal(lookupOut, &withTier)
			if withTier.Tier == "" {
				t.Fatal("lookup preflight report missing tier for outcome=ok")
			}
		}
	}

	readOut, readSkip := runStructuredReportMode(t, parityCmd, "--report-read", "0x11111111", "0x22222222", "0x409", "0", path)
	if !readSkip {
		var report struct {
			Outcome string `json:"outcome"`
		}
		if err := json.Unmarshal(readOut, &report); err != nil {
			t.Fatalf("read preflight JSON parse failed: %v", err)
		}
		if report.Outcome == "" {
			t.Fatal("read preflight report missing outcome")
		}
		if report.Outcome == "ok" {
			var withPayload map[string]any
			_ = json.Unmarshal(readOut, &withPayload)
			if _, ok := withPayload["payload"]; !ok {
				t.Fatal("read preflight report missing payload field for outcome=ok")
			}
		}
	}
}

func TestRunStructuredReportMode_StrictUnsupportedFails(t *testing.T) {
	cmdPath := fakeParityCommand(t, 2, "", "unsupported report mode")
	_, _, err := evaluateStructuredReportMode(cmdPath, true, "--report-lookup", "0x409", "0", "archive.mpq")
	if err == nil || !strings.Contains(err.Error(), "explicitly unsupported in strict mode") {
		t.Fatalf("expected strict unsupported failure, got %v", err)
	}
}

func TestRunStructuredReportMode_StrictUnsupportedPhraseExactness(t *testing.T) {
	cmdPath := fakeParityCommand(t, 2, "", "unsupported report")
	_, _, err := evaluateStructuredReportMode(cmdPath, true, "--report-lookup", "0x409", "0", "archive.mpq")
	if err == nil || !strings.Contains(err.Error(), "failed in strict mode") {
		t.Fatalf("expected strict failure for non-exact unsupported phrase, got %v", err)
	}
}

func TestRunStructuredReportMode_SoftUnsupportedSkips(t *testing.T) {
	cmdPath := fakeParityCommand(t, 2, "", "unsupported report mode")
	_, skipped, err := evaluateStructuredReportMode(cmdPath, false, "--report-lookup", "0x409", "0", "archive.mpq")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !skipped {
		t.Fatal("expected soft mode to skip for explicit unsupported report mode")
	}
}

func TestRunStructuredReportMode_SoftUnsupportedPhraseExactness(t *testing.T) {
	cmdPath := fakeParityCommand(t, 2, "", "unsupported report")
	_, skipped, err := evaluateStructuredReportMode(cmdPath, false, "--report-lookup", "0x409", "0", "archive.mpq")
	if err == nil {
		t.Fatal("expected soft mode error for non-exact unsupported phrase")
	}
	if skipped {
		t.Fatal("soft mode should not skip for non-exact unsupported phrase")
	}
}

func TestRunStructuredReportMode_StrictMalformedJSONFails(t *testing.T) {
	cmdPath := fakeParityCommand(t, 0, "{bad-json", "")
	out, skipped, err := evaluateStructuredReportMode(cmdPath, true, "--report-read", "1", "2", "3", "0", "archive.mpq")
	if err != nil {
		t.Fatalf("unexpected execution error: %v", err)
	}
	if skipped {
		t.Fatal("strict mode must not skip malformed-json output")
	}
	var report struct {
		Outcome string `json:"outcome"`
	}
	if err := json.Unmarshal(out, &report); err == nil {
		t.Fatal("expected malformed json parse failure")
	}
}

func TestRunStructuredReportMode_SoftMalformedJSONBehavior(t *testing.T) {
	cmdPath := fakeParityCommand(t, 0, "{bad-json", "")
	out, skipped, err := evaluateStructuredReportMode(cmdPath, false, "--report-read", "1", "2", "3", "0", "archive.mpq")
	if err != nil {
		t.Fatalf("unexpected execution error: %v", err)
	}
	if skipped {
		t.Fatal("soft mode should not auto-skip when command exits successfully")
	}
	var report struct {
		Outcome string `json:"outcome"`
	}
	if err := json.Unmarshal(out, &report); err == nil {
		t.Fatal("expected malformed json parse failure in soft-mode regression test")
	}
}

func TestValidateLookupReport_RequiresTierOnOK(t *testing.T) {
	err := validateLookupReport("ok", "payload", "", "ok", "payload", "exact")
	if err == nil || !strings.Contains(err.Error(), "tier") {
		t.Fatalf("expected missing tier failure, got %v", err)
	}
}

func TestValidateReadReport_RequiresPayloadOnOK(t *testing.T) {
	err := validateReadReport("ok", "", "ok", "payload")
	if err == nil || !strings.Contains(err.Error(), "payload") {
		t.Fatalf("expected missing payload failure, got %v", err)
	}
}

func TestClassifyGoReadOutcome_TableDriven(t *testing.T) {
	tests := []struct {
		name        string
		payload     []byte
		err         error
		wantOutcome string
		wantPayload string
	}{
		{name: "ok", payload: []byte("abc"), err: nil, wantOutcome: "ok", wantPayload: "abc"},
		{name: "not found", err: errors.New("file not found"), wantOutcome: "not-found"},
		{name: "decode", err: errors.New("decode failed"), wantOutcome: "decode-fail"},
		{name: "invalid", err: errors.New("invalid sector table"), wantOutcome: "decode-fail"},
		{name: "unsupported", err: errors.New("unexpected io state"), wantOutcome: "unsupported"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			gotOutcome, gotPayload := classifyGoReadOutcome(tc.payload, tc.err)
			if gotOutcome != tc.wantOutcome || gotPayload != tc.wantPayload {
				t.Fatalf("got (%q,%q), want (%q,%q)", gotOutcome, gotPayload, tc.wantOutcome, tc.wantPayload)
			}
		})
	}
}

func parityCommandFingerprint(path string) string {
	cmd := exec.Command(path, "--version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("path=%s version=unavailable err=%v", path, err)
	}
	return fmt.Sprintf("path=%s version=%s", path, strings.TrimSpace(string(out)))
}

func fakeParityCommand(t *testing.T, exitCode int, stdout, stderr string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "fake-parity.sh")
	script := fmt.Sprintf("#!/usr/bin/env sh\nprintf '%%s' '%s'\nprintf '%%s' '%s' 1>&2\nexit %d\n", escapeSingleQuotes(stdout), escapeSingleQuotes(stderr), exitCode)
	if runtime.GOOS == "windows" {
		path = filepath.Join(dir, "fake-parity.bat")
		script = fmt.Sprintf("@echo off\r\n<nul set /p =%s\r\n1>&2 <nul set /p =%s\r\nexit /b %d\r\n", stdout, stderr, exitCode)
	}
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake parity command: %v", err)
	}
	return path
}

func escapeSingleQuotes(s string) string {
	return strings.ReplaceAll(s, "'", "'\"'\"'")
}

func validateLookupReport(gotOutcome, gotPayload, gotTier, wantOutcome, wantPayload, wantTier string) error {
	if gotOutcome != wantOutcome {
		return fmt.Errorf("outcome mismatch: got %q want %q", gotOutcome, wantOutcome)
	}
	if wantOutcome == "ok" {
		if gotPayload != wantPayload {
			return fmt.Errorf("payload mismatch: got %q want %q", gotPayload, wantPayload)
		}
		if gotTier == "" {
			return fmt.Errorf("tier required for outcome=ok")
		}
		if gotTier != wantTier {
			return fmt.Errorf("tier mismatch: got %q want %q", gotTier, wantTier)
		}
	}
	if wantOutcome == "not-found" && gotTier != "" {
		return fmt.Errorf("tier must be empty for not-found, got %q", gotTier)
	}
	return nil
}

func validateReadReport(gotOutcome, gotPayload, wantOutcome, wantPayload string) error {
	if gotOutcome != wantOutcome {
		return fmt.Errorf("outcome mismatch: got %q want %q", gotOutcome, wantOutcome)
	}
	if wantOutcome == "ok" {
		if gotPayload == "" && wantPayload != "" {
			return fmt.Errorf("payload required for outcome=ok")
		}
		if gotPayload != wantPayload {
			return fmt.Errorf("payload mismatch: got %q want %q", gotPayload, wantPayload)
		}
	}
	return nil
}

func strictReportModeEnabled() bool {
	if v, ok := os.LookupEnv("STORMLIB_PARITY_STRICT"); ok {
		parsed, err := strconv.ParseBool(v)
		if err == nil {
			return parsed
		}
	}
	return strings.EqualFold(os.Getenv("CI"), "true")
}

func classifyGoReadOutcome(payload []byte, err error) (string, string) {
	if err == nil {
		return "ok", string(payload)
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "file not found") || strings.Contains(msg, "not found") {
		return "not-found", ""
	}
	if strings.Contains(msg, "decode") || strings.Contains(msg, "decompress") || strings.Contains(msg, "invalid") || strings.Contains(msg, "out of range") {
		return "decode-fail", ""
	}
	return "unsupported", ""
}

func TestSpotcheckDriftScriptHelp(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not in PATH")
	}
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	script := filepath.Join(filepath.Dir(thisFile), "scripts", "spotcheck_c_backed_drift.sh")
	cmd := exec.Command(bash, script, "-h")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("spotcheck -h: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "parity-c-vs-go-diff") {
		t.Fatalf("unexpected help output: %s", out)
	}
}

func nameHashAForTest(name string) uint32 { return mpq.NameHashA(name) }
func nameHashBForTest(name string) uint32 { return mpq.NameHashB(name) }
