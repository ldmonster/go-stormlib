package parity

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ldmonster/go-stormlib/pkg/storm"
)

// TestHetBetWriteRoundTripParity creates v3 and v4 archives with the Go writer
// (which emits HET/BET extension tables) and confirms the canonical StormLib C
// reader still opens them. This is end-to-end binary-format validation of the
// HET/BET serializer wired into Flush()/Compact().
func TestHetBetWriteRoundTripParity(t *testing.T) {
	parityCmd := os.Getenv("STORMLIB_PARITY_CMD")
	if parityCmd == "" {
		t.Skip("set STORMLIB_PARITY_CMD to enable C parity execution")
	}

	cases := []struct {
		name    string
		version uint32
	}{
		{"v3", 2},
		{"v4", 3},
	}

	files := map[string][]byte{
		"alpha.txt":              bytes.Repeat([]byte("A"), 64),
		"sub\\beta.bin":          bytes.Repeat([]byte{0xBE, 0xEF}, 32),
		"deep\\nested\\path.dat": bytes.Repeat([]byte("Z"), 17),
	}

	const flagExists = uint32(0x80000000)
	const flagSingleUnit = uint32(0x01000000)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "hetbet-"+tc.name+".mpq")
			a, err := storm.Create(path, storm.CreateOptions{
				ArchiveVersion: tc.version,
				MaxFileCount:   16,
			})
			if err != nil {
				t.Fatalf("storm.Create: %v", err)
			}
			for name, data := range files {
				if err := a.AddFile(name, data, flagExists|flagSingleUnit); err != nil {
					t.Fatalf("AddFile %q: %v", name, err)
				}
			}
			if err := a.Flush(); err != nil {
				t.Fatalf("Flush: %v", err)
			}
			if err := a.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}

			// Re-open with Go to confirm HET/BET pointers were stamped.
			ar, err := storm.Open(path, storm.OpenOptions{})
			if err != nil {
				t.Fatalf("storm.Open after write: %v", err)
			}
			h := ar.Header()
			if h.HetTablePos64 == 0 || h.BetTablePos64 == 0 {
				t.Fatalf("HET/BET pointers missing after %s write: het=%#x bet=%#x",
					tc.name, h.HetTablePos64, h.BetTablePos64)
			}
			ar.Close()

			cmd := exec.Command(parityCmd, path)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("%s parity command failed: %v (%s)", tc.name, err, string(out))
			}
			if got := strings.TrimSpace(string(out)); got != "open-ok" {
				t.Fatalf("%s: stormlib C rejected Go-written archive: got %q want %q",
					tc.name, got, "open-ok")
			}
		})
	}
}
