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

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ldmonster/go-stormlib/internal/mpq"
)

func TestDefaultMode_OpenStatus(t *testing.T) {
	path := makeArchive(t, func(buf []byte) {
		writeHeader(buf, 0x200, 32, 0, 3, 0x200, 0x300, 0, 0)
	})
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	cmd := NewRootCmd(stdout, stderr)
	cmd.SetArgs([]string{path})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute error: %v", err)
	}
	if strings.TrimSpace(stdout.String()) != "open-ok" {
		t.Fatalf("stdout = %q, want open-ok", stdout.String())
	}
}

func TestReportLookup_ArgValidation(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	cmd := NewRootCmd(stdout, stderr)
	cmd.SetArgs([]string{"--report-lookup", "bad", "x", "archive.mpq"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected arg validation error")
	}
	var ce *cliError
	if !strings.Contains(err.Error(), "invalid locale") && !(errorAs(err, &ce) && ce.code == 1) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReportUnsupportedModeSignal(t *testing.T) {
	t.Setenv("STORMLIB_PARITY_DISABLE_REPORT", "true")
	path := makeArchive(t, func(buf []byte) {
		writeHeader(buf, 0x200, 32, 0, 3, 0x200, 0x300, 0, 0)
	})
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	cmd := NewRootCmd(stdout, stderr)
	cmd.SetArgs([]string{"--report-lookup", "0x409", "0", path})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected unsupported report mode error")
	}
	var ce *cliError
	if !errorAs(err, &ce) || ce.code != 2 || !strings.Contains(ce.msg, "unsupported report mode") {
		t.Fatalf("unexpected error = %#v", err)
	}
}

func TestReportRead_JSONShape(t *testing.T) {
	path := makeArchive(t, func(buf []byte) {
		writeHeader(buf, 0x200, 32, 0, 3, 0x200, 0x300, 0, 0)
	})
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	cmd := NewRootCmd(stdout, stderr)
	cmd.SetArgs([]string{"--report-read", "0x1", "0x2", "0x409", "0", path})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute error: %v", err)
	}
	var report map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &report); err != nil {
		t.Fatalf("invalid json: %v (%q)", err, stdout.String())
	}
	if report["outcome"] == nil {
		t.Fatalf("missing outcome in report: %v", report)
	}
}

func TestLookupReport_ContractTierVocabulary(t *testing.T) {
	path := makeArchive(t, func(buf []byte) {
		writeHeader(buf, 0x200, 32, 0, 3, 0x200, 0x300, 0, 0)
	})
	stdout := &bytes.Buffer{}
	cmd := NewRootCmd(stdout, &bytes.Buffer{})
	cmd.SetArgs([]string{"--report-lookup", "0x409", "0", path})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute error: %v", err)
	}
	var report map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &report); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if out, _ := report["outcome"].(string); out == "ok" {
		tier, _ := report["tier"].(string)
		allowed := map[string]bool{
			"exact":                   true,
			"locale-neutral-platform": true,
			"neutral-locale-platform": true,
			"fully-neutral":           true,
		}
		if !allowed[tier] {
			t.Fatalf("invalid tier %q", tier)
		}
	}
}

func TestReadReport_ContractOutcomeVocabulary(t *testing.T) {
	path := makeArchive(t, func(buf []byte) {
		writeHeader(buf, 0x200, 32, 0, 3, 0x200, 0x300, 0, 0)
	})
	stdout := &bytes.Buffer{}
	cmd := NewRootCmd(stdout, &bytes.Buffer{})
	cmd.SetArgs([]string{"--report-read", "0x1", "0x2", "0x409", "0", path})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute error: %v", err)
	}
	var report map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &report); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	outcome, _ := report["outcome"].(string)
	allowed := map[string]bool{
		"ok":          true,
		"not-found":   true,
		"decode-fail": true,
		"unsupported": true,
	}
	if !allowed[outcome] {
		t.Fatalf("invalid outcome vocabulary %q", outcome)
	}
}

func TestReportMode_StdoutJSONOnly(t *testing.T) {
	path := makeArchive(t, func(buf []byte) {
		writeHeader(buf, 0x200, 32, 0, 3, 0x200, 0x300, 0, 0)
	})
	stdout := &bytes.Buffer{}
	cmd := NewRootCmd(stdout, &bytes.Buffer{})
	cmd.SetArgs([]string{"--report-read", "0x1", "0x2", "0x409", "0", path})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute error: %v", err)
	}
	line := strings.TrimSpace(stdout.String())
	if strings.Count(line, "\n") != 0 {
		t.Fatalf("stdout should be single-line json, got %q", stdout.String())
	}
	var report map[string]any
	if err := json.Unmarshal([]byte(line), &report); err != nil {
		t.Fatalf("stdout not pure json: %v (%q)", err, line)
	}
}

func TestReadReport_PayloadNormalizationGuard(t *testing.T) {
	path := makeArchive(t, func(buf []byte) {
		writeHeader(buf, 0x200, 32, 0, 3, 0x400, 0x600, 1, 1)
		payload := []byte("line-with-newline\n")
		hashPlain := make([]byte, 16)
		binary.LittleEndian.PutUint32(hashPlain[0:4], 0x11111111)
		binary.LittleEndian.PutUint32(hashPlain[4:8], 0x22222222)
		binary.LittleEndian.PutUint32(hashPlain[12:16], 0)
		mpq.EncryptMpqTableDiskBytes(hashPlain, mpq.HashTableEncryptKey())
		copy(buf[0x200+0x400:0x200+0x400+len(hashPlain)], hashPlain)
		blockPlain := make([]byte, 16)
		binary.LittleEndian.PutUint32(blockPlain[0:4], 0x900)
		binary.LittleEndian.PutUint32(blockPlain[4:8], uint32(len(payload)))
		binary.LittleEndian.PutUint32(blockPlain[8:12], uint32(len(payload)))
		binary.LittleEndian.PutUint32(blockPlain[12:16], 0x01000000)
		mpq.EncryptMpqTableDiskBytes(blockPlain, mpq.BlockTableEncryptKey())
		copy(buf[0x200+0x600:0x200+0x600+len(blockPlain)], blockPlain)
		copy(buf[0x200+0x900:0x200+0x900+len(payload)], payload)
	})
	stdout := &bytes.Buffer{}
	cmd := NewRootCmd(stdout, &bytes.Buffer{})
	cmd.SetArgs([]string{"--report-read", "0x11111111", "0x22222222", "0x0", "0", path})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute error: %v", err)
	}
	var report struct {
		Outcome string `json:"outcome"`
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &report); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if report.Outcome != "ok" {
		t.Fatalf("unexpected outcome: %q", report.Outcome)
	}
	if report.Payload != "line-with-newline\n" {
		t.Fatalf("payload normalization mismatch: %q", report.Payload)
	}
}

func makeArchive(t *testing.T, populate func([]byte)) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cmdcase.mpq")
	buf := make([]byte, 0x2000)
	populate(buf)
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}

func writeHeader(buf []byte, offset int, headerSize uint32, version uint16, sectorExp uint16, hashPos uint32, blockPos uint32, hashSize uint32, blockSize uint32) {
	binary.LittleEndian.PutUint32(buf[offset+0:offset+4], 0x1A51504D)
	binary.LittleEndian.PutUint32(buf[offset+4:offset+8], headerSize)
	binary.LittleEndian.PutUint32(buf[offset+8:offset+12], uint32(len(buf)-offset))
	binary.LittleEndian.PutUint16(buf[offset+12:offset+14], version)
	binary.LittleEndian.PutUint16(buf[offset+14:offset+16], sectorExp)
	binary.LittleEndian.PutUint32(buf[offset+16:offset+20], hashPos)
	binary.LittleEndian.PutUint32(buf[offset+20:offset+24], blockPos)
	binary.LittleEndian.PutUint32(buf[offset+24:offset+28], hashSize)
	binary.LittleEndian.PutUint32(buf[offset+28:offset+32], blockSize)
}

func errorAs(err error, target any) bool {
	switch t := target.(type) {
	case **cliError:
		ce, ok := err.(*cliError)
		if ok {
			*t = ce
		}
		return ok
	default:
		return false
	}
}
