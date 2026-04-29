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
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type summary struct {
	Total         int            `json:"total"`
	Passed        int            `json:"passed"`
	Failed        int            `json:"failed"`
	Skipped       int            `json:"skipped"`
	SkipReasons   map[string]int `json:"skip_reasons"`
	FailedTestIDs []string       `json:"failed_test_ids"`
}

type testEvent struct {
	Action  string `json:"Action"`
	Test    string `json:"Test"`
	Output  string `json:"Output"`
	Package string `json:"Package"`
}

func run() error {
	if len(os.Args) != 2 {
		return fmt.Errorf("usage: parity-summary <go-test-jsonl-path>")
	}

	f, err := os.Open(os.Args[1])
	if err != nil {
		return err
	}
	defer f.Close()

	out := summary{SkipReasons: map[string]int{}}
	recentOutput := map[string]string{}

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var ev testEvent
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			continue
		}

		if ev.Test != "" && ev.Action == "output" {
			recentOutput[ev.Test] += ev.Output
		}

		if ev.Test == "" {
			continue
		}

		switch ev.Action {
		case "pass":
			out.Total++
			out.Passed++
		case "fail":
			out.Total++
			out.Failed++
			out.FailedTestIDs = append(out.FailedTestIDs, ev.Test)
		case "skip":
			out.Total++
			out.Skipped++
			reason := bucketSkipReason(recentOutput[ev.Test])
			out.SkipReasons[reason]++
		}
	}

	if err := sc.Err(); err != nil {
		return err
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")

	return enc.Encode(out)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func bucketSkipReason(output string) string {
	l := strings.ToLower(output)
	switch {
	case strings.Contains(l, "set stormlib_parity_cmd"):
		return "missing_command"
	case strings.Contains(l, "unsupported report mode"):
		return "unsupported_report_mode"
	case strings.Contains(l, "skipped"):
		return "generic_skip"
	default:
		return "unknown"
	}
}
