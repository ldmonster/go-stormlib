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
	"encoding/json"
	"fmt"
	"os"
)

type summary struct {
	Total         int      `json:"total"`
	Passed        int      `json:"passed"`
	Failed        int      `json:"failed"`
	Skipped       int      `json:"skipped"`
	FailedTestIDs []string `json:"failed_test_ids"`
}

type diffReport struct {
	LeftPath           string   `json:"left_path"`
	RightPath          string   `json:"right_path"`
	TotalDelta         int      `json:"total_delta"`
	PassedDelta        int      `json:"passed_delta"`
	FailedDelta        int      `json:"failed_delta"`
	SkippedDelta       int      `json:"skipped_delta"`
	FailedOnlyInLeft   []string `json:"failed_only_in_left"`
	FailedOnlyInRight  []string `json:"failed_only_in_right"`
	HasBehavioralDrift bool     `json:"has_behavioral_drift"`
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(
			os.Stderr,
			"usage: parity-summary-diff <left-summary.json> <right-summary.json>",
		)
		os.Exit(1)
	}

	leftPath := os.Args[1]
	rightPath := os.Args[2]

	left, err := readSummary(leftPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	right, err := readSummary(rightPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	leftSet := make(map[string]bool, len(left.FailedTestIDs))

	rightSet := make(map[string]bool, len(right.FailedTestIDs))
	for _, id := range left.FailedTestIDs {
		leftSet[id] = true
	}

	for _, id := range right.FailedTestIDs {
		rightSet[id] = true
	}

	var onlyLeft, onlyRight []string

	for id := range leftSet {
		if !rightSet[id] {
			onlyLeft = append(onlyLeft, id)
		}
	}

	for id := range rightSet {
		if !leftSet[id] {
			onlyRight = append(onlyRight, id)
		}
	}

	out := diffReport{
		LeftPath:          leftPath,
		RightPath:         rightPath,
		TotalDelta:        right.Total - left.Total,
		PassedDelta:       right.Passed - left.Passed,
		FailedDelta:       right.Failed - left.Failed,
		SkippedDelta:      right.Skipped - left.Skipped,
		FailedOnlyInLeft:  onlyLeft,
		FailedOnlyInRight: onlyRight,
		HasBehavioralDrift: (right.Failed != left.Failed) ||
			(right.Skipped != left.Skipped) ||
			(len(onlyLeft) > 0) || (len(onlyRight) > 0),
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")

	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func readSummary(path string) (summary, error) {
	var s summary

	f, err := os.Open(path)
	if err != nil {
		return s, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	if err := json.NewDecoder(f).Decode(&s); err != nil {
		return s, fmt.Errorf("decode %s: %w", path, err)
	}

	return s, nil
}
