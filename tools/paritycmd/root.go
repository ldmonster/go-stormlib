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
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	internalarchive "github.com/ldmonster/go-stormlib/internal/archive"
	"github.com/ldmonster/go-stormlib/internal/mpq"
)

type commandOptions struct {
	forceV1      bool
	marker       string
	reportLookup bool
	reportRead   bool
}

const ParityCmdVersion = "v0.1.0-contract1"

func NewRootCmd(stdout, stderr io.Writer) *cobra.Command {
	opts := &commandOptions{}
	cmd := &cobra.Command{
		Use:           "stormlib-parity [flags] <archive>",
		Version:       ParityCmdVersion,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			openOptions, optsErr := openOpts(opts)
			if opts.reportLookup && opts.reportRead {
				return usageError(cmd, "only one report mode can be selected")
			}

			if opts.reportLookup {
				if os.Getenv("STORMLIB_PARITY_DISABLE_REPORT") == "true" {
					return &cliError{code: 2, msg: "unsupported report mode"}
				}

				if len(args) != 3 {
					return usageError(cmd, "report-lookup requires <locale> <platform> <archive>")
				}

				locale, err := parseNumeric(args[0], 16)
				if err != nil {
					return usageError(cmd, "invalid locale")
				}

				platform, err := parseNumeric(args[1], 8)
				if err != nil {
					return usageError(cmd, "invalid platform")
				}

				if optsErr != nil {
					return usageError(cmd, optsErr.Error())
				}

				return runLookupReport(
					stdout,
					args[2],
					openOptions,
					uint16(locale),
					uint8(platform),
				)
			}

			if opts.reportRead {
				if os.Getenv("STORMLIB_PARITY_DISABLE_REPORT") == "true" {
					return &cliError{code: 2, msg: "unsupported report mode"}
				}

				if len(args) != 5 {
					return usageError(
						cmd,
						"report-read requires <hashA> <hashB> <locale> <platform> <archive>",
					)
				}

				hashA, err := parseNumeric(args[0], 32)
				if err != nil {
					return usageError(cmd, "invalid hashA")
				}

				hashB, err := parseNumeric(args[1], 32)
				if err != nil {
					return usageError(cmd, "invalid hashB")
				}

				locale, err := parseNumeric(args[2], 16)
				if err != nil {
					return usageError(cmd, "invalid locale")
				}

				platform, err := parseNumeric(args[3], 8)
				if err != nil {
					return usageError(cmd, "invalid platform")
				}

				if optsErr != nil {
					return usageError(cmd, optsErr.Error())
				}

				return runReadReport(
					stdout,
					args[4],
					openOptions,
					uint32(hashA),
					uint32(hashB),
					uint16(locale),
					uint8(platform),
				)
			}

			if len(args) != 1 {
				return usageError(cmd, "default mode requires <archive>")
			}

			if optsErr != nil {
				return usageError(cmd, optsErr.Error())
			}

			return runOpenMode(stdout, args[0], openOptions)
		},
	}
	cmd.SetVersionTemplate("{{.Version}}\n")
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)
	cmd.Flags().BoolVar(&opts.forceV1, "force-v1", false, "force MPQ v1 mode")
	cmd.Flags().StringVar(&opts.marker, "marker", "", "custom marker signature (hex or decimal)")
	cmd.Flags().BoolVar(&opts.reportLookup, "report-lookup", false, "emit lookup report mode")
	cmd.Flags().BoolVar(&opts.reportRead, "report-read", false, "emit read report mode")

	return cmd
}

func openOpts(opts *commandOptions) (internalarchive.OpenOptions, error) {
	var marker uint32
	if opts.marker != "" {
		v, err := parseNumeric(opts.marker, 32)
		if err != nil {
			return internalarchive.OpenOptions{}, errors.New("invalid marker")
		}

		marker = uint32(v)
	}

	return internalarchive.OpenOptions{ForceMPQV1: opts.forceV1, MarkerSignature: marker}, nil
}

func runOpenMode(
	stdout io.Writer,
	archivePath string,
	openOptions internalarchive.OpenOptions,
) error {
	_, err := internalarchive.OpenWithOptions(archivePath, openOptions)
	if err != nil {
		fmt.Fprintln(stdout, "open-fail")
		return nil
	}

	fmt.Fprintln(stdout, "open-ok")

	return nil
}

func runLookupReport(
	stdout io.Writer,
	archivePath string,
	openOptions internalarchive.OpenOptions,
	locale uint16,
	platform uint8,
) error {
	a, err := internalarchive.OpenWithOptions(archivePath, openOptions)
	if err != nil {
		return emitJSON(stdout, map[string]string{"outcome": "unsupported"})
	}

	type key struct {
		a uint32
		b uint32
	}

	groups := map[key][]mpq.IndexedFileEntry{}

	for _, e := range a.FileIndex {
		k := key{a: e.Hash.HashA, b: e.Hash.HashB}
		groups[k] = append(groups[k], e)
	}

	keys := make([]key, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}

	sort.Slice(keys, func(i, j int) bool {
		if keys[i].a != keys[j].a {
			return keys[i].a < keys[j].a
		}

		return keys[i].b < keys[j].b
	})

	for _, k := range keys {
		entry, ok := mpq.FindIndexedFileEntry(groups[k], k.a, k.b, locale, platform)
		if !ok {
			continue
		}

		h, err := a.OpenIndexedFileByHash(k.a, k.b, locale, platform)
		if err != nil {
			return emitJSON(stdout, map[string]string{"outcome": "not-found"})
		}

		payload, err := a.ReadFile(h)
		if err != nil {
			return emitJSON(stdout, map[string]string{"outcome": "decode-fail"})
		}

		report := map[string]string{
			"outcome": "ok",
			"payload": string(payload),
			"tier":    lookupTier(entry, locale, platform),
		}

		return emitJSON(stdout, report)
	}

	return emitJSON(stdout, map[string]string{"outcome": "not-found"})
}

func runReadReport(
	stdout io.Writer,
	archivePath string,
	openOptions internalarchive.OpenOptions,
	hashA, hashB uint32,
	locale uint16,
	platform uint8,
) error {
	a, err := internalarchive.OpenWithOptions(archivePath, openOptions)
	if err != nil {
		return emitJSON(stdout, map[string]string{"outcome": "unsupported"})
	}

	h, err := a.OpenIndexedFileByHash(hashA, hashB, locale, platform)
	if err != nil {
		return emitJSON(stdout, map[string]string{"outcome": "not-found"})
	}

	payload, err := a.ReadFile(h)
	if err != nil {
		return emitJSON(stdout, map[string]string{"outcome": "decode-fail"})
	}

	return emitJSON(stdout, map[string]string{"outcome": "ok", "payload": string(payload)})
}

func lookupTier(entry mpq.IndexedFileEntry, locale uint16, platform uint8) string {
	switch {
	case entry.Hash.Locale == locale && entry.Hash.Platform == platform:
		return "exact"
	case entry.Hash.Locale == locale && entry.Hash.Platform == 0:
		return "locale-neutral-platform"
	case entry.Hash.Locale == 0 && entry.Hash.Platform == platform:
		return "neutral-locale-platform"
	default:
		return "fully-neutral"
	}
}

func emitJSON(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}

	_, err = fmt.Fprintln(w, string(b))

	return err
}

func parseNumeric(v string, bits int) (uint64, error) {
	base := 10

	s := strings.TrimSpace(v)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		base = 16
		s = s[2:]
	}

	if s == "" {
		return 0, errors.New("empty value")
	}

	return strconv.ParseUint(s, base, bits)
}

func usageError(cmd *cobra.Command, msg string) error {
	return &cliError{
		code: 1,
		msg:  fmt.Sprintf("%s\n\n%s", msg, strings.TrimSpace(cmd.UsageString())),
	}
}
