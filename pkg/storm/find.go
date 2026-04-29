package storm

import (
	"path"
	"strings"

	"github.com/ldmonster/go-stormlib/internal/mpq"
)

// LocaleInfo describes a (locale, platform) pair under which a logical filename
// is present in the archive (parity with SFileEnumLocales).
type LocaleInfo struct {
	Name     string
	Locale   uint16
	Platform uint8
}

// FindFiles returns every file in the archive whose name matches the supplied
// glob mask. The mask uses standard `*` and `?` wildcards (case-insensitive,
// `\\` and `/` treated as equivalent path separators). An empty or `*` mask
// matches everything.
//
// This is the Go-idiomatic equivalent of SFileFindFirstFile/SFileFindNextFile:
// callers receive the entire match set in one call rather than iterating.
func (a *Archive) FindFiles(mask string) ([]FileInfo, error) {
	all, err := a.ListFiles()
	if err != nil {
		return nil, err
	}

	if mask == "" || mask == "*" || mask == "*.*" {
		return all, nil
	}

	out := make([]FileInfo, 0, len(all))
	for _, fi := range all {
		if matchMpqMask(mask, fi.Name) {
			out = append(out, fi)
		}
	}

	return out, nil
}

// EnumLocales returns every (locale, platform) entry in the hash table whose
// name hash matches the supplied filename. Mirrors SFileEnumLocales.
func (a *Archive) EnumLocales(name string) ([]LocaleInfo, error) {
	hashA := mpq.NameHashA(name)
	hashB := mpq.NameHashB(name)

	var out []LocaleInfo

	for _, e := range a.inner.FileIndex {
		if e.Hash.HashA == hashA && e.Hash.HashB == hashB {
			out = append(out, LocaleInfo{
				Name:     name,
				Locale:   e.Hash.Locale,
				Platform: e.Hash.Platform,
			})
		}
	}

	return out, nil
}

// matchMpqMask runs a case-insensitive glob match on MPQ-style paths. `*` and
// `?` are honored; backslashes are normalized to forward slashes so callers can
// pass either separator.
func matchMpqMask(mask, name string) bool {
	mask = strings.ToLower(strings.ReplaceAll(mask, "\\", "/"))
	name = strings.ToLower(strings.ReplaceAll(name, "\\", "/"))

	ok, err := path.Match(mask, name)
	if err == nil && ok {
		return true
	}

	// Fallback: simple `*substr*` containment for non-`path.Match`-friendly
	// masks (e.g. masks with embedded path separators that path.Match treats
	// strictly).
	if strings.HasPrefix(mask, "*") && strings.HasSuffix(mask, "*") {
		needle := strings.Trim(mask, "*")
		if needle != "" && strings.Contains(name, needle) {
			return true
		}
	}

	return false
}
