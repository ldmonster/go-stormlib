// Package storm is the public Go API for go-stormlib.
//
// It provides MPQ archive open/read/list/extract operations and a narrow set
// of write/create/mutation primitives, with behavior aligned to StormLib
// where practical. Compatibility deltas are documented in
// docs/compatibility.md at the repo root.
//
// Typical use:
//
//	a, err := storm.Open("example.mpq", storm.OpenOptions{})
//	if err != nil { ... }
//	defer a.Close()
//
//	files, _ := a.ListFiles()
//	data, _ := a.ReadFileByName("path\\inside.archive", 0, 0)
//
// See the repository [README] and the per-method doc comments for details.
//
// [README]: https://github.com/ldmonster/go-stormlib
package storm
