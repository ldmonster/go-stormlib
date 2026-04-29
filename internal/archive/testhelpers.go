package archive

import "github.com/ldmonster/go-stormlib/internal/mpq"

// PersistHeaderAndTablesForTest is an exported wrapper around persistHeaderAndTables
// for use by storm-package tests that need to inject/mutate tables.
func (a *Archive) PersistHeaderAndTablesForTest(
	h mpq.Header,
	hashes []mpq.HashEntry,
	blocks []mpq.BlockEntry,
) error {
	return a.persistHeaderAndTables(h, hashes, blocks)
}
