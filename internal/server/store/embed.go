package store

import (
	"io/fs"
)

func mustSub(f fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(f, dir)
	if err != nil {
		panic(err) // embedded path is static
	}
	return sub
}

// Migrations returns the embedded migration files (for tests and tooling).
func Migrations() fs.FS { return mustSub(migrations, "migrations") }
