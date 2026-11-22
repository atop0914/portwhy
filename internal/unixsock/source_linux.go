//go:build linux

package unixsock

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// DefaultDir is where the kernel keeps the table.
const DefaultDir = "/proc/net"

// TableName is the file inside DefaultDir.
const TableName = "unix"

// Read reads dir/unix.
//
// A missing file is ErrTableMissing and an unreadable one is a plain error: the
// caller cannot answer either way, but only one of them is a fact about the
// kernel rather than about our access to it.
func Read(dir string) Table {
	t := Table{Name: TableName}
	path := filepath.Join(dir, TableName)
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			t.Err = fmt.Errorf("%w: %s", ErrTableMissing, path)
		} else {
			t.Err = fmt.Errorf("unixsock: open %s: %w", path, err)
		}
		return t
	}
	// Read-only descriptor: a close error cannot change what was parsed.
	defer func() { _ = f.Close() }()

	socks, err := Parse(TableName, f)
	if err != nil {
		t.Err = err
		return t
	}
	t.Sockets = socks
	return t
}
