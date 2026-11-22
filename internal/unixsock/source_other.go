//go:build !linux

package unixsock

import "runtime"

// DefaultDir exists so callers do not need a build tag to name it.
const DefaultDir = "/proc/net"

// TableName mirrors the Linux name so callers compile everywhere.
const TableName = "unix"

// Read fails on every non-Linux platform, and fails loudly.
//
// The alternative — an empty table — would be read by the judgement as "nothing
// holds this name", which on macOS and Windows is simply false. A tool that
// cannot see has to say so.
func Read(dir string) Table {
	return Table{
		Name: TableName,
		Err:  errUnsupported(),
	}
}

func errUnsupported() error {
	return &unsupportedError{goos: runtime.GOOS}
}

type unsupportedError struct{ goos string }

func (e *unsupportedError) Error() string {
	return ErrUnsupported.Error() + " (this is " + e.goos + ")"
}

func (e *unsupportedError) Is(target error) bool { return target == ErrUnsupported }
