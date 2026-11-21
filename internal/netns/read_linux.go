//go:build linux

package netns

import (
	"os"
	"path/filepath"
)

// Read reports the network namespace this process runs in, read from root
// (usually /proc).
//
// Both links are read in the same call so that the comparison is between two
// observations taken at nearly the same instant: a process that setns()'d in
// between would otherwise produce a report describing no moment at all. The
// failure of either read is kept as its own state — a namespace with no
// comparison is still worth printing, and a comparison with no namespace is
// worth stating as missing.
func Read(root string) Identity {
	id := Identity{Path: filepath.Join(root, selfLink)}

	target, err := os.Readlink(id.Path)
	if err != nil {
		id.Err = err.Error()
		return id
	}
	inode, err := parseLink(target)
	if err != nil {
		id.Err = err.Error()
		return id
	}
	id.Self, id.Inode = target, inode

	pidOnePath := filepath.Join(root, pidOneLink)
	pidOne, err := os.Readlink(pidOnePath)
	if err != nil {
		id.SameErr = err.Error()
		return id
	}
	inodeOne, err := parseLink(pidOne)
	if err != nil {
		id.SameErr = err.Error()
		return id
	}
	id.PIDOne = pidOne
	if inodeOne == inode {
		// Equality of the inode, not of the text: two spellings of the same
		// namespace are the same namespace, and the number is what the kernel
		// compares too.
		id.Same = PIDOneSame
	} else {
		id.Same = PIDOneDifferent
	}
	return id
}
