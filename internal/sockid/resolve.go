// Package sockid maps a socket inode to the processes that hold it.
//
// The kernel's socket tables name an inode and nothing else; the process that
// owns it is only discoverable by walking /proc/<pid>/fd and reading the
// symlinks. That walk can be partial — another user's process is not readable
// without privilege — and a partial walk that is reported as complete is worse
// than no walk at all: it turns "I could not look" into "nobody holds it".
//
// So every Index carries how much of the system it actually saw.
package sockid

import (
	"strconv"
	"strings"
)

// DefaultRoot is where process state lives on Linux. It is declared here, not
// in the Linux-only file, so callers need no build tag to name it.
const DefaultRoot = "/proc"

// Holder is one open file descriptor of one process.
type Holder struct {
	PID  int
	Comm string
	FD   int
}

// Index is the result of one walk of /proc.
type Index struct {
	// ByInode maps a socket inode to every descriptor pointing at it. More than
	// one holder is normal: a forked worker inherits its parent's listener, and
	// naming only the parent would send the user to kill the wrong process.
	ByInode map[uint64][]Holder

	// ProcsRead is how many processes we looked inside.
	ProcsRead int
	// ProcsDenied is how many processes refused us (typically another user's).
	// When this is not zero, an empty result means "not visible", not "absent".
	ProcsDenied int
	// ProcsSkipped counts entries that vanished or were not processes during
	// the walk. A busy machine churns; this is bookkeeping, not a worry.
	ProcsSkipped int
}

// Complete reports whether every process on the machine was readable.
func (i *Index) Complete() bool { return i != nil && i.ProcsDenied == 0 }

// Holders returns the holders of one inode. Inode 0 (TIME_WAIT and friends) has
// no file behind it, so no process can hold it.
func (i *Index) Holders(inode uint64) []Holder {
	if i == nil || inode == 0 {
		return nil
	}
	return i.ByInode[inode]
}

func (i *Index) add(inode uint64, h Holder) {
	if i.ByInode == nil {
		i.ByInode = make(map[uint64][]Holder)
	}
	i.ByInode[inode] = append(i.ByInode[inode], h)
}

// ParseSockLink extracts the inode from a /proc/<pid>/fd symlink target.
//
// Only "socket:[N]" is a socket. A pipe, an anon_inode, a regular file: all of
// them are skipped rather than guessed at.
func ParseSockLink(target string) (uint64, bool) {
	const prefix = "socket:["
	if !strings.HasPrefix(target, prefix) || !strings.HasSuffix(target, "]") {
		return 0, false
	}
	n, err := strconv.ParseUint(target[len(prefix):len(target)-1], 10, 64)
	if err != nil || n == 0 {
		return 0, false
	}
	return n, true
}
