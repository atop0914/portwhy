// Package netns names the network namespace this process runs in.
//
// It exists because "nothing holds this port" is only ever a statement about one
// namespace: a container has its own, and a process holding 8080 on the host is
// invisible from inside it. Reporting the namespace turns a silent scope into a
// stated one.
//
// What this package refuses to do is as important as what it reads. It cannot
// see another namespace, and it cannot prove that its own is the machine's
// initial one: inside a container pid 1 is the container's init, so "the same
// namespace as pid 1" is a measurement of the boundary between this process and
// pid 1 — not a claim about the host.
package netns

import (
	"fmt"
	"strconv"
	"strings"
)

// DefaultRoot is where Linux mounts procfs.
const DefaultRoot = "/proc"

// SelfLink and PIDOneLink are the two links read, relative to the procfs root.
const (
	selfLink   = "self/ns/net"
	pidOneLink = "1/ns/net"
)

// SameAsPIDOne is the answer to one question only: does this process share a
// network namespace with the process this pid namespace calls 1?
//
// The zero value means the comparison could not be made. It is deliberately not
// named "initial": a container's pid 1 is the container's init, so equality here
// proves the absence of a boundary between the two processes and nothing about
// the host.
type SameAsPIDOne uint8

const (
	// PIDOneUnknown means one of the two links could not be read, so no
	// comparison was made.
	PIDOneUnknown SameAsPIDOne = iota
	// PIDOneSame means both links were read and name the same namespace.
	PIDOneSame
	// PIDOneDifferent means both links were read and name different
	// namespaces: this process is in a namespace pid 1 is not in.
	PIDOneDifferent
)

// Identity is one reading of this process's network namespace.
type Identity struct {
	// Inode is the number in net:[...]. It is 0 when nothing was read, and it
	// is never invented.
	Inode uint64
	// Self is the link target exactly as the kernel spelled it, so a report can
	// be compared against `readlink /proc/self/ns/net` by hand.
	Self string
	// PIDOne is pid 1's link target, empty when it could not be read.
	PIDOne string
	// Same is the comparison, and SameErr says why there is no comparison.
	Same    SameAsPIDOne
	SameErr string
	// Path is the link this process's namespace was read from.
	Path string
	// Err is why no inode was obtained; non-empty means Inode is 0.
	Err string
}

// Known reports whether this process's namespace was really read.
func (i Identity) Known() bool {
	return i.Err == "" && i.Inode != 0
}

// Describe is the scope phrase a report prints: the namespace, what the
// comparison with pid 1 found, or the reason there is nothing to print.
func (i Identity) Describe() string {
	if !i.Known() {
		if i.Err != "" {
			return fmt.Sprintf("this process's network namespace could not be read (%s): %s", i.Path, i.Err)
		}
		return "this process's network namespace was not read"
	}
	head := i.Self + ", this process's network namespace"
	switch i.Same {
	case PIDOneSame:
		return head + ", the same one pid 1 runs in"
	case PIDOneDifferent:
		return fmt.Sprintf("%s, a different one from pid 1's (%s)", head, i.PIDOne)
	}
	if i.SameErr != "" {
		return fmt.Sprintf("%s; whether pid 1 runs in it could not be read: %s", head, i.SameErr)
	}
	return head
}

// parseLink turns "net:[4026531840]" into the inode.
//
// Only that exact shape is accepted. A link that does not parse is not a
// namespace this tool understands, and inventing an inode for it would put a
// number in a report that nobody can look up.
func parseLink(target string) (uint64, error) {
	text := strings.TrimSpace(target)
	inner, ok := strings.CutPrefix(text, "net:[")
	if !ok {
		return 0, fmt.Errorf("%q is not a network namespace link", text)
	}
	inner, ok = strings.CutSuffix(inner, "]")
	if !ok {
		return 0, fmt.Errorf("%q is not a network namespace link", text)
	}
	inode, err := strconv.ParseUint(inner, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%q does not name a namespace inode", text)
	}
	if inode == 0 {
		return 0, fmt.Errorf("%q names inode 0, which no namespace has", text)
	}
	return inode, nil
}
