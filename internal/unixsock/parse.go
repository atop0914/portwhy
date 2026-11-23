// Package unixsock reads and inspects unix domain socket names.
//
// It exists because a unix socket failure is not a port failure: there is no
// port, no listen state in the tcp sense, and a bind() that fails says nothing
// about who is holding what. What it does have is the failure mode no port has:
// the socket file outlives the process, and bind() keeps failing until someone
// removes it. That case is the reason this package is separate from procnet.
//
// The parse half is a pure function over an io.Reader so the fixtures are real
// captures; the inspect half touches the filesystem and is kept apart from the
// judgement, which only ever sees what this package measured.
package unixsock

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// ErrNoHeader is returned for a file whose first line is not the column header.
// Returning zero rows for it would read as "nothing is bound", which is the one
// answer this package must never invent.
var ErrNoHeader = errors.New("unixsock: table has no header line")

// ErrTableMissing means this kernel does not expose /proc/net/unix at all.
// It is kept apart from a read failure because the two mean different things:
// one is a fact about the kernel, the other about our access to it.
var ErrTableMissing = errors.New("unixsock: table not provided by this kernel")

// ErrUnsupported is returned on platforms without /proc/net/unix.
var ErrUnsupported = errors.New("unixsock: unix socket tables are only available on Linux")

// Type is the socket type column: what kind of unix socket this is.
type Type uint16

const (
	TypeStream    Type = 0x0001
	TypeDgram     Type = 0x0002
	TypeSeqPacket Type = 0x0005
)

func (t Type) String() string {
	switch t {
	case TypeStream:
		return "stream"
	case TypeDgram:
		return "dgram"
	case TypeSeqPacket:
		return "seqpacket"
	}
	return fmt.Sprintf("UNKNOWN(0x%04x)", uint16(t))
}

// State is the St column. The names are the kernel's SS_* values.
//
// Note what is missing: there is no LISTEN here. A listening unix socket is
// unconnected with the SO_ACCEPTCON flag set, which is why Listen is a separate
// field and not a state value.
type State uint8

const (
	StateUnconnected   State = 0x01
	StateConnecting    State = 0x02
	StateConnected     State = 0x03
	StateDisconnecting State = 0x04
)

func (s State) String() string {
	switch s {
	case StateUnconnected:
		return "UNCONNECTED"
	case StateConnecting:
		return "CONNECTING"
	case StateConnected:
		return "CONNECTED"
	case StateDisconnecting:
		return "DISCONNECTING"
	}
	return fmt.Sprintf("UNKNOWN(0x%02x)", uint8(s))
}

// soAcceptConn is the flag the kernel sets on a socket that has called listen().
// It is the unix equivalent of the TCP LISTEN state and the only way to tell a
// bound-and-listening socket from a bound-and-not-listening one.
const soAcceptConn uint32 = 0x00010000

// Socket is one row of /proc/net/unix.
type Socket struct {
	// Name is the Path column exactly as the kernel printed it. For an abstract
	// socket it starts with '@'; for a filesystem socket it is the path.
	//
	// It is empty for sockets that are not bound to a name (socketpair, accepted
	// connections). Those rows are real and are kept: dropping them would make
	// the reader believe the table only ever contains names.
	Name string
	// Type, State, Flags and Inode are the kernel's own columns.
	Type  Type
	State State
	Flags uint32
	Inode uint64
}

// Abstract reports whether this socket lives in the abstract namespace.
//
// The '@' prefix is how the kernel spells it, and it is the whole distinction: an
// abstract socket has no file, so nothing about it can be learned from the
// filesystem, and a path with the same text is a different socket. Verified on a
// live kernel: binding "@name" and then "/name" both succeed.
func (s Socket) Abstract() bool { return strings.HasPrefix(s.Name, "@") }

// Listening reports whether the socket called listen(). For a unix socket this is
// the only difference between "bound" and "accepting connections" — bind() fails
// for both while the name exists.
func (s Socket) Listening() bool { return s.Flags&soAcceptConn != 0 }

// Table is the result of reading /proc/net/unix. Err is per table, so a missing
// file (a kernel without unix sockets, or a non-Linux host) stays
// distinguishable from an empty one.
type Table struct {
	Name    string
	Sockets []Socket
	Err     error
}

// Bound reports whether the table was read successfully.
func (t Table) Bound() bool { return t.Err == nil }

// Missing reports whether the kernel does not offer the table at all, as
// opposed to the table existing and this process failing to read it. A kernel
// built without unix sockets and a procfs this process may not open both leave
// the question unanswered, but they are not the same fact.
func (t Table) Missing() bool { return errors.Is(t.Err, ErrTableMissing) }

// Parse reads /proc/net/unix.
//
// An unparsable line is an error, never a skipped line: a parser that drops what
// it does not understand reports "no one holds this name" for a table it only
// half read.
func Parse(name string, r io.Reader) ([]Socket, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 1<<20)

	line := 0
	sawHeader := false
	var out []Socket
	for sc.Scan() {
		line++
		raw := sc.Text()
		if !sawHeader {
			if strings.HasPrefix(strings.TrimSpace(raw), "Num") {
				sawHeader = true
				continue
			}
			return nil, fmt.Errorf("%w: line %d is %q", ErrNoHeader, line, raw)
		}
		text := strings.TrimSpace(raw)
		if text == "" {
			continue
		}
		s, err := parseRow(text)
		if err != nil {
			return nil, fmt.Errorf("unixsock: line %d: %w: %q", line, err, raw)
		}
		out = append(out, s)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("unixsock: read %s: %w", name, err)
	}
	if !sawHeader {
		return nil, ErrNoHeader
	}
	return out, nil
}

// Field offsets in a /proc/net/unix row.
const (
	fieldFlags = 3
	fieldType  = 4
	fieldState = 5
	fieldInode = 6
	fieldPath  = 7
	// minFields is the last column that carries meaning for us; a row without a
	// path stops at the inode.
	minFields = fieldInode + 1
)

func parseRow(text string) (Socket, error) {
	f := strings.Fields(text)
	if len(f) < minFields {
		return Socket{}, fmt.Errorf("want at least %d fields, got %d", minFields, len(f))
	}
	flags, err := strconv.ParseUint(f[fieldFlags], 16, 32)
	if err != nil {
		return Socket{}, fmt.Errorf("flags %q is not hex", f[fieldFlags])
	}
	typ, err := strconv.ParseUint(f[fieldType], 16, 16)
	if err != nil {
		return Socket{}, fmt.Errorf("type %q is not hex", f[fieldType])
	}
	state, err := strconv.ParseUint(f[fieldState], 16, 8)
	if err != nil {
		return Socket{}, fmt.Errorf("state %q is not hex", f[fieldState])
	}
	inode, err := strconv.ParseUint(f[fieldInode], 10, 64)
	if err != nil {
		return Socket{}, fmt.Errorf("inode %q is not a number", f[fieldInode])
	}

	s := Socket{
		Type:  Type(typ),
		State: State(state),
		Flags: uint32(flags),
		Inode: inode,
	}
	if len(f) > fieldPath {
		// The path is the rest of the line and may contain spaces, so the columns
		// are not enough: joining the tail with single spaces preserves the name
		// the kernel printed (a name with two consecutive spaces is possible, and
		// this is the one place where that detail is visible).
		s.Name = strings.Join(f[fieldPath:], " ")
	}
	return s, nil
}
