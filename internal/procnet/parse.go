// Package procnet parses the kernel's socket tables (/proc/net/tcp{,6},
// /proc/net/udp{,6}).
//
// Everything here is a pure function over an io.Reader: the shape of those
// files is the only thing this package knows, and it does not touch the
// filesystem. That matters for testing — the fixtures are real captures, and
// the same code parses them and the live kernel.
//
// The one rule that runs through the whole package: an unparsable line is an
// error, never a skipped line. A parser that drops what it does not understand
// reports "no one holds this port" for a table it only half read, and that
// sentence is the one a user will act on.
package procnet

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

// Proto is the transport protocol a table describes.
type Proto uint8

const (
	// TCP is SOCK_STREAM over IP.
	TCP Proto = iota + 1
	// UDP is SOCK_DGRAM over IP.
	UDP
)

func (p Proto) String() string {
	switch p {
	case TCP:
		return "tcp"
	case UDP:
		return "udp"
	}
	return fmt.Sprintf("proto(%d)", uint8(p))
}

// Family is the address family of a table.
type Family uint8

const (
	// V4 is IPv4.
	V4 Family = iota + 1
	// V6 is IPv6.
	V6
)

func (f Family) String() string {
	switch f {
	case V4:
		return "ipv4"
	case V6:
		return "ipv6"
	}
	return fmt.Sprintf("family(%d)", uint8(f))
}

// State is the TCP state as encoded in the table's "st" column.
//
// Unknown codes are kept rather than rejected: the kernel has added states
// before (NEW_SYN_RECV) and a new one must not break the parser. They surface as
// UNKNOWN(0x..) so a reader can tell "the tool does not know this state" from
// "this socket is in a state I understand".
type State uint8

const (
	StateEstablished State = 0x01
	StateSynSent     State = 0x02
	StateSynRecv     State = 0x03
	StateFinWait1    State = 0x04
	StateFinWait2    State = 0x05
	StateTimeWait    State = 0x06
	StateClose       State = 0x07
	StateCloseWait   State = 0x08
	StateLastAck     State = 0x09
	StateListen      State = 0x0A
	StateClosing     State = 0x0B
	StateNewSynRecv  State = 0x0C
)

// The names and the bind() consequences live in state.go: one table, so a state
// cannot be named here and forgotten there.

// Addr is one endpoint as the table spells it: an address and a port.
type Addr struct {
	IP   netip.Addr
	Port uint16
}

func (a Addr) String() string {
	if !a.IP.IsValid() {
		return fmt.Sprintf("<invalid>:%d", a.Port)
	}
	return netip.AddrPortFrom(a.IP, a.Port).String()
}

// IsWildcard reports whether the address matches every local address of its
// family. It is the single most important predicate in this package: a wildcard
// holder shadows every specific address, and missing that is how a conflict
// report ends up saying "free" about a port that cannot be bound.
func (a Addr) IsWildcard() bool {
	return a.IP.IsValid() && a.IP.IsUnspecified()
}

// Socket is one row of a table.
type Socket struct {
	Proto  Proto
	Family Family
	State  State
	Local  Addr
	Remote Addr
	UID    uint32
	Inode  uint64
	// Table is the file this row came from, kept so a report can point at its
	// evidence instead of asking the reader to trust it.
	Table string
}

// Table is the result of reading one file. Err is set per table, not globally:
// a kernel without IPv6 has no tcp6 file, and that is "this table does not
// exist", which is different from "this table is empty".
type Table struct {
	Name    string
	Proto   Proto
	Family  Family
	Sockets []Socket
	Err     error
}

// Missing reports whether the kernel does not offer this table at all, as
// opposed to the table existing and this process failing to read it. The
// distinction is reported to the user because only one of the two is something
// they can do anything about.
func (t Table) Missing() bool { return errors.Is(t.Err, ErrTableMissing) }

// ErrNoHeader is returned for a table whose first line is not the column
// header. Every kernel socket table starts with one; its absence means we are
// reading something else (a truncated capture, an empty file, a different
// format), and returning zero sockets for it would be a silent lie.
var ErrNoHeader = errors.New("procnet: table has no header line")

// ErrTableMissing means the kernel does not expose this table at all (a build
// without IPv6 has no tcp6). It is reported separately from "read failed"
// because the two lead to different conclusions: one is a fact about the
// kernel, the other is a fact about our access to it.
var ErrTableMissing = errors.New("procnet: table not provided by this kernel")

// ParseError carries the line number, because a bare "invalid syntax" on a
// 200-line /proc file helps nobody.
type ParseError struct {
	Line int
	Text string
	Err  error
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("procnet: line %d: %v: %q", e.Line, e.Err, e.Text)
}

func (e *ParseError) Unwrap() error { return e.Err }

// Parse reads one socket table.
//
// name is the table's name ("tcp6"), used only to label the rows.
func Parse(name string, proto Proto, family Family, r io.Reader) ([]Socket, error) {
	sc := bufio.NewScanner(r)
	// /proc rows are short, but a captured file may carry extra columns from a
	// newer kernel; 1 MiB is far past anything legitimate.
	sc.Buffer(make([]byte, 0, 4096), 1<<20)

	line := 0
	sawHeader := false
	var out []Socket
	for sc.Scan() {
		line++
		raw := sc.Text()
		if !sawHeader {
			if strings.HasPrefix(strings.TrimSpace(raw), "sl") {
				sawHeader = true
				continue
			}
			return nil, &ParseError{Line: line, Text: raw, Err: ErrNoHeader}
		}
		text := strings.TrimSpace(raw)
		if text == "" {
			continue
		}
		s, err := parseRow(name, proto, family, text)
		if err != nil {
			return nil, &ParseError{Line: line, Text: raw, Err: err}
		}
		out = append(out, s)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("procnet: read %s: %w", name, err)
	}
	if !sawHeader {
		return nil, &ParseError{Line: 0, Text: "", Err: ErrNoHeader}
	}
	return out, nil
}

// Field offsets in a /proc/net row. Columns after "inode" are kernel-version
// specific and deliberately ignored.
const (
	fieldLocal = 1
	fieldState = 3
	fieldUID   = 7
	fieldInode = 9
	minFields  = fieldInode + 1

	// maxFields is where a line stops being a line. A tcp row has 17 columns on
	// 6.x and had 15 on older kernels, so 20 is three columns of headroom; a
	// future kernel adds columns one at a time, never seventeen at once. A line
	// carrying two rows' worth of fields is not a newer kernel, it is a lost
	// newline — a truncated capture, a concatenated file, a hand-written
	// fixture — and accepting it would answer for the first row while silently
	// dropping the second, whose port would then look free. Rejecting the line
	// costs a table and yields unknown; accepting it yields a confident lie.
	maxFields = 2 * minFields
)

func parseRow(name string, proto Proto, family Family, text string) (Socket, error) {
	f := strings.Fields(text)
	if len(f) < minFields {
		return Socket{}, fmt.Errorf("want at least %d fields, got %d", minFields, len(f))
	}
	if len(f) > maxFields {
		return Socket{}, fmt.Errorf("want at most %d fields, got %d (two rows on one line?)", maxFields, len(f))
	}

	local, err := parseHexAddr(f[fieldLocal], family)
	if err != nil {
		return Socket{}, fmt.Errorf("local address: %w", err)
	}
	remote, err := parseHexAddr(f[2], family)
	if err != nil {
		return Socket{}, fmt.Errorf("remote address: %w", err)
	}
	state, err := parseHex8(f[fieldState])
	if err != nil {
		return Socket{}, fmt.Errorf("state: %w", err)
	}
	uid, err := strconv.ParseUint(f[fieldUID], 10, 32)
	if err != nil {
		return Socket{}, fmt.Errorf("uid: %w", err)
	}
	inode, err := strconv.ParseUint(f[fieldInode], 10, 64)
	if err != nil {
		return Socket{}, fmt.Errorf("inode: %w", err)
	}

	return Socket{
		Proto:  proto,
		Family: family,
		State:  State(state),
		Local:  local,
		Remote: remote,
		UID:    uint32(uid),
		Inode:  inode,
		Table:  name,
	}, nil
}

func parseHex8(s string) (uint8, error) {
	v, err := strconv.ParseUint(s, 16, 8)
	if err != nil {
		return 0, fmt.Errorf("%q is not a hex byte", s)
	}
	return uint8(v), nil
}

// parseHexAddr decodes "AABBCCDD:PORT" (IPv4) or 32 hex chars plus port (IPv6).
//
// Both are stored little-endian, and for IPv6 that is per 32-bit word, not for
// the whole address: "::1" appears as 00000000000000000000000001000000.
func parseHexAddr(s string, family Family) (Addr, error) {
	host, portText, ok := strings.Cut(s, ":")
	if !ok {
		return Addr{}, fmt.Errorf("%q has no port separator", s)
	}
	port, err := strconv.ParseUint(portText, 16, 16)
	if err != nil {
		return Addr{}, fmt.Errorf("port %q is not hex", portText)
	}

	switch family {
	case V4:
		if len(host) != 8 {
			return Addr{}, fmt.Errorf("%q is not 8 hex chars", host)
		}
		b, err := decodeHex(host)
		if err != nil {
			return Addr{}, err
		}
		reverse(b)
		return Addr{IP: netip.AddrFrom4([4]byte(b)), Port: uint16(port)}, nil
	case V6:
		if len(host) != 32 {
			return Addr{}, fmt.Errorf("%q is not 32 hex chars", host)
		}
		b, err := decodeHex(host)
		if err != nil {
			return Addr{}, err
		}
		for i := 0; i < 16; i += 4 {
			reverse(b[i : i+4])
		}
		return Addr{IP: netip.AddrFrom16([16]byte(b)), Port: uint16(port)}, nil
	}
	return Addr{}, fmt.Errorf("unsupported family %v", family)
}

func decodeHex(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("%q has an odd number of hex chars", s)
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		v, err := strconv.ParseUint(s[i*2:i*2+2], 16, 8)
		if err != nil {
			return nil, fmt.Errorf("%q is not hex", s)
		}
		out[i] = byte(v)
	}
	return out, nil
}

func reverse(b []byte) {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
}
