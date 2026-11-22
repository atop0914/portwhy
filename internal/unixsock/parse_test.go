package unixsock

import (
	"strings"
	"testing"
)

// The header the kernel prints. Every row below is a real capture from a live
// kernel, including the inode numbers, so the parser is exercised by the shape it
// will actually see rather than by a tidied-up version of it.
const unixHeader = "Num       RefCount Protocol Flags    Type St Inode Path"

func parseFixture(t *testing.T, lines ...string) []Socket {
	t.Helper()
	socks, err := Parse("unix", strings.NewReader(unixHeader+"\n"+strings.Join(lines, "\n")+"\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return socks
}

func TestParseRealRows(t *testing.T) {
	socks := parseFixture(t,
		// A socket that called bind() and never listen(): flags 0, state 01.
		"0000000000000000: 00000002 00000000 00000000 0001 01 46893107 /tmp/day7-bound-only.sock",
		// The same socket after listen(): only the flag differs.
		"0000000000000000: 00000002 00000000 00010000 0001 01 46893111 /tmp/day7-listening.sock",
		// Abstract namespace.
		"0000000000000000: 00000002 00000000 00000000 0001 01 46893115 @day7-abstract",
		// A path with a space in it: the kernel prints it raw, so the name is the
		// rest of the line and not a single field.
		"0000000000000000: 00000002 00000000 00010000 0001 01 46898824 /tmp/day7 with space.sock",
		// An unnamed socket (socketpair, or an accepted connection): no Path
		// column at all.
		"0000000000000000: 00000003 00000000 00000000 0001 03 46899000",
	)
	if len(socks) != 5 {
		t.Fatalf("parsed %d rows, want 5", len(socks))
	}

	bound := socks[0]
	if bound.Name != "/tmp/day7-bound-only.sock" || bound.Inode != 46893107 {
		t.Errorf("row 0 = %+v", bound)
	}
	if bound.Listening() {
		t.Error("a socket that never called listen() reports Listening()")
	}
	if bound.Type != TypeStream || bound.State != StateUnconnected {
		t.Errorf("row 0 type/state = %v/%v, want stream/UNCONNECTED", bound.Type, bound.State)
	}

	listening := socks[1]
	if !listening.Listening() {
		t.Error("a socket with the SO_ACCEPTCON flag does not report Listening()")
	}
	if listening.State != StateUnconnected {
		t.Errorf("listening socket state = %v, want UNCONNECTED (listen() is a flag, not a state)", listening.State)
	}

	if !socks[2].Abstract() {
		t.Error("an @name is not reported as abstract")
	}
	if socks[2].Name != "@day7-abstract" {
		t.Errorf("abstract name = %q, want the kernel's spelling with the @", socks[2].Name)
	}
	if socks[0].Abstract() || socks[1].Abstract() {
		t.Error("a filesystem path is reported as abstract")
	}

	if socks[3].Name != "/tmp/day7 with space.sock" {
		t.Errorf("path with a space parsed as %q", socks[3].Name)
	}

	if socks[4].Name != "" {
		t.Errorf("an unnamed socket got the name %q", socks[4].Name)
	}
	if socks[4].State != StateConnected {
		t.Errorf("unnamed socket state = %v, want CONNECTED", socks[4].State)
	}
}

// A file whose first line is not the header is not this file. Returning zero rows
// would read as "nothing is bound", which is the answer that gets people to run a
// bind that fails.
func TestParseRefusesAFileWithoutTheHeader(t *testing.T) {
	if _, err := Parse("unix", strings.NewReader("0000000000000000: 00000002 00000000 00000000 0001 01 1 /tmp/x\n")); err == nil {
		t.Fatal("Parse accepted a table with no header")
	}
	if _, err := Parse("unix", strings.NewReader("")); err == nil {
		t.Fatal("Parse accepted an empty file")
	}
}

// One bad row fails the whole parse: a half-read table reported as complete is
// how "no one holds this name" gets printed for a name someone holds.
func TestParseRefusesABadRow(t *testing.T) {
	cases := map[string]string{
		"short row": "0000000000000000: 00000002 00000000",
		"bad flags": "0000000000000000: 00000002 00000000 zzzz 0001 01 1 /tmp/x",
		"bad type":  "0000000000000000: 00000002 00000000 00000000 zz 01 1 /tmp/x",
		"bad state": "0000000000000000: 00000002 00000000 00000000 0001 zz 1 /tmp/x",
		"bad inode": "0000000000000000: 00000002 00000000 00000000 0001 01 notanumber /tmp/x",
	}
	for name, row := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse("unix", strings.NewReader(unixHeader+"\n"+row+"\n")); err == nil {
				t.Fatalf("Parse accepted %q", row)
			}
		})
	}
}

// Codes this build does not know are named as unknown rather than guessed: a
// socket type or state invented here would be a description of something we did
// not understand.
func TestUnknownTypeAndStateAreNamedAsUnknown(t *testing.T) {
	if got := Type(0x0009).String(); !strings.HasPrefix(got, "UNKNOWN(0x") {
		t.Errorf("type 0x0009 prints %q", got)
	}
	if got := State(0x7f).String(); !strings.HasPrefix(got, "UNKNOWN(0x") {
		t.Errorf("state 0x7f prints %q", got)
	}
	for _, want := range []struct {
		typ Type
		str string
	}{
		{TypeStream, "stream"}, {TypeDgram, "dgram"}, {TypeSeqPacket, "seqpacket"},
	} {
		if got := want.typ.String(); got != want.str {
			t.Errorf("type 0x%04x = %q, want %q", uint16(want.typ), got, want.str)
		}
	}
	for _, want := range []struct {
		state State
		str   string
	}{
		{StateUnconnected, "UNCONNECTED"}, {StateConnecting, "CONNECTING"},
		{StateConnected, "CONNECTED"}, {StateDisconnecting, "DISCONNECTING"},
	} {
		if got := want.state.String(); got != want.str {
			t.Errorf("state 0x%02x = %q, want %q", uint8(want.state), got, want.str)
		}
	}
}
