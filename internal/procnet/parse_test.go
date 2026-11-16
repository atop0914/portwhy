package procnet

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// The fixtures below are verbatim captures from a Linux 6.x kernel, taken by a
// program that opened a listener, connected to it, then closed both. Only the
// trailing padding spaces are stripped. They are stored rather than generated so
// that the column layout under test is the one the kernel actually writes.
const (
	headerTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode`

	// A listener plus its two live children. Note the FIN_WAIT1 child on line 2
	// carries inode 0: only sockets that own a file descriptor have an inode,
	// which is why "no inode" is not "no socket".
	tableListening = headerTCP + "\n" + `   0: 0100007F:922F 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 29841669 1 0000000000000000 100 0 0 10 0
   1: 0100007F:922F 0100007F:8EC4 04 00000001:00000000 01:00000014 00000000     0        0 0 3 0000000000000000 20 0 0 10 -1
   2: 0100007F:8EC4 0100007F:922F 08 00000000:00000000 02:000005DC 00000000     0        0 29841673 4 0000000000000000 20 4 31 10 -1`

	// After both sides closed: one TIME_WAIT row on the listener's port, inode 0.
	tableTimeWait = headerTCP + "\n" + `   0: 0100007F:922F 0100007F:8EC4 06 00000000:00000000 03:00001752 00000000     0        0 0 3 0000000000000000`

	// IPv6 rows: "::" as a wildcard listener and "::1" as a peer.
	headerTCP6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode`
	tableIPv6  = headerTCP6 + "\n" + `   0: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 41234 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000001000000:1F90 00000000000000000000000001000000:C350 01 00000000:00000000 00:00000000 00000000     0        0 41235 1 0000000000000000 20 4 30 10 -1`
)

func TestParseListenerAndChildren(t *testing.T) {
	socks, err := Parse("tcp", TCP, V4, strings.NewReader(tableListening))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(socks) != 3 {
		t.Fatalf("got %d rows, want 3", len(socks))
	}

	ln := socks[0]
	if ln.State != StateListen {
		t.Errorf("row 0 state = %v, want LISTEN", ln.State)
	}
	want := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 0x922F)
	if got := netip.AddrPortFrom(ln.Local.IP, ln.Local.Port); got != want {
		t.Errorf("row 0 local = %v, want %v", got, want)
	}
	if ln.Inode != 29841669 {
		t.Errorf("row 0 inode = %d, want 29841669", ln.Inode)
	}
	if ln.Table != "tcp" || ln.Proto != TCP || ln.Family != V4 {
		t.Errorf("row 0 provenance = %q/%v/%v", ln.Table, ln.Proto, ln.Family)
	}

	// The child in FIN_WAIT1 has no inode. If the parser were to invent one, a
	// later layer would look up a holder that does not exist and the report
	// would name the wrong process.
	if got := socks[1]; got.Inode != 0 || got.State != StateFinWait1 {
		t.Errorf("row 1 = inode %d state %v, want inode 0 / FIN_WAIT1", got.Inode, got.State)
	}
}

func TestParseTimeWaitHasNoOwnerInode(t *testing.T) {
	socks, err := Parse("tcp", TCP, V4, strings.NewReader(tableTimeWait))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(socks) != 1 {
		t.Fatalf("got %d rows, want 1", len(socks))
	}
	if socks[0].State != StateTimeWait {
		t.Fatalf("state = %v, want TIME_WAIT", socks[0].State)
	}
	if socks[0].Inode != 0 {
		t.Errorf("TIME_WAIT inode = %d, want 0 (the kernel keeps no file for it)", socks[0].Inode)
	}
	// It still has an address and a port: the row is about a real reservation,
	// even though no process owns it any more.
	if socks[0].Local.Port != 0x922F {
		t.Errorf("TIME_WAIT local port = %d, want %d", socks[0].Local.Port, 0x922F)
	}
}

func TestParseIPv6LittleEndianPerWord(t *testing.T) {
	socks, err := Parse("tcp6", TCP, V6, strings.NewReader(tableIPv6))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(socks) != 2 {
		t.Fatalf("got %d rows, want 2", len(socks))
	}
	if !socks[0].Local.IsWildcard() {
		t.Errorf("row 0 local = %v, want the :: wildcard", socks[0].Local)
	}
	if got, want := socks[1].Local.IP, netip.MustParseAddr("::1"); got != want {
		t.Errorf("row 1 local ip = %v, want %v", got, want)
	}
	if socks[1].State != StateEstablished {
		t.Errorf("row 1 state = %v, want ESTABLISHED", socks[1].State)
	}
}

func TestParseRejectsMalformedTables(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want error
	}{
		{"empty input", "", ErrNoHeader},
		{"no header", "   0: 0100007F:922F 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1", ErrNoHeader},
		{"header only is not an error", headerTCP + "\n", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			socks, err := Parse("tcp", TCP, V4, strings.NewReader(c.in))
			if c.want != nil {
				if !errors.Is(err, c.want) {
					t.Fatalf("err = %v, want %v", err, c.want)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
			if len(socks) != 0 {
				t.Fatalf("got %d rows, want 0", len(socks))
			}
		})
	}
}

func TestParseRowErrorsCarryLineNumber(t *testing.T) {
	cases := []struct{ name, row string }{
		{"too few fields", `   0: 0100007F:922F 00000000:0000 0A 00000000:00000000`},
		{"port not hex", `   0: 0100007F:ZZZZ 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1`},
		{"address wrong length", `   0: 0100007FAA:922F 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1`},
		{"inode not a number", `   0: 0100007F:922F 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 notanumber`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse("tcp", TCP, V4, strings.NewReader(headerTCP+"\n"+c.row+"\n"))
			if err == nil {
				t.Fatal("err = nil, want a parse error")
			}
			var pe *ParseError
			if !errors.As(err, &pe) {
				t.Fatalf("err = %T (%v), want *ParseError", err, err)
			}
			if pe.Line != 2 {
				t.Errorf("line = %d, want 2 (the header is line 1)", pe.Line)
			}
		})
	}
}

func TestParseUnknownStateIsNamedNotRejected(t *testing.T) {
	row := `   0: 0100007F:922F 00000000:0000 0D 00000000:00000000 00:00000000 00000000 0 0 1`
	socks, err := Parse("tcp", TCP, V4, strings.NewReader(headerTCP+"\n"+row+"\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := socks[0].State.String(); got != "UNKNOWN(0x0d)" {
		t.Errorf("state string = %q, want UNKNOWN(0x0d)", got)
	}
}

func TestAddrIsWildcard(t *testing.T) {
	cases := []struct {
		addr netip.Addr
		want bool
	}{
		{netip.MustParseAddr("0.0.0.0"), true},
		{netip.MustParseAddr("::"), true},
		{netip.MustParseAddr("127.0.0.1"), false},
		{netip.MustParseAddr("::1"), false},
	}
	for _, c := range cases {
		if got := (Addr{IP: c.addr, Port: 80}).IsWildcard(); got != c.want {
			t.Errorf("IsWildcard(%v) = %v, want %v", c.addr, got, c.want)
		}
	}
}
