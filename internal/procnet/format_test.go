package procnet

import (
	"fmt"
	"math/rand"
	"net/netip"
	"strings"
	"testing"
)

// The expected strings below are the kernel's, not this package's: every pair is
// either copied from a capture (see the fixtures in parse_test.go) or a byte
// reversal of one that can be read off by hand. Nothing here was produced by
// running FormatAddr and pasting the output, because a test built that way only
// says the function still does what it did yesterday.
func TestFormatAddrSpellsWhatTheKernelSpells(t *testing.T) {
	cases := []struct {
		addr netip.Addr
		port uint16
		want string
	}{
		// Captured from a real listener on 127.0.0.1:37423 (0x922F).
		{netip.MustParseAddr("127.0.0.1"), 0x922F, "0100007F:922F"},
		// The wildcard row of every table; port zero is how a peer is spelled.
		{netip.MustParseAddr("0.0.0.0"), 0, "00000000:0000"},
		// 10.1.2.3 is 0A 01 02 03, and the kernel stores it backwards.
		{netip.MustParseAddr("10.1.2.3"), 8080, "0302010A:1F90"},
		// 192.168.1.1 = C0 A8 01 01.
		{netip.MustParseAddr("192.168.1.1"), 53, "0101A8C0:0035"},
		// Palindromic, so it cannot tell endianness apart — but it does catch a
		// dropped byte.
		{netip.MustParseAddr("255.255.255.255"), 65535, "FFFFFFFF:FFFF"},
		// Captured: [::] and ::1, little-endian per 32-bit word. ::1 is not
		// "...0001" at the end; it is 01000000, which is the one fact a
		// hand-rolled encoder gets wrong.
		{netip.MustParseAddr("::"), 0x1F90, "00000000000000000000000000000000:1F90"},
		{netip.MustParseAddr("::1"), 0x1F90, "00000000000000000000000001000000:1F90"},
		// 2001:db8::1 → words 20010db8 00000000 00000000 00000001, each reversed.
		{netip.MustParseAddr("2001:db8::1"), 443, "B80D0120000000000000000001000000:01BB"},
		// A v4-mapped address appears in tcp6 with ffff in the third word; this is
		// the shape that makes an IPv4 listener look like IPv6.
		{netip.MustParseAddr("::ffff:127.0.0.1"), 8080, "0000000000000000FFFF00000100007F:1F90"},
	}
	for _, c := range cases {
		got, err := FormatAddr(Addr{IP: c.addr, Port: c.port})
		if err != nil {
			t.Errorf("FormatAddr(%v): %v", c.addr, err)
			continue
		}
		if got != c.want {
			t.Errorf("FormatAddr(%v port %d) = %q, want %q", c.addr, c.port, got, c.want)
		}
	}
}

// A zero Addr has no family, and guessing one would spell "00000000" for an
// address the caller never supplied. An error is the only honest answer, the same
// way an unreadable table cannot become "free".
func TestFormatAddrRefusesAnAddressWithNoFamily(t *testing.T) {
	if s, err := FormatAddr(Addr{Port: 80}); err == nil {
		t.Fatalf("FormatAddr(zero IP) = %q, want an error", s)
	}
}

// testRow builds one table line. It goes through FormatAddr on purpose: a fixture
// written by hand can encode a layout the parser accepts and the kernel never
// emits, and then the two agree with each other and with nothing else.
func testRow(t *testing.T, local, remote Addr, state State, inode uint64) string {
	t.Helper()
	return fmt.Sprintf("   0: %s %s %02X 00000000:00000000 00:00000000 00000000     0        0 %d 1 0000000000000000 100 0 0 10 0",
		mustFormat(t, local), mustFormat(t, remote), uint8(state), inode)
}

func mustFormat(t *testing.T, a Addr) string {
	t.Helper()
	s, err := FormatAddr(a)
	if err != nil {
		t.Fatalf("FormatAddr(%v): %v", a, err)
	}
	return s
}

// addresses returns a deterministic set: the boundaries a byte reversal can get
// wrong (first byte, last byte, all bits) plus pseudo-random fills. The seed is
// fixed so a failure can be reproduced from the printed address alone.
func addresses() []netip.Addr {
	out := []netip.Addr{
		netip.AddrFrom4([4]byte{}),
		netip.AddrFrom4([4]byte{0xff, 0xff, 0xff, 0xff}),
		netip.AddrFrom4([4]byte{1, 0, 0, 0}),
		netip.AddrFrom4([4]byte{0, 0, 0, 1}),
		netip.AddrFrom4([4]byte{0, 0, 0xff, 0}),
		netip.IPv6Unspecified(),
		netip.IPv6Loopback(),
		netip.MustParseAddr("::ffff:0:0"),
		netip.MustParseAddr("2001:db8::1"),
	}
	r := rand.New(rand.NewSource(20261125)) // reproducible, and not a secret
	for i := 0; i < 250; i++ {
		var b4 [4]byte
		var b16 [16]byte
		r.Read(b4[:])
		r.Read(b16[:])
		out = append(out, netip.AddrFrom4(b4), netip.AddrFrom16(b16))
	}
	return out
}

func familyOf(ip netip.Addr) Family {
	if ip.Is4() {
		return V4
	}
	return V6
}

func familyWildcard(ip netip.Addr) netip.Addr {
	if ip.Is4() {
		return netip.AddrFrom4([4]byte{})
	}
	return netip.IPv6Unspecified()
}

// Format then Parse must give back the same address and port. The round trip goes
// through the public parser rather than calling the decoder directly, because the
// point of the encoder is that a generated fixture is a real row.
func TestFormatAddrRoundTripsThroughParse(t *testing.T) {
	for _, ip := range addresses() {
		for _, port := range []uint16{0, 1, 80, 0x922F, 65535} {
			local := Addr{IP: ip, Port: port}
			row := testRow(t, local, Addr{IP: familyWildcard(ip), Port: 0}, StateListen, 42)
			socks, err := Parse("tcp", TCP, familyOf(ip), strings.NewReader(headerTCP+"\n"+row+"\n"))
			if err != nil {
				t.Fatalf("Parse of %q: %v", row, err)
			}
			if len(socks) != 1 {
				t.Fatalf("Parse of %q gave %d rows, want 1", row, len(socks))
			}
			got := socks[0].Local
			if got.IP != ip || got.Port != port {
				t.Fatalf("round trip of %v port %d gave %v port %d (row %q)", ip, port, got.IP, got.Port, row)
			}
		}
	}
}

// The reverse direction: whatever a row spells must parse. No encoder output is
// allowed to be a line the parser rejects — that is the property a fixture
// generator depends on, and it is the one that breaks if the two sides drift.
func TestFormatAddrAlwaysProducesAParsableField(t *testing.T) {
	for _, ip := range addresses() {
		s := mustFormat(t, Addr{IP: ip, Port: 9})
		if _, err := parseHexAddr(s, familyOf(ip)); err != nil {
			t.Fatalf("parseHexAddr(%q) rejected what FormatAddr produced: %v", s, err)
		}
	}
}
