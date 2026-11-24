//go:build linux

package probe

import (
	"bytes"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

// heldPort returns an address a real listener is holding.
func heldPort(t *testing.T) (netip.AddrPort, net.Listener) {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ap := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(l.Addr().(*net.TCPAddr).Port))
	return ap, l
}

// freePort returns an address nothing holds, by asking the kernel for one and
// then giving it back.
func freePort(t *testing.T) netip.AddrPort {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ap := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(l.Addr().(*net.TCPAddr).Port))
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return ap
}

func TestBindOnHeldAddressIsAddrInUse(t *testing.T) {
	ap, l := heldPort(t)
	defer l.Close()

	a := Bind(ap, ModePlain)
	if a.Outcome != OutcomeAddrInUse {
		t.Fatalf("outcome = %s (%s %s), want %s", a.Outcome, a.Errno, a.Message, OutcomeAddrInUse)
	}
	if a.Errno != "EADDRINUSE" {
		t.Errorf("errno = %q, want EADDRINUSE", a.Errno)
	}
	if !a.Trustworthy() {
		t.Errorf("attempt not trustworthy: %q", a.Err)
	}
	if a.At.IsZero() {
		t.Error("attempt carries no timestamp")
	}
}

// The probe must leave nothing behind. If it held the address after returning,
// the next bind would fail and the tool would have caused the problem it
// reports on.
func TestBindReleasesTheAddressAndNeverListens(t *testing.T) {
	ap := freePort(t)
	for attempt := 0; attempt < 5; attempt++ {
		a := Bind(ap, ModePlain)
		if a.Outcome != OutcomeBound {
			t.Fatalf("outcome = %s (%s %s), want %s", a.Outcome, a.Errno, a.Message, OutcomeBound)
		}
	}
	// A listener needs the address back: with SO_REUSEADDR (which net.Listen
	// sets) this succeeds only if nothing holds it and nothing is listening.
	l, err := net.Listen("tcp4", ap.String())
	if err != nil {
		t.Fatalf("the probe kept the address: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// A closed connection leaves a TIME_WAIT reservation, and the difference between
// the two attempts is the answer "one socket option away".
func TestReuseAddrSucceedsWherePlainIsRefusedOnTimeWait(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ap := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(l.Addr().(*net.TCPAddr).Port))

	conn, err := net.Dial("tcp4", ap.String())
	if err != nil {
		l.Close()
		t.Fatalf("dial: %v", err)
	}
	server, err := l.Accept()
	if err != nil {
		l.Close()
		conn.Close()
		t.Fatalf("accept: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	// The side bound to the port must close first: TIME_WAIT lives on the side
	// that initiated the close, which is what makes the port reserved.
	if err := server.Close(); err != nil {
		t.Fatalf("close server side: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close client side: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		plain := Bind(ap, ModePlain)
		if plain.Outcome == OutcomeAddrInUse {
			reuse := Bind(ap, ModeReuseAddr)
			if reuse.Outcome != OutcomeBound {
				t.Fatalf("reuseaddr outcome = %s (%s %s), want %s", reuse.Outcome, reuse.Errno, reuse.Message, OutcomeBound)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the port never became reserved: plain outcome = %s", plain.Outcome)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestBindRefusesWhatItCannotAskAbout(t *testing.T) {
	cases := map[string]struct {
		target netip.AddrPort
		mode   Mode
		want   string
	}{
		"port zero": {
			target: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 0),
			mode:   ModePlain,
			want:   "port 0",
		},
		"scoped ipv6": {
			target: netip.MustParseAddrPort("[fe80::1%eth0]:8080"),
			mode:   ModePlain,
			want:   "scoped",
		},
		"unknown mode": {
			target: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 8080),
			mode:   Mode("reuseport"),
			want:   "unknown probe mode",
		},
	}
	for name, tc := range cases {
		a := Bind(tc.target, tc.mode)
		if a.Outcome != OutcomeNotRun {
			t.Errorf("%s: outcome = %s, want %s", name, a.Outcome, OutcomeNotRun)
		}
		if !strings.Contains(a.Err, tc.want) {
			t.Errorf("%s: err = %q, want it to mention %q", name, a.Err, tc.want)
		}
		if a.Trustworthy() {
			t.Errorf("%s: an attempt that did not run must not be evidence", name)
		}
	}
}

// Both must make both attempts, plain first: the report explains the difference
// between them, so the order it is presented in has to be fixed.
func TestBothMakesPlainThenReuseAddr(t *testing.T) {
	ap, l := heldPort(t)
	defer l.Close()

	got := Both(ap)
	if len(got) != 2 {
		t.Fatalf("attempts = %d, want 2", len(got))
	}
	if got[0].Mode != ModePlain || got[1].Mode != ModeReuseAddr {
		t.Fatalf("modes = %s, %s; want plain, reuseaddr", got[0].Mode, got[1].Mode)
	}
	for _, a := range got {
		if a.Outcome != OutcomeAddrInUse {
			t.Errorf("%s: outcome = %s, want %s", a.Mode, a.Outcome, OutcomeAddrInUse)
		}
	}
}

// A bind on a wildcard must not be refused by the probe machinery itself, and an
// IPv6 target must be expressible: the two families take different sockaddrs,
// and a mistake there would look exactly like "free".
func TestBindSpeaksBothFamilies(t *testing.T) {
	cases := map[string]netip.AddrPort{
		"ipv4 wildcard": netip.AddrPortFrom(netip.MustParseAddr("0.0.0.0"), portOf(t)),
		"ipv6 loopback": netip.AddrPortFrom(netip.MustParseAddr("::1"), portOf(t)),
	}
	for name, ap := range cases {
		a := Bind(ap, ModePlain)
		if a.Outcome == OutcomeNotRun {
			t.Errorf("%s: probe refused its own target: %s", name, a.Err)
		}
	}
}

// portOf returns a port that was free a moment ago, so the family test above is
// about address encoding and not about occupation.
func portOf(t *testing.T) uint16 {
	t.Helper()
	return freePort(t).Port()
}

// The probe must never call listen(): a listener completes handshakes on the
// user's behalf, and listen()+close() is indistinguishable from bind()+close()
// to every outside observer — a client that dials during the window cannot be
// asked afterwards. So the invariant is asserted where it is enforced, in the
// source, instead of being asserted about behaviour it cannot see.
//
// This is deliberately narrow: it would not catch a listener reached through a
// helper in another file, and it is not meant to. It catches the one edit that
// is tempting to make.
func TestProbeSourceNeverListens(t *testing.T) {
	src, err := os.ReadFile("bind_linux.go")
	if err != nil {
		t.Fatalf("read own source: %v", err)
	}
	for _, forbidden := range []string{"syscall.Listen(", "net.Listen("} {
		if bytes.Contains(src, []byte(forbidden)) {
			t.Errorf("the probe calls %s: binding is enough to learn the answer, listening is not ours to do", forbidden)
		}
	}
}

// heldUDP returns an address a real datagram socket is bound to.
func heldUDP(t *testing.T) (netip.AddrPort, net.PacketConn) {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen packet: %v", err)
	}
	ap := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(pc.LocalAddr().(*net.UDPAddr).Port))
	return ap, pc
}

// freeUDPPort asks the kernel for a datagram port and gives it back.
func freeUDPPort(t *testing.T) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen packet: %v", err)
	}
	ap := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(pc.LocalAddr().(*net.UDPAddr).Port))
	if err := pc.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return ap
}

func TestBindUDPOnHeldDatagramAddressIsAddrInUse(t *testing.T) {
	ap, pc := heldUDP(t)
	defer pc.Close()

	a := BindUDP(ap)
	if a.Outcome != OutcomeAddrInUse {
		t.Fatalf("outcome = %s (%s %s), want %s", a.Outcome, a.Errno, a.Message, OutcomeAddrInUse)
	}
	if a.Errno != "EADDRINUSE" {
		t.Errorf("errno = %q, want EADDRINUSE", a.Errno)
	}
	if !a.Trustworthy() {
		t.Errorf("attempt not trustworthy: %q", a.Err)
	}
}

// The two directions of the same claim: a stream bind and a datagram bind are
// independent namespaces, so neither may be reported as evidence about the
// other. Each half is exercised with a real socket, because a rule about
// namespaces cannot be checked against a table.
func TestTCPAndUDPBindsDoNotBlockEachOther(t *testing.T) {
	tcpAddr, ln := heldPort(t)
	defer ln.Close()
	if a := BindUDP(tcpAddr); a.Outcome != OutcomeBound {
		t.Fatalf("a tcp listener made the udp bind fail: %s (%s %s)", a.Outcome, a.Errno, a.Message)
	}

	udpAddr, pc := heldUDP(t)
	defer pc.Close()
	if a := Bind(udpAddr, ModePlain); a.Outcome != OutcomeBound {
		t.Fatalf("a bound udp socket made the tcp bind fail: %s (%s %s)", a.Outcome, a.Errno, a.Message)
	}
}

// Same rule as the stream probe: the address must be free again the instant the
// attempt returns, or the tool becomes the holder it is asked to find.
func TestBindUDPReleasesTheAddress(t *testing.T) {
	ap := freeUDPPort(t)
	for i := 0; i < 5; i++ {
		if a := BindUDP(ap); a.Outcome != OutcomeBound {
			t.Fatalf("attempt %d: outcome = %s (%s %s), want %s", i+1, a.Outcome, a.Errno, a.Message, OutcomeBound)
		}
	}
	pc, err := net.ListenPacket("udp4", ap.String())
	if err != nil {
		t.Fatalf("the probe kept the datagram address: %v", err)
	}
	if err := pc.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}
