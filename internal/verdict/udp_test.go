package verdict

import (
	"testing"

	"github.com/atop0914/portwhy/internal/procnet"
	"github.com/atop0914/portwhy/internal/sysctl"
)

// A bound UDP socket is the ordinary case, and the trap: its row is st=07, which
// the TCP table calls "already released". The answer has to be "bound", not
// "free" — a plain second bind() really does fail with EADDRINUSE.
func TestUDPBoundSocketIsBoundNotFree(t *testing.T) {
	tables := []procnet.Table{table("udp", procnet.UDP, procnet.V4,
		sock(procnet.StateClose, "127.0.0.1", 5353, procnet.UDP))}
	v := Explain(query("127.0.0.1", 5353, procnet.UDP), tables, Env{})
	if v.Kind != KindBound {
		t.Fatalf("kind = %v, want bound (st=07 in /proc/net/udp is a bound socket)", v.Kind)
	}
	if !hasReason(v, ReasonBound) {
		t.Error("missing socket-bound-to-address reason")
	}
	if hasReason(v, ReasonListener) {
		t.Error("udp answer claims a listener; udp has no listening state")
	}
	if hasReason(v, ReasonTeardown) {
		t.Error("udp bound socket reported as being destroyed")
	}
	if len(v.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(v.Findings))
	}
}

// A connected UDP socket holds the port as well (st=01, remote end set).
func TestUDPConnectedSocketIsBound(t *testing.T) {
	s := sock(procnet.StateEstablished, "127.0.0.1", 5353, procnet.UDP)
	s.Remote = procnet.Addr{IP: s.Local.IP, Port: 40000}
	tables := []procnet.Table{table("udp", procnet.UDP, procnet.V4, s)}
	v := Explain(query("127.0.0.1", 5353, procnet.UDP), tables, Env{})
	if v.Kind != KindBound {
		t.Fatalf("kind = %v, want bound", v.Kind)
	}
}

// The reverse assertion that keeps the two namespaces apart: a TCP listener on
// this port says nothing about a UDP bind, and the other way round.
func TestProtocolsDoNotLeakIntoEachOther(t *testing.T) {
	tcpListener := table("tcp", procnet.TCP, procnet.V4,
		sock(procnet.StateListen, "0.0.0.0", 5353, procnet.TCP))
	udpBound := table("udp", procnet.UDP, procnet.V4,
		sock(procnet.StateClose, "0.0.0.0", 5353, procnet.UDP))
	tables := []procnet.Table{tcpListener, udpBound}

	if v := Explain(query("127.0.0.1", 5353, procnet.UDP), tables, Env{}); v.Kind != KindBound {
		t.Errorf("udp question with a tcp listener present: kind = %v, want bound", v.Kind)
	}
	if v := Explain(query("127.0.0.1", 5353, procnet.TCP), tables, Env{}); v.Kind != KindListening {
		t.Errorf("tcp question with a udp socket present: kind = %v, want listening", v.Kind)
	}
}

// The bind-without-listen caveat is a TCP property: it describes a socket that
// called bind() and skipped listen(). UDP has no listen() to skip, and a bound
// UDP socket is listed in /proc/net/udp, so the caveat there would describe a
// hole that cannot exist.
func TestUDPFreeDoesNotBorrowTheTCPBindWithoutListenCaveat(t *testing.T) {
	tables := []procnet.Table{table("udp", procnet.UDP, procnet.V4)}
	v := Explain(query("127.0.0.1", 5353, procnet.UDP), tables, Env{})
	if v.Kind != KindFree {
		t.Fatalf("kind = %v, want free", v.Kind)
	}
	if hasReason(v, ReasonUnlistedBinding) {
		t.Error("udp free answer carries the tcp-only bind-without-listen caveat")
	}
	// The tcp answer on the same evidence still carries it: the caveat was not
	// deleted, it was scoped.
	tcp := Explain(query("127.0.0.1", 5353, procnet.TCP),
		[]procnet.Table{table("tcp", procnet.TCP, procnet.V4)}, Env{})
	if !hasReason(tcp, ReasonUnlistedBinding) {
		t.Error("tcp free answer lost the bind-without-listen caveat")
	}
}

// A state code this build does not place in the UDP vocabulary is a hole, not an
// occupation and not a release. LISTEN cannot occur in a UDP table; if it does,
// something is wrong with the evidence and the answer has to say so.
func TestUDPUnknownStateIsUnknownNotFree(t *testing.T) {
	tables := []procnet.Table{table("udp", procnet.UDP, procnet.V4,
		sock(procnet.StateListen, "127.0.0.1", 5353, procnet.UDP))}
	v := Explain(query("127.0.0.1", 5353, procnet.UDP), tables, Env{})
	if v.Kind != KindUnknown {
		t.Fatalf("kind = %v, want unknown", v.Kind)
	}
	if !hasReason(v, ReasonUnknownState) {
		t.Error("missing unknown-state-code reason")
	}
}

// A dual-stack UDP6 wildcard holds the IPv4 wildcard too, exactly like a TCP
// listener does. Missing it would produce a free answer about a port that cannot
// be bound — the failure this tool exists to prevent.
func TestUDPv6WildcardShadowIsJudged(t *testing.T) {
	tables := []procnet.Table{
		table("udp", procnet.UDP, procnet.V4),
		table("udp6", procnet.UDP, procnet.V6,
			sock(procnet.StateClose, "::", 5353, procnet.UDP)),
	}
	dual := Env{V6Only: sysctl.BindV6Only{State: sysctl.BindV6OnlyDualStack}}
	v := Explain(query("0.0.0.0", 5353, procnet.UDP), tables, dual)
	if v.Kind != KindBound {
		t.Fatalf("kind = %v, want bound (dual-stack [::] holds the ipv4 wildcard)", v.Kind)
	}
	if !hasReason(v, ReasonV6Shadow) {
		t.Error("missing ipv6-wildcard-holds-ipv4 reason")
	}
	if hasReason(v, ReasonListener) {
		t.Error("a udp shadow was reported as a listener")
	}

	// bindv6only=1: the same rows, the opposite answer, and the measurement has
	// to be visible in the report.
	v6Only := Env{V6Only: sysctl.BindV6Only{State: sysctl.BindV6OnlyIPv6Only}}
	v = Explain(query("0.0.0.0", 5353, procnet.UDP), tables, v6Only)
	if v.Kind != KindFree {
		t.Fatalf("kind = %v, want free with bindv6only=1", v.Kind)
	}
	if !hasReason(v, ReasonV6NoShadow) {
		t.Error("missing ipv6-wildcard-does-not-hold-ipv4 reason")
	}

	// Unreadable tunable: neither answer is available, and free is the one that
	// must not be guessed.
	v = Explain(query("0.0.0.0", 5353, procnet.UDP), tables, Env{})
	if v.Kind != KindUnknown {
		t.Fatalf("kind = %v, want unknown when bindv6only was not measured", v.Kind)
	}
}
