package verdict

import (
	"strings"
	"testing"

	"github.com/atop0914/portwhy/internal/probe"
	"github.com/atop0914/portwhy/internal/procnet"
	"github.com/atop0914/portwhy/internal/sysctl"
)

// v6only builds a measured value, the way internal/sysctl would hand one in.
// The path is the real one so that the details these tests assert on are the
// details a user reads.
func v6only(state sysctl.BindV6OnlyState, raw string) sysctl.BindV6Only {
	return sysctl.BindV6Only{State: state, Raw: raw, Path: "/proc/sys/net/ipv6/bindv6only"}
}

func dualStack() sysctl.BindV6Only { return v6only(sysctl.BindV6OnlyDualStack, "0\n") }
func ipv6Only() sysctl.BindV6Only  { return v6only(sysctl.BindV6OnlyIPv6Only, "1\n") }

func unreadableV6Only() sysctl.BindV6Only {
	return sysctl.BindV6Only{
		Path: "/proc/sys/net/ipv6/bindv6only",
		Err:  "open /proc/sys/net/ipv6/bindv6only: permission denied",
	}
}

// wildcardTables is the shape that made Day 1 answer "unknown": an IPv4 table
// with nothing on the port, and a [::] listener on it.
func wildcardTables() []procnet.Table {
	return []procnet.Table{
		table("tcp", procnet.TCP, procnet.V4),
		table("tcp6", procnet.TCP, procnet.V6, sock(procnet.StateListen, "::", 8080, procnet.TCP)),
	}
}

// The measurement is what turns "I cannot tell" into an answer, so the
// unreadable case has to keep saying "I cannot tell" — and it has to say why,
// with the file it tried.
func TestV6WildcardUnreadableStaysUnknownAndSaysWhy(t *testing.T) {
	v := Explain(query("127.0.0.1", 8080, procnet.TCP), wildcardTables(), Env{V6Only: unreadableV6Only()})
	if v.Kind != KindUnknown {
		t.Fatalf("kind = %v, want unknown", v.Kind)
	}
	detail, ok := reasonDetail(v, ReasonV6Wildcard)
	if !ok {
		t.Fatal("missing ipv6-wildcard-may-shadow-ipv4 reason")
	}
	if !strings.Contains(detail, "permission denied") {
		t.Errorf("detail %q does not carry the reason the read failed", detail)
	}
	if !strings.Contains(detail, "/proc/sys/net/ipv6/bindv6only") {
		t.Errorf("detail %q does not name the file it tried", detail)
	}
	if hasReason(v, ReasonV6Shadow) || hasReason(v, ReasonV6NoShadow) {
		t.Error("an unreadable value produced one of the answered sentences")
	}
}

// bindv6only=1: the wildcard is IPv6 only. The answer returns to free, and the
// measured value is printed — a number the verdict rests on has to be visible.
func TestV6WildcardDoesNotShadowWhenBindV6OnlyIsOne(t *testing.T) {
	v := Explain(query("127.0.0.1", 8080, procnet.TCP), wildcardTables(), Env{V6Only: ipv6Only()})
	if v.Kind != KindFree {
		t.Fatalf("kind = %v, want free: bindv6only=1 means [::] is not on IPv4", v.Kind)
	}
	if hasReason(v, ReasonV6Shadow) {
		t.Error("reported a shadow although bindv6only is 1")
	}
	if len(v.Findings) != 0 {
		t.Errorf("findings = %v, want none: the v6 wildcard does not hold this address", v.Findings)
	}
	detail, ok := reasonDetail(v, ReasonV6NoShadow)
	if !ok {
		t.Fatal("missing ipv6-wildcard-does-not-hold-ipv4 reason")
	}
	if !strings.Contains(detail, "= 1") {
		t.Errorf("detail %q does not print the measured value", detail)
	}
	if !strings.Contains(detail, "/proc/sys/net/ipv6/bindv6only") {
		t.Errorf("detail %q does not cite the source", detail)
	}
	// Free still owes the blind-spot caveat: the tunable answers the v6
	// question and nothing about sockets bound without listen().
	if !hasReason(v, ReasonUnlistedBinding) {
		t.Error("free answer lost the bind-without-listen caveat")
	}
}

// bindv6only=0: the wildcard is dual-stack, so it holds the IPv4 address. The
// row joins the findings with its owner, because "which process" is the next
// question and this row is the answer to it.
func TestV6WildcardShadowsWhenBindV6OnlyIsZero(t *testing.T) {
	shadow := sock(procnet.StateListen, "::", 8080, procnet.TCP)
	shadow.Inode = 9911
	tables := []procnet.Table{
		table("tcp", procnet.TCP, procnet.V4),
		table("tcp6", procnet.TCP, procnet.V6, shadow),
	}
	v := Explain(query("127.0.0.1", 8080, procnet.TCP), tables, Env{
		V6Only: dualStack(),
		Lookup: func(s procnet.Socket) []Owner {
			if s.Inode != 9911 {
				return nil
			}
			return []Owner{{PID: 4242, Comm: "nginx", FD: 6}}
		},
	})
	if v.Kind != KindListening {
		t.Fatalf("kind = %v, want listening: a dual-stack [::] holds the IPv4 address", v.Kind)
	}
	if len(v.Findings) != 1 || !v.Findings[0].Socket.Local.IP.IsUnspecified() {
		t.Fatalf("findings = %v, want the [::] row", v.Findings)
	}
	if got := v.Findings[0].Owners; len(got) != 1 || got[0].PID != 4242 {
		t.Errorf("owners = %v, want the listener's process: a shadow without a pid is a dead end", got)
	}
	detail, ok := reasonDetail(v, ReasonV6Shadow)
	if !ok {
		t.Fatal("missing ipv6-wildcard-holds-ipv4 reason")
	}
	if !strings.Contains(detail, "= 0") {
		t.Errorf("detail %q does not print the measured value", detail)
	}
	if !hasReason(v, ReasonV6PerSocket) {
		t.Error("the per-socket limit is missing: bindv6only is a default, not a property of that socket")
	}
	if hasReason(v, ReasonUnlistedBinding) {
		t.Error("a taken answer kept the free-only caveat")
	}
	if hasReason(v, ReasonNoSockets) {
		t.Error("reported no-sockets-found next to a row that holds the address")
	}
}

// An IPv4 listener settles the question no matter what the tunable says. If the
// read failed, the answer must not drop from "a listener holds it" to "I cannot
// tell" — that would trade a fact for a gap.
func TestV6WildcardUnreadableDoesNotDowngradeAKnownListener(t *testing.T) {
	tables := []procnet.Table{
		table("tcp", procnet.TCP, procnet.V4, sock(procnet.StateListen, "127.0.0.1", 8080, procnet.TCP)),
		table("tcp6", procnet.TCP, procnet.V6, sock(procnet.StateListen, "::", 8080, procnet.TCP)),
	}
	v := Explain(query("127.0.0.1", 8080, procnet.TCP), tables, Env{V6Only: unreadableV6Only()})
	if v.Kind != KindListening {
		t.Fatalf("kind = %v, want listening: an IPv4 listener is not a question about bindv6only", v.Kind)
	}
}

// The reverse of the shadow: a specific IPv6 address is a different address in
// every setting. Treating [::1] as covering 127.0.0.1 would be the false
// conflict that makes users uninstall the tool.
func TestSpecificIPv6ListenerNeverShadowsIPv4(t *testing.T) {
	tables := []procnet.Table{
		table("tcp", procnet.TCP, procnet.V4),
		table("tcp6", procnet.TCP, procnet.V6, sock(procnet.StateListen, "::1", 8080, procnet.TCP)),
	}
	for name, measured := range map[string]sysctl.BindV6Only{
		"dual-stack":   dualStack(),
		"ipv6-only":    ipv6Only(),
		"unreadable":   unreadableV6Only(),
		"not measured": {},
	} {
		t.Run(name, func(t *testing.T) {
			v := Explain(query("127.0.0.1", 8080, procnet.TCP), tables, Env{V6Only: measured})
			if v.Kind != KindFree {
				t.Fatalf("kind = %v, want free: [::1] is not 127.0.0.1, whatever the tunable says", v.Kind)
			}
			if hasReason(v, ReasonV6Wildcard) || hasReason(v, ReasonV6Shadow) || hasReason(v, ReasonV6NoShadow) {
				t.Errorf("reasons mention a wildcard that is not on this port: %v", v.Reasons)
			}
		})
	}
}

// A row in tcp6 holding ::ffff:127.0.0.1 is an IPv4 socket: it is the same
// binding, and a bind to 127.0.0.1 on that port fails. Comparing it as IPv6
// would answer "free" about a port that is plainly taken.
func TestIPv4MappedRowsAreComparedAsIPv4(t *testing.T) {
	t.Run("mapped holder, plain v4 query", func(t *testing.T) {
		tables := []procnet.Table{
			table("tcp", procnet.TCP, procnet.V4),
			table("tcp6", procnet.TCP, procnet.V6, sock(procnet.StateListen, "::ffff:127.0.0.1", 8080, procnet.TCP)),
		}
		v := Explain(query("127.0.0.1", 8080, procnet.TCP), tables, Env{V6Only: ipv6Only()})
		if v.Kind != KindListening {
			t.Fatalf("kind = %v, want listening: ::ffff:127.0.0.1 holds 127.0.0.1", v.Kind)
		}
	})

	t.Run("mapped query, plain v4 holder", func(t *testing.T) {
		tables := []procnet.Table{
			table("tcp", procnet.TCP, procnet.V4, sock(procnet.StateListen, "127.0.0.1", 8080, procnet.TCP)),
			table("tcp6", procnet.TCP, procnet.V6),
		}
		v := Explain(query("::ffff:127.0.0.1", 8080, procnet.TCP), tables, Env{V6Only: ipv6Only()})
		if v.Kind != KindListening {
			t.Fatalf("kind = %v, want listening: the mapped target is the same address", v.Kind)
		}
	})

	t.Run("mapped neighbour on another port stays irrelevant", func(t *testing.T) {
		tables := []procnet.Table{
			table("tcp", procnet.TCP, procnet.V4),
			table("tcp6", procnet.TCP, procnet.V6, sock(procnet.StateListen, "::ffff:127.0.0.1", 8081, procnet.TCP)),
		}
		if v := Explain(query("127.0.0.1", 8080, procnet.TCP), tables, Env{V6Only: ipv6Only()}); v.Kind != KindFree {
			t.Fatalf("kind = %v, want free", v.Kind)
		}
	})
}

// Same tables, same measurement, twice: the answer and the rows behind it have
// to be identical, or the report cannot be diffed between runs.
func TestV6AnswersAreReproducible(t *testing.T) {
	for name, measured := range map[string]sysctl.BindV6Only{
		"dual-stack": dualStack(),
		"ipv6-only":  ipv6Only(),
	} {
		t.Run(name, func(t *testing.T) {
			first := Explain(query("127.0.0.1", 8080, procnet.TCP), wildcardTables(), Env{V6Only: measured})
			second := Explain(query("127.0.0.1", 8080, procnet.TCP), wildcardTables(), Env{V6Only: measured})
			if first.Kind != second.Kind {
				t.Fatalf("kind changed between runs: %v then %v", first.Kind, second.Kind)
			}
			if len(first.Reasons) != len(second.Reasons) {
				t.Fatalf("reasons changed: %v then %v", first.Reasons, second.Reasons)
			}
			for i := range first.Reasons {
				if first.Reasons[i] != second.Reasons[i] {
					t.Fatalf("reason %d changed: %v then %v", i, first.Reasons[i], second.Reasons[i])
				}
			}
			if len(first.Findings) != len(second.Findings) {
				t.Fatalf("findings changed: %v then %v", first.Findings, second.Findings)
			}
			for i := range first.Findings {
				if first.Findings[i].Socket.Local != second.Findings[i].Socket.Local {
					t.Fatalf("finding %d changed", i)
				}
			}
		})
	}
}

// The per-socket caveat says "this port might still be bindable". A refused
// plain bind has just measured that it is not, so the caveat must go — keeping
// it would send the reader to try what the tool already tried.
func TestRefusedProbeRemovesThePerSocketCaveat(t *testing.T) {
	v := Explain(query("127.0.0.1", 8080, procnet.TCP), wildcardTables(), Env{
		V6Only: dualStack(),
		Probe:  []probe.Attempt{attempt(probe.ModePlain, probe.OutcomeAddrInUse, "EADDRINUSE")},
	})
	if v.Kind != KindListening {
		t.Fatalf("kind = %v, want listening: a refused bind corroborates the shadow", v.Kind)
	}
	if hasReason(v, ReasonV6PerSocket) {
		t.Error("the caveat survived a bind that proved the port is un-bindable")
	}
	if !hasReason(v, ReasonProbeRefused) {
		t.Error("missing probe-bind-was-refused reason")
	}
}

// The mirror: a probe that could not run contradicts nothing, so the caveat has
// to stay. This is the difference between "measured and refused" and "never
// measured".
func TestDeniedProbeKeepsThePerSocketCaveat(t *testing.T) {
	v := Explain(query("127.0.0.1", 8080, procnet.TCP), wildcardTables(), Env{
		V6Only: dualStack(),
		Probe:  []probe.Attempt{attempt(probe.ModePlain, probe.OutcomeNotPermitted, "EACCES")},
	})
	if !hasReason(v, ReasonV6PerSocket) {
		t.Error("the caveat was removed by a probe that never reached the address")
	}
	if v.Kind != KindListening {
		t.Errorf("kind = %v, want listening: an EACCES probe says nothing about occupation", v.Kind)
	}
}

// The case the caveat exists for, measured: the wildcard looked dual-stack and a
// bind succeeded, so that listener set IPV6_V6ONLY for itself. The report must
// say this, and must not keep the claim the probe just disproved — two
// contradictory sentences in one report are worse than a gap.
func TestProbeRevealsTheWildcardOptedOut(t *testing.T) {
	v := Explain(query("127.0.0.1", 8080, procnet.TCP), wildcardTables(), Env{
		V6Only: dualStack(),
		Probe:  []probe.Attempt{attempt(probe.ModePlain, probe.OutcomeBound, "")},
	})
	if v.Kind != KindUnknown {
		t.Fatalf("kind = %v, want unknown: a successful bind may not promote the answer to free", v.Kind)
	}
	if hasReason(v, ReasonV6Shadow) {
		t.Error("the disproved shadow claim is still in the report")
	}
	if hasReason(v, ReasonV6PerSocket) {
		t.Error("the caveat survived the measurement that settled it")
	}
	detail, ok := reasonDetail(v, ReasonV6OptOut)
	if !ok {
		t.Fatal("missing ipv6-wildcard-turned-out-ipv6-only reason")
	}
	if !strings.Contains(detail, "[::]:8080") {
		t.Errorf("detail %q does not name the socket", detail)
	}
	if hasReason(v, ReasonProbeConflict) {
		t.Error("reported a stale table: both observations are of the same instant, and the reason differs")
	}
	if hasReason(v, ReasonUnlistedBinding) {
		t.Error("an unknown answer kept the free-only caveat")
	}
}

// A v4 listener plus a shadow: then a successful bind really does contradict the
// table, and the generic conflict sentence is the right one.
func TestProbeConflictWithARealIPv4ListenerStaysAConflict(t *testing.T) {
	tables := []procnet.Table{
		table("tcp", procnet.TCP, procnet.V4, sock(procnet.StateListen, "127.0.0.1", 8080, procnet.TCP)),
		table("tcp6", procnet.TCP, procnet.V6, sock(procnet.StateListen, "::", 8080, procnet.TCP)),
	}
	v := Explain(query("127.0.0.1", 8080, procnet.TCP), tables, Env{
		V6Only: dualStack(),
		Probe:  []probe.Attempt{attempt(probe.ModePlain, probe.OutcomeBound, "")},
	})
	if v.Kind != KindUnknown {
		t.Fatalf("kind = %v, want unknown", v.Kind)
	}
	if !hasReason(v, ReasonProbeConflict) {
		t.Error("missing table-and-probe-disagree reason")
	}
	if hasReason(v, ReasonV6OptOut) {
		t.Error("blamed the v6 socket although an IPv4 listener was also in the table")
	}
}
