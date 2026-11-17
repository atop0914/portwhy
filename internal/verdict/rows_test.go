package verdict

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/atop0914/portwhy/internal/procnet"
)

// errUnreadable stands in for a permission error on a kernel table: the shape of
// the failure does not matter to the judgement, only that it is not ErrTableMissing.
var errUnreadable = errors.New("permission denied")

// An unrecognised state code is a hole in the evidence, not a row to be counted.
// Folding it into "occupied" would claim an occupation nobody can describe;
// folding it into "free" would be worse.
func TestUnknownStateCodeDegradesToUnknown(t *testing.T) {
	tables := []procnet.Table{table("tcp", procnet.TCP, procnet.V4,
		sock(procnet.State(0x7f), "127.0.0.1", 8080, procnet.TCP))}
	v := Explain(query("127.0.0.1", 8080, procnet.TCP), tables, Env{})
	if v.Kind != KindUnknown {
		t.Fatalf("kind = %v, want unknown (a row whose meaning is unknown cannot support an answer)", v.Kind)
	}
	if !hasReason(v, ReasonUnknownState) {
		t.Error("missing unknown-state-code reason")
	}
}

// A listener still settles the question even if another row is unreadable: the
// listener alone explains EADDRINUSE, so degrading to unknown would be hiding a
// fact the tool actually has.
func TestKnownBlockerOutranksUnknownState(t *testing.T) {
	tables := []procnet.Table{table("tcp", procnet.TCP, procnet.V4,
		sock(procnet.State(0x7f), "127.0.0.1", 8080, procnet.TCP),
		sock(procnet.StateListen, "127.0.0.1", 8080, procnet.TCP))}
	v := Explain(query("127.0.0.1", 8080, procnet.TCP), tables, Env{})
	if v.Kind != KindListening {
		t.Fatalf("kind = %v, want listening", v.Kind)
	}
}

// A CLOSE row is a socket the kernel has already unhashed: it does not hold the
// port, so it must not be handed to the user as somebody to go kill. It is still
// disclosed, because a report that silently drops a row the user can see in
// /proc/net/tcp is a report they stop trusting.
func TestReleasedRowIsDisclosedButNotAHolder(t *testing.T) {
	ln := sock(procnet.StateClose, "127.0.0.1", 8080, procnet.TCP)
	ln.Inode = 777
	tables := []procnet.Table{table("tcp", procnet.TCP, procnet.V4, ln)}

	v := Explain(query("127.0.0.1", 8080, procnet.TCP), tables,
		Env{Lookup: func(procnet.Socket) []Owner { return []Owner{{PID: 9, Comm: "gone", FD: 5}} }})

	if v.Kind != KindFree {
		t.Fatalf("kind = %v, want free (the kernel released the port)", v.Kind)
	}
	if len(v.Findings) != 0 {
		t.Errorf("findings = %v, want none: a released socket is not a holder", v.Findings)
	}
	if !hasReason(v, ReasonTeardown) {
		t.Error("missing row-being-destroyed reason: the row was dropped without saying so")
	}
	// The reverse of "no row matched": a row did match, so claiming nothing was
	// found would contradict the table the user is looking at.
	if hasReason(v, ReasonNoSockets) {
		t.Error("claims no-sockets-found although a row on the port was seen")
	}
}

// A listener plus a row being torn down: the answer is the listener, and the
// teardown is mentioned without being allowed to change anything.
func TestReleasedRowDoesNotDisturbAListener(t *testing.T) {
	tables := []procnet.Table{table("tcp", procnet.TCP, procnet.V4,
		sock(procnet.StateClose, "127.0.0.1", 8080, procnet.TCP),
		sock(procnet.StateListen, "127.0.0.1", 8080, procnet.TCP))}
	v := Explain(query("127.0.0.1", 8080, procnet.TCP), tables, Env{})
	if v.Kind != KindListening {
		t.Fatalf("kind = %v, want listening", v.Kind)
	}
	if len(v.Findings) != 1 || v.Findings[0].Socket.State != procnet.StateListen {
		t.Errorf("findings = %v, want just the listener", v.Findings)
	}
	if !hasReason(v, ReasonTeardown) {
		t.Error("missing row-being-destroyed reason")
	}
}

// The caveat belongs on the answer it can invalidate and nowhere else. If it
// appeared on every report it would be noise; if it appeared on none, a "free"
// answer would be claiming more than the data source can support.
func TestOnlyFreeCarriesTheUnlistedBindingCaveat(t *testing.T) {
	free := Explain(query("127.0.0.1", 8080, procnet.TCP),
		[]procnet.Table{table("tcp", procnet.TCP, procnet.V4)}, Env{})
	if !hasReason(free, ReasonUnlistedBinding) {
		t.Error(`free answer without the bind-without-listen caveat`)
	}

	taken := Explain(query("127.0.0.1", 8080, procnet.TCP),
		[]procnet.Table{table("tcp", procnet.TCP, procnet.V4,
			sock(procnet.StateListen, "127.0.0.1", 8080, procnet.TCP))}, Env{})
	if hasReason(taken, ReasonUnlistedBinding) {
		t.Error("listening answer carries the free-answer caveat")
	}
}

// TIME_WAIT must not be swept into the teardown bucket. The kernel has released
// the descriptor, but the 4-tuple is still reserved, which is exactly the
// distinction this tool exists to make.
func TestTimeWaitIsReservationNotTeardown(t *testing.T) {
	tables := []procnet.Table{table("tcp", procnet.TCP, procnet.V4,
		sock(procnet.StateTimeWait, "127.0.0.1", 8080, procnet.TCP))}
	v := Explain(query("127.0.0.1", 8080, procnet.TCP), tables, Env{})
	if v.Kind != KindTimeWaitOnly {
		t.Fatalf("kind = %v, want time-wait-only", v.Kind)
	}
	if len(v.Findings) != 1 {
		t.Fatalf("findings = %d, want 1: a TIME_WAIT row is the evidence", len(v.Findings))
	}
	if hasReason(v, ReasonTeardown) {
		t.Error("TIME_WAIT reported as a socket being destroyed")
	}
}

// Every state the table calls "options decide" must reach occupied-non-listening,
// and every one of them must be measured here rather than sampled: the whole
// point of the table is that the twelve codes behave predictably.
func TestEveryBoundStateClassifiesAsOccupation(t *testing.T) {
	for _, s := range procnet.KnownStates() {
		switch s.Binding() {
		case procnet.EffectOptionsDecide:
			tables := []procnet.Table{table("tcp", procnet.TCP, procnet.V4,
				sock(s, "127.0.0.1", 8080, procnet.TCP))}
			v := Explain(query("127.0.0.1", 8080, procnet.TCP), tables, Env{})
			want := KindOccupiedNonListening
			if s == procnet.StateTimeWait {
				want = KindTimeWaitOnly
			}
			if v.Kind != want {
				t.Errorf("%v: kind = %v, want %v", s, v.Kind, want)
			}
		case procnet.EffectBlocks:
			tables := []procnet.Table{table("tcp", procnet.TCP, procnet.V4,
				sock(s, "127.0.0.1", 8080, procnet.TCP))}
			if v := Explain(query("127.0.0.1", 8080, procnet.TCP), tables, Env{}); v.Kind != KindListening {
				t.Errorf("%v: kind = %v, want listening", s, v.Kind)
			}
		}
	}
}

// classify is documented to skip teardown rows even when a caller bypasses
// Explain. That guard is only worth having if it is exercised, so it is: the
// expected answer is "free", not "occupied".
func TestClassifyIgnoresReleasedRows(t *testing.T) {
	findings := []Finding{{Socket: sock(procnet.StateClose, "127.0.0.1", 8080, procnet.TCP)}}
	kind, unrecognised := classify(findings)
	if kind != KindFree {
		t.Errorf("kind = %v, want free", kind)
	}
	if len(unrecognised) != 0 {
		t.Errorf("unrecognised = %v, want none (CLOSE is a known state)", unrecognised)
	}
}

func TestMatchCodesDescribeEachKindOfNeighbour(t *testing.T) {
	v4Query := query("127.0.0.1", 8080, procnet.TCP)
	cases := []struct {
		name string
		s    procnet.Socket
		want MatchCode
	}{
		{"same address", sock(procnet.StateListen, "127.0.0.1", 8080, procnet.TCP), MatchMatched},
		{"wildcard covers the query", sock(procnet.StateListen, "0.0.0.0", 8080, procnet.TCP), MatchMatched},
		{"released row on the address", sock(procnet.StateClose, "127.0.0.1", 8080, procnet.TCP), MatchReleased},
		{"other port", sock(procnet.StateListen, "127.0.0.1", 8081, procnet.TCP), MatchOtherPort},
		{"other proto", sock(procnet.StateListen, "127.0.0.1", 8080, procnet.UDP), MatchOtherProto},
		{"other family", sock(procnet.StateListen, "::1", 8080, procnet.TCP), MatchOtherFamily},
		{"v6 wildcard listener", sock(procnet.StateListen, "::", 8080, procnet.TCP), MatchWildcardShadowed},
		{"v6 wildcard time-wait is not a shadow", sock(procnet.StateTimeWait, "::", 8080, procnet.TCP), MatchOtherFamily},
		{"other specific address", sock(procnet.StateListen, "10.1.2.3", 8080, procnet.TCP), MatchOtherAddress},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := matchCode(c.s, v4Query); got != c.want {
				t.Errorf("matchCode = %q, want %q", got, c.want)
			}
		})
	}
}

// The mirror of wildcard-shadowed must not exist: a 0.0.0.0 listener never
// occupies an IPv6 address, so calling it a shadow would invent a conflict.
func TestIPv4WildcardIsNotAShadowForIPv6(t *testing.T) {
	got := matchCode(sock(procnet.StateListen, "0.0.0.0", 8080, procnet.TCP),
		query("::1", 8080, procnet.TCP))
	if got != MatchOtherFamily {
		t.Errorf("matchCode = %q, want %q", got, MatchOtherFamily)
	}
}

// The load-bearing claim of --all: seeing the neighbours cannot move the answer.
// It is asserted over a matrix of shapes, and on the kind rather than on the
// rendered text, because the text is allowed to grow a section.
func TestAllRowsNeverChangeTheJudgement(t *testing.T) {
	shapes := map[string][]procnet.Table{
		"empty":              {table("tcp", procnet.TCP, procnet.V4)},
		"listener":           {table("tcp", procnet.TCP, procnet.V4, sock(procnet.StateListen, "127.0.0.1", 8080, procnet.TCP))},
		"neighbour port":     {table("tcp", procnet.TCP, procnet.V4, sock(procnet.StateListen, "127.0.0.1", 8081, procnet.TCP))},
		"neighbour address":  {table("tcp", procnet.TCP, procnet.V4, sock(procnet.StateListen, "10.9.9.9", 8080, procnet.TCP))},
		"other proto":        {table("udp", procnet.UDP, procnet.V4, sock(procnet.StateListen, "127.0.0.1", 8080, procnet.UDP))},
		"v6 wildcard shadow": {table("tcp6", procnet.TCP, procnet.V6, sock(procnet.StateListen, "::", 8080, procnet.TCP))},
		"time-wait":          {table("tcp", procnet.TCP, procnet.V4, sock(procnet.StateTimeWait, "127.0.0.1", 8080, procnet.TCP))},
		"close-wait":         {table("tcp", procnet.TCP, procnet.V4, sock(procnet.StateCloseWait, "127.0.0.1", 8080, procnet.TCP))},
		"released":           {table("tcp", procnet.TCP, procnet.V4, sock(procnet.StateClose, "127.0.0.1", 8080, procnet.TCP))},
		"unreadable":         {{Name: "tcp", Proto: procnet.TCP, Family: procnet.V4, Err: errUnreadable}},
		"listener + noise": {table("tcp", procnet.TCP, procnet.V4,
			sock(procnet.StateListen, "127.0.0.1", 8080, procnet.TCP),
			sock(procnet.StateListen, "127.0.0.1", 8081, procnet.TCP),
			sock(procnet.StateEstablished, "10.0.0.1", 8080, procnet.TCP))},
	}
	q := query("127.0.0.1", 8080, procnet.TCP)
	for name, tables := range shapes {
		t.Run(name, func(t *testing.T) {
			plain := Explain(q, tables, Env{})
			all := ExplainAll(q, tables, Env{})
			if plain.Kind != all.Kind {
				t.Fatalf("kind with --all = %v, without = %v", all.Kind, plain.Kind)
			}
			if len(plain.All) != 0 {
				t.Errorf("Explain produced %d rows; All must stay empty without ExplainAll", len(plain.All))
			}
			if len(all.Findings) != len(plain.Findings) {
				t.Errorf("findings differ: %d with --all, %d without", len(all.Findings), len(plain.Findings))
			}
		})
	}
}

func TestAllRowsListNeighboursWithTheirCode(t *testing.T) {
	tables := []procnet.Table{
		table("tcp", procnet.TCP, procnet.V4,
			sock(procnet.StateListen, "127.0.0.1", 8080, procnet.TCP),
			sock(procnet.StateListen, "127.0.0.1", 8081, procnet.TCP)),
		table("udp", procnet.UDP, procnet.V4, sock(procnet.StateListen, "127.0.0.1", 8080, procnet.UDP)),
	}
	v := ExplainAll(query("127.0.0.1", 8080, procnet.TCP), tables, Env{})
	if len(v.All) != 2 {
		t.Fatalf("rows = %d, want 2", len(v.All))
	}
	if v.All[0].Match != MatchMatched {
		t.Errorf("first row = %q, want matched first", v.All[0].Match)
	}
	if v.All[1].Match != MatchOtherProto {
		t.Errorf("second row = %q, want other-proto", v.All[1].Match)
	}
}

// Rows must come out in the same order twice. A listing whose rows swap between
// runs cannot be diffed, and diffing two runs is how people use --all.
func TestAllRowsAreOrderedReproducibly(t *testing.T) {
	tables := []procnet.Table{table("tcp", procnet.TCP, procnet.V4,
		sock(procnet.StateEstablished, "10.0.0.1", 8080, procnet.TCP),
		sock(procnet.StateListen, "127.0.0.1", 8080, procnet.TCP),
		sock(procnet.StateTimeWait, "192.168.1.1", 8080, procnet.TCP))}
	q := query("127.0.0.1", 8080, procnet.TCP)
	first := ExplainAll(q, tables, Env{}).All
	second := ExplainAll(q, tables, Env{}).All
	if len(first) != 3 {
		t.Fatalf("rows = %d, want 3", len(first))
	}
	for i := range first {
		if first[i].Socket.Local.IP != second[i].Socket.Local.IP || first[i].Match != second[i].Match {
			t.Fatalf("row %d changed between runs: %v then %v", i, first[i], second[i])
		}
	}
}

// The rows carry owners too: "who is on the other address" is the next question
// after "why is that row not the one". A nil lookup must leave them empty rather
// than fabricated.
func TestAllRowsCarryOwnersOnlyWhenLookedUp(t *testing.T) {
	s := sock(procnet.StateListen, "127.0.0.1", 8080, procnet.TCP)
	s.Inode = 4242
	tables := []procnet.Table{table("tcp", procnet.TCP, procnet.V4, s)}
	q := query("127.0.0.1", 8080, procnet.TCP)

	if got := ExplainAll(q, tables, Env{}).All[0].Owners; len(got) != 0 {
		t.Errorf("owners = %v, want none when no lookup was given", got)
	}
	got := ExplainAll(q, tables, Env{
		Lookup: func(procnet.Socket) []Owner { return []Owner{{PID: 31, Comm: "svc", FD: 4}} },
	}).All[0].Owners
	if len(got) != 1 || got[0].PID != 31 || got[0].Role != RoleSole {
		t.Errorf("owners = %+v, want pid 31 as the sole holder", got)
	}
}

// A query on the wildcard must still find the specific holder: the two directions
// of bind() are not symmetric in code but they are in effect.
func TestAllRowsFromAWildcardQuery(t *testing.T) {
	tables := []procnet.Table{table("tcp", procnet.TCP, procnet.V4,
		sock(procnet.StateListen, "127.0.0.1", 8080, procnet.TCP))}
	v := ExplainAll(Query{Addr: procnet.Addr{IP: netip.IPv4Unspecified(), Port: 8080}, Proto: procnet.TCP},
		tables, Env{})
	if len(v.All) != 1 || v.All[0].Match != MatchMatched {
		t.Fatalf("rows = %+v, want one matched row", v.All)
	}
}
