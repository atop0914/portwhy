package verdict

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/atop0914/portwhy/internal/procnet"
)

func sock(state procnet.State, ip string, port uint16, proto procnet.Proto) procnet.Socket {
	addr := netip.MustParseAddr(ip)
	return procnet.Socket{
		Proto:  proto,
		Family: familyOf(addr),
		State:  state,
		Local:  procnet.Addr{IP: addr, Port: port},
	}
}

func familyOf(a netip.Addr) procnet.Family {
	if a.Is4() {
		return procnet.V4
	}
	return procnet.V6
}

func table(name string, proto procnet.Proto, fam procnet.Family, socks ...procnet.Socket) procnet.Table {
	out := make([]procnet.Socket, 0, len(socks))
	for _, s := range socks {
		s.Table = name
		out = append(out, s)
	}
	return procnet.Table{Name: name, Proto: proto, Family: fam, Sockets: out}
}

func query(ip string, port uint16, proto procnet.Proto) Query {
	return Query{Addr: procnet.Addr{IP: netip.MustParseAddr(ip), Port: port}, Proto: proto}
}

func hasReason(v Verdict, code string) bool {
	for _, r := range v.Reasons {
		if r.Code == code {
			return true
		}
	}
	return false
}

func TestExplainFreeWhenNothingHoldsIt(t *testing.T) {
	v := Explain(query("127.0.0.1", 8080, procnet.TCP),
		[]procnet.Table{table("tcp", procnet.TCP, procnet.V4)}, Env{})
	if v.Kind != KindFree {
		t.Fatalf("kind = %v, want free", v.Kind)
	}
	if !hasReason(v, ReasonNoSockets) {
		t.Error("missing no-sockets-found reason")
	}
	if len(v.Findings) != 0 {
		t.Errorf("findings = %v, want none", v.Findings)
	}
}

func TestExplainListenerOnExactAddress(t *testing.T) {
	tables := []procnet.Table{table("tcp", procnet.TCP, procnet.V4,
		sock(procnet.StateListen, "127.0.0.1", 8080, procnet.TCP))}
	v := Explain(query("127.0.0.1", 8080, procnet.TCP), tables, Env{})
	if v.Kind != KindListening {
		t.Fatalf("kind = %v, want listening", v.Kind)
	}
	if !hasReason(v, ReasonListener) {
		t.Error("missing listener-holds-address reason")
	}
}

// A wildcard holder covers every specific address in its family, in both
// directions of the question: binding "0.0.0.0:8080" while "127.0.0.1:8080" is
// listenable fails just as binding "127.0.0.1:8080" while "0.0.0.0:8080" is.
func TestExplainWildcardCoversBothDirections(t *testing.T) {
	t.Run("wildcard holder blocks specific query", func(t *testing.T) {
		tables := []procnet.Table{table("tcp", procnet.TCP, procnet.V4,
			sock(procnet.StateListen, "0.0.0.0", 8080, procnet.TCP))}
		if v := Explain(query("10.1.2.3", 8080, procnet.TCP), tables, Env{}); v.Kind != KindListening {
			t.Fatalf("kind = %v, want listening", v.Kind)
		}
	})
	t.Run("wildcard query collides with specific holder", func(t *testing.T) {
		tables := []procnet.Table{table("tcp", procnet.TCP, procnet.V4,
			sock(procnet.StateListen, "127.0.0.1", 8080, procnet.TCP))}
		if v := Explain(query("0.0.0.0", 8080, procnet.TCP), tables, Env{}); v.Kind != KindListening {
			t.Fatalf("kind = %v, want listening", v.Kind)
		}
	})
}

// The reverse assertions. Each of these would be a false conflict report, and a
// false positive is what makes a user uninstall a diagnostic tool.
func TestExplainDoesNotInventConflicts(t *testing.T) {
	cases := []struct {
		name  string
		q     Query
		socks []procnet.Socket
	}{
		{
			name:  "same port, different specific address",
			q:     query("10.1.2.3", 8080, procnet.TCP),
			socks: []procnet.Socket{sock(procnet.StateListen, "127.0.0.1", 8080, procnet.TCP)},
		},
		{
			name:  "adjacent port",
			q:     query("127.0.0.1", 8081, procnet.TCP),
			socks: []procnet.Socket{sock(procnet.StateListen, "127.0.0.1", 8080, procnet.TCP)},
		},
		{
			name:  "same port and address, other protocol",
			q:     query("127.0.0.1", 8080, procnet.TCP),
			socks: []procnet.Socket{sock(procnet.StateListen, "127.0.0.1", 8080, procnet.UDP)},
		},
		{
			name:  "same port, other family",
			q:     query("127.0.0.1", 8080, procnet.TCP),
			socks: []procnet.Socket{sock(procnet.StateListen, "::1", 8080, procnet.TCP)},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tables := []procnet.Table{
				table("tcp", procnet.TCP, procnet.V4, c.socks...),
				table("tcp6", procnet.TCP, procnet.V6),
			}
			v := Explain(c.q, tables, Env{})
			// The only acceptable answers here are "free" or "unknown" (the v6
			// rows can make it unknown). A conflict report would be a lie about
			// a bind that would in fact succeed.
			if v.Kind != KindFree && v.Kind != KindUnknown {
				t.Fatalf("kind = %v: invented a conflict", v.Kind)
			}
		})
	}
}

// TIME_WAIT is a different problem from a live listener: one is fixed by a
// socket option or by waiting, the other by talking to the process. Folding them
// together is the single most common way these tools mislead.
func TestExplainSeparatesTimeWaitFromListener(t *testing.T) {
	t.Run("time-wait only", func(t *testing.T) {
		tables := []procnet.Table{table("tcp", procnet.TCP, procnet.V4,
			sock(procnet.StateTimeWait, "127.0.0.1", 8080, procnet.TCP))}
		v := Explain(query("127.0.0.1", 8080, procnet.TCP), tables, Env{})
		if v.Kind != KindTimeWaitOnly {
			t.Fatalf("kind = %v, want time-wait-only", v.Kind)
		}
		// A TIME_WAIT row has inode 0, so it can have no owner. Saying so is
		// the difference between "unknown" and "the tool is broken".
		if !hasReason(v, ReasonNoOwnerInode) {
			t.Error("missing no-inode-so-no-owner reason")
		}
		for _, f := range v.Findings {
			if len(f.Owners) != 0 {
				t.Errorf("TIME_WAIT finding has owners %v, want none", f.Owners)
			}
		}
	})

	t.Run("listener wins over time-wait child", func(t *testing.T) {
		tables := []procnet.Table{table("tcp", procnet.TCP, procnet.V4,
			sock(procnet.StateTimeWait, "127.0.0.1", 8080, procnet.TCP),
			sock(procnet.StateListen, "127.0.0.1", 8080, procnet.TCP),
			sock(procnet.StateFinWait1, "127.0.0.1", 8080, procnet.TCP))}
		v := Explain(query("127.0.0.1", 8080, procnet.TCP), tables, Env{})
		if v.Kind != KindListening {
			t.Fatalf("kind = %v, want listening", v.Kind)
		}
		if got := v.Findings[0].Socket.State; got != procnet.StateListen {
			t.Errorf("first finding state = %v, want LISTEN first", got)
		}
	})
}

func TestExplainNonListeningOccupation(t *testing.T) {
	tables := []procnet.Table{table("tcp", procnet.TCP, procnet.V4,
		sock(procnet.StateEstablished, "127.0.0.1", 8080, procnet.TCP))}
	v := Explain(query("127.0.0.1", 8080, procnet.TCP), tables, Env{})
	if v.Kind != KindOccupiedNonListening {
		t.Fatalf("kind = %v, want occupied-non-listening", v.Kind)
	}
	if !hasReason(v, ReasonOtherState) {
		t.Error("missing non-listening-state reason")
	}
}

// An unreadable table must never become "free". This is the assertion that
// protects the tool's central promise.
func TestExplainUnreadableTableIsUnknownNotFree(t *testing.T) {
	tables := []procnet.Table{{Name: "tcp", Proto: procnet.TCP, Family: procnet.V4, Err: errors.New("permission denied")}}
	v := Explain(query("127.0.0.1", 8080, procnet.TCP), tables, Env{})
	if v.Kind != KindUnknown {
		t.Fatalf("kind = %v, want unknown", v.Kind)
	}
	if !hasReason(v, ReasonTableUnreadable) {
		t.Error("missing table-unreadable reason")
	}
	if len(v.TablesUnreadable) != 1 || v.TablesUnreadable[0] != "tcp" {
		t.Errorf("TablesUnreadable = %v, want [tcp]", v.TablesUnreadable)
	}
}

// The mirror of the above: a kernel that simply has no IPv6 must not make an
// IPv4 question unanswerable.
func TestExplainMissingIPv6TableDoesNotBlockIPv4Answer(t *testing.T) {
	tables := []procnet.Table{
		table("tcp", procnet.TCP, procnet.V4),
		{Name: "tcp6", Proto: procnet.TCP, Family: procnet.V6, Err: procnet.ErrTableMissing},
	}
	v := Explain(query("127.0.0.1", 8080, procnet.TCP), tables, Env{})
	if v.Kind != KindFree {
		t.Fatalf("kind = %v, want free (a missing v6 table hides nothing about v4)", v.Kind)
	}
	if len(v.TablesUnreadable) != 0 {
		t.Errorf("TablesUnreadable = %v, want none", v.TablesUnreadable)
	}
	if v.TablesRead != 1 {
		t.Errorf("TablesRead = %d, want 1", v.TablesRead)
	}
}

// An IPv6 wildcard on the port may or may not occupy IPv4 (net.ipv6.bindv6only).
// Until a probe settles it, the answer is "unknown" — never "free".
func TestExplainIPv6WildcardForcesUnknown(t *testing.T) {
	tables := []procnet.Table{
		table("tcp", procnet.TCP, procnet.V4),
		table("tcp6", procnet.TCP, procnet.V6, sock(procnet.StateListen, "::", 8080, procnet.TCP)),
	}
	v := Explain(query("127.0.0.1", 8080, procnet.TCP), tables, Env{})
	if v.Kind != KindUnknown {
		t.Fatalf("kind = %v, want unknown", v.Kind)
	}
	if !hasReason(v, ReasonV6Wildcard) {
		t.Error("missing ipv6-wildcard-may-shadow-ipv4 reason")
	}
}

func TestExplainRecordsIncompleteHolderLookup(t *testing.T) {
	ln := sock(procnet.StateListen, "127.0.0.1", 8080, procnet.TCP)
	ln.Inode = 4242

	t.Run("denied processes and no owner", func(t *testing.T) {
		v := Explain(query("127.0.0.1", 8080, procnet.TCP),
			[]procnet.Table{table("tcp", procnet.TCP, procnet.V4, ln)},
			Env{Lookup: func(procnet.Socket) []Owner { return nil }, ProcsDenied: 3, ProcsRead: 100})
		if !hasReason(v, ReasonProcsDenied) {
			t.Error("missing some-processes-unreadable reason")
		}
		if v.ProcsDenied != 3 || v.ProcsRead != 100 {
			t.Errorf("counts = %d/%d, want 3/100", v.ProcsDenied, v.ProcsRead)
		}
	})

	t.Run("owner found despite denials", func(t *testing.T) {
		v := Explain(query("127.0.0.1", 8080, procnet.TCP),
			[]procnet.Table{table("tcp", procnet.TCP, procnet.V4, ln)},
			Env{Lookup: func(procnet.Socket) []Owner { return []Owner{{PID: 7, Comm: "svc", FD: 3}} }, ProcsDenied: 3})
		if hasReason(v, ReasonProcsDenied) {
			t.Error("procs-denied reported although the owner is known")
		}
		if got := v.Findings[0].Owners; len(got) != 1 || got[0].PID != 7 {
			t.Errorf("owners = %v, want pid 7", got)
		}
	})
}

func TestExplainAlwaysDisclosesThatNothingWasProbed(t *testing.T) {
	// Every verdict in this version rests on table state alone. If the output
	// ever stopped saying so, it would be claiming a bind test that never ran.
	cases := map[string][]procnet.Table{
		"free":      {table("tcp", procnet.TCP, procnet.V4)},
		"listening": {table("tcp", procnet.TCP, procnet.V4, sock(procnet.StateListen, "127.0.0.1", 8080, procnet.TCP))},
	}
	for name, tables := range cases {
		v := Explain(query("127.0.0.1", 8080, procnet.TCP), tables, Env{})
		if !hasReason(v, ReasonProbeNotRun) {
			t.Errorf("%s: missing bind-not-probed reason", name)
		}
	}
}

func TestFindingsAreOrderedReproducibly(t *testing.T) {
	tables := []procnet.Table{table("tcp", procnet.TCP, procnet.V4,
		sock(procnet.StateFinWait1, "0.0.0.0", 8080, procnet.TCP),
		sock(procnet.StateListen, "0.0.0.0", 8080, procnet.TCP),
		sock(procnet.StateEstablished, "127.0.0.1", 8080, procnet.TCP))}
	v := Explain(query("127.0.0.1", 8080, procnet.TCP), tables, Env{})
	if len(v.Findings) != 3 {
		t.Fatalf("findings = %d, want 3", len(v.Findings))
	}
	if v.Findings[0].Socket.State != procnet.StateListen {
		t.Errorf("first finding = %v, want LISTEN", v.Findings[0].Socket.State)
	}
	// Stable across runs: same input, same order.
	again := Explain(query("127.0.0.1", 8080, procnet.TCP), tables, Env{})
	for i := range v.Findings {
		if v.Findings[i].Socket.State != again.Findings[i].Socket.State {
			t.Fatalf("order changed between runs at %d", i)
		}
	}
}

func TestReasonDetailsAreNotEmpty(t *testing.T) {
	tables := []procnet.Table{
		table("tcp", procnet.TCP, procnet.V4),
		table("tcp6", procnet.TCP, procnet.V6, sock(procnet.StateListen, "::", 8080, procnet.TCP)),
	}
	v := Explain(query("127.0.0.1", 8080, procnet.TCP), tables, Env{})
	for _, r := range v.Reasons {
		if strings.TrimSpace(r.Code) == "" {
			t.Error("reason with empty code")
		}
		if r.Code == ReasonV6Wildcard && r.Detail == "" {
			t.Error("wildcard reason without the address it saw")
		}
	}
}
