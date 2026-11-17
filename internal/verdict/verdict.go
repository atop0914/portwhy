// Package verdict answers "why can't I bind this port", from evidence.
//
// It is a pure function over the kernel's socket tables: no filesystem, no
// syscalls, no clock. Everything it concludes has to be traceable to a row it
// was given, because the alternative — a plausible story assembled from
// folklore — is exactly what this tool exists to replace.
//
// What it does not do is equally deliberate: it does not claim a port is free
// when it could not read a table, and it does not claim a port is taken when the
// only evidence is a socket on a different address. Both directions of error are
// tested as first-class cases.
package verdict

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/atop0914/portwhy/internal/procnet"
)

// Kind is the answer. The names are stable: they appear in JSON output and in
// the exit-code contract, so they are codes, not prose.
type Kind string

const (
	// KindFree means every relevant table was read and nothing occupies it.
	KindFree Kind = "free"
	// KindListening means a socket in LISTEN holds the address.
	KindListening Kind = "listening"
	// KindTimeWaitOnly means only TIME_WAIT rows hold it: a different problem
	// with a different fix, which is why it is not folded into KindListening.
	KindTimeWaitOnly Kind = "time-wait-only"
	// KindOccupiedNonListening means sockets hold the address in some other
	// state (ESTABLISHED, FIN_WAIT1, CLOSE_WAIT...). Whether that blocks a bind
	// depends on socket options, so this is reported as its own case.
	KindOccupiedNonListening Kind = "occupied-non-listening"
	// KindUnknown means the evidence needed for an answer is missing. It is a
	// separate kind, not a flavour of free: "I could not look" and "nothing is
	// there" must never share an exit code.
	KindUnknown Kind = "unknown"
)

// Reason codes. The CLI turns them into sentences; tests assert on the codes so
// that changing wording never quietly changes meaning.
const (
	ReasonNoSockets       = "no-sockets-found"
	ReasonListener        = "listener-holds-address"
	ReasonTimeWait        = "only-time-wait-rows"
	ReasonOtherState      = "non-listening-state"
	ReasonTableUnreadable = "table-unreadable"
	ReasonV6Wildcard      = "ipv6-wildcard-may-shadow-ipv4"
	ReasonNoOwnerInode    = "no-inode-so-no-owner"
	ReasonProcsDenied     = "some-processes-unreadable"
	ReasonProbeNotRun     = "bind-not-probed"
	// ReasonTeardown records rows that were seen on the address and discarded
	// because the kernel had already released them. Silently dropping them
	// would make the report disagree with the table a user is looking at.
	ReasonTeardown = "row-being-destroyed"
	// ReasonUnknownState is a state code this build does not know. It is a hole
	// in the evidence, not a row to be counted as occupation.
	ReasonUnknownState = "unknown-state-code"
	// ReasonUnlistedBinding is a property of the data source, not of this run: a
	// socket that was bound without listen() holds the port and has no row in
	// /proc/net/tcp. It is stated on every "free" answer, the only answer it can
	// invalidate.
	ReasonUnlistedBinding = "bind-without-listen-not-listed"
)

// Owner is one process holding one socket, as this package needs to know it.
// Keeping it here rather than importing the /proc walker is what lets the whole
// judgement be tested without a machine.
type Owner struct {
	PID  int
	Comm string
	FD   int
	// Role is what the process tree proves about how this process got the
	// socket. It answers the question a user actually asks when several pids
	// share one listener: which of these do I deal with.
	Role Role
}

// Finding is one socket that occupies the queried address, with whoever holds it.
type Finding struct {
	Socket procnet.Socket
	Owners []Owner
}

// Reason is machine-readable evidence for the verdict.
type Reason struct {
	Code   string
	Detail string
}

// Query is the question.
type Query struct {
	Addr  procnet.Addr
	Proto procnet.Proto
}

// Env is everything Explain needs from the outside world, injected so that the
// judgement itself stays pure.
type Env struct {
	// Lookup returns the holders of one socket. Nil is allowed and means "not
	// attempted"; findings then carry no owners rather than invented ones.
	Lookup func(procnet.Socket) []Owner
	// ProcsRead and ProcsDenied describe how complete the holder lookup was.
	ProcsRead   int
	ProcsDenied int
	// PPID maps pid to parent pid and is the only evidence available about which
	// of several holders had a socket first: the kernel records no creator, but a
	// shared socket is inherited across fork(), so the holder that is an ancestor
	// of the others must precede them. Nil is allowed — roles then stop at
	// "sole" and "shared" instead of guessing.
	PPID map[int]int
}

// Verdict is the answer plus the evidence it rests on.
type Verdict struct {
	Query    Query
	Kind     Kind
	Findings []Finding
	Reasons  []Reason
	// All is every row that mentions the queried port, each labelled with why it
	// did or did not take part. It is empty unless ExplainAll was used, and it is
	// filled afterwards: no row in it can reach the judgement.
	All []Row
	// TablesRead and TablesUnreadable document the scope of the look, so a
	// reader can tell "nothing holds it" from "nothing was readable".
	TablesRead       int
	TablesUnreadable []string
	ProcsRead        int
	ProcsDenied      int
}

// Explain classifies one address.
//
// The order of the checks is the honesty of the result: an unreadable table is
// settled first, so that no later branch can turn a blind spot into "free".
func Explain(q Query, tables []procnet.Table, env Env) Verdict {
	v := Verdict{Query: q, ProcsRead: env.ProcsRead, ProcsDenied: env.ProcsDenied}

	var relevant []procnet.Table
	for _, t := range tables {
		if t.Proto == q.Proto {
			relevant = append(relevant, t)
		}
	}

	// A table that exists but could not be read is a hole in the evidence.
	// A table that the kernel does not provide is not: a kernel without IPv6
	// simply has no sockets to hide from an IPv4 question.
	readable := 0
	for _, t := range relevant {
		switch {
		case t.Err == nil:
			readable++
		case isMissingTable(t.Err) && q.Addr.IP.Is4() && t.Family == procnet.V6:
			// Nothing to hide an IPv4 answer behind.
		case isMissingTable(t.Err) && q.Addr.IP.Is6() && t.Family == procnet.V4:
			// Same, mirrored.
		default:
			v.TablesUnreadable = append(v.TablesUnreadable, t.Name)
		}
	}
	v.TablesRead = readable

	if len(v.TablesUnreadable) > 0 {
		v.Kind = KindUnknown
		v.Reasons = append(v.Reasons, Reason{
			Code:   ReasonTableUnreadable,
			Detail: fmt.Sprintf("could not read: %v", v.TablesUnreadable),
		})
		return v
	}

	// Rows the kernel has already released are collected separately: they match
	// the address but they do not hold it, and calling them holders would tell a
	// user to go kill a process that is already gone.
	var released []procnet.Socket
	for _, t := range relevant {
		for _, s := range t.Sockets {
			// The row carries its own protocol; checking it as well as the
			// table's keeps a mismatched input from turning a UDP socket into a
			// TCP blocker.
			if s.Proto != q.Proto {
				continue
			}
			if !occupies(s, q) {
				continue
			}
			if s.State.Binding() == procnet.EffectTeardown {
				released = append(released, s)
				continue
			}
			f := Finding{Socket: s}
			if env.Lookup != nil {
				f.Owners = prepareOwners(env.Lookup(s), env.PPID)
			}
			v.Findings = append(v.Findings, f)
		}
	}

	// Findings are ordered for reproducible output: listeners first, then by
	// address, then by state. A report whose row order changes between runs is
	// a report nobody can diff.
	sort.SliceStable(v.Findings, func(i, j int) bool {
		a, b := v.Findings[i].Socket, v.Findings[j].Socket
		if (a.State == procnet.StateListen) != (b.State == procnet.StateListen) {
			return a.State == procnet.StateListen
		}
		if a.Local.IP != b.Local.IP {
			return a.Local.IP.Less(b.Local.IP)
		}
		return a.State < b.State
	})

	var unrecognised []procnet.State
	v.Kind, unrecognised = classify(v.Findings)
	if len(unrecognised) > 0 {
		v.Reasons = append(v.Reasons, Reason{
			Code:   ReasonUnknownState,
			Detail: stateLabels(unrecognised),
		})
	}

	switch v.Kind {
	case KindFree:
		// An IPv6 wildcard listener can also occupy IPv4, depending on
		// net.ipv6.bindv6only. This version does not verify which, so it must
		// not answer "free" — an unverified "free" is the one answer a
		// diagnostic tool must never give.
		if shadow := v6WildcardShadow(q, tables); shadow != nil {
			v.Kind = KindUnknown
			v.Findings = append(v.Findings, Finding{Socket: *shadow})
			v.Reasons = append(v.Reasons, Reason{
				Code:   ReasonV6Wildcard,
				Detail: shadow.Local.String(),
			})
		} else if len(released) == 0 {
			v.Reasons = append(v.Reasons, Reason{Code: ReasonNoSockets})
		}
		if v.Kind == KindFree {
			// The one answer this blind spot can invalidate, so it is stated
			// here and nowhere else: a caveat that appears on every report stops
			// being read.
			v.Reasons = append(v.Reasons, Reason{Code: ReasonUnlistedBinding})
		}
	case KindListening:
		v.Reasons = append(v.Reasons, Reason{Code: ReasonListener})
	case KindTimeWaitOnly:
		v.Reasons = append(v.Reasons, Reason{Code: ReasonTimeWait})
	case KindOccupiedNonListening:
		v.Reasons = append(v.Reasons, Reason{Code: ReasonOtherState})
	}

	if len(released) > 0 {
		v.Reasons = append(v.Reasons, Reason{Code: ReasonTeardown, Detail: teardownDetail(released)})
	}

	// A row with inode 0 has no file descriptor behind it — a TIME_WAIT row, or a
	// socket we closed that is still waiting out its timeout — so no amount of
	// /proc walking will name an owner. Saying that out loud stops the next
	// question ("which process?").
	for _, f := range v.Findings {
		if f.Socket.Inode == 0 {
			v.Reasons = append(v.Reasons, Reason{Code: ReasonNoOwnerInode})
			break
		}
	}

	unknownOwner := false
	for _, f := range v.Findings {
		if len(f.Owners) == 0 && f.Socket.Inode != 0 {
			unknownOwner = true
		}
	}
	if unknownOwner && env.ProcsDenied > 0 {
		v.Reasons = append(v.Reasons, Reason{
			Code:   ReasonProcsDenied,
			Detail: fmt.Sprintf("%d process(es) not readable", env.ProcsDenied),
		})
	}

	// State only; the empirical bind probe is a later capability and this
	// version must not imply it happened.
	v.Reasons = append(v.Reasons, Reason{Code: ReasonProbeNotRun})
	return v
}

// classify folds the findings into one kind, reading the consequence of each
// row out of the state table instead of comparing states by hand.
//
// The precedence is the honesty of the answer. A listener explains an EADDRINUSE
// outright and no other row can weaken that; an unrecognised state code is a hole
// in the evidence and must not be folded into "occupied"; TIME_WAIT and nothing
// else is its own diagnosis because its fix is different from a live socket's.
func classify(findings []Finding) (Kind, []procnet.State) {
	var (
		unrecognised []procnet.State
		listening    bool
		occupied     bool
		considered   int
	)
	onlyTimeWait := true
	for _, f := range findings {
		switch effect := f.Socket.State.Binding(); effect {
		case procnet.EffectTeardown:
			// Explain drops these before classifying. Skipping here too means a
			// released row can never be counted as occupation by any caller — and
			// it is not counted as "something was here" either, so a report made
			// only of released rows does not become "only TIME_WAIT".
			continue
		case procnet.EffectBlocks:
			listening = true
		case procnet.EffectOptionsDecide:
			occupied = true
		default:
			unrecognised = append(unrecognised, f.Socket.State)
		}
		considered++
		if f.Socket.State != procnet.StateTimeWait {
			onlyTimeWait = false
		}
	}
	switch {
	case listening:
		return KindListening, nil
	case len(unrecognised) > 0:
		return KindUnknown, unrecognised
	case considered > 0 && onlyTimeWait:
		return KindTimeWaitOnly, nil
	case occupied:
		return KindOccupiedNonListening, nil
	}
	return KindFree, nil
}

// stateLabels renders state codes once each, in a stable order, so a reason's
// detail is diffable between runs.
func stateLabels(states []procnet.State) string {
	seen := make(map[procnet.State]bool, len(states))
	labels := make([]string, 0, len(states))
	for _, s := range states {
		if seen[s] {
			continue
		}
		seen[s] = true
		labels = append(labels, s.String())
	}
	sort.Strings(labels)
	return strings.Join(labels, ", ")
}

// teardownDetail names what was seen and dropped, so a reader can find those rows
// in the table themselves instead of wondering what the tool hid.
func teardownDetail(released []procnet.Socket) string {
	states := make([]procnet.State, 0, len(released))
	for _, s := range released {
		states = append(states, s.State)
	}
	return fmt.Sprintf("%d row(s) in %s: the kernel has already released the port",
		len(released), stateLabels(states))
}

// occupies reports whether a socket row sits on the queried address.
func occupies(s procnet.Socket, q Query) bool {
	return s.Local.Port == q.Addr.Port && addressCovers(s.Local, q.Addr)
}

// addressCovers applies bind()'s rule for one address against another: a wildcard
// on either side covers the other, a specific address covers only itself, and
// different families never interact.
//
// Getting this wrong in the loose direction reports a conflict that does not
// exist, and users stop believing the tool after one such report.
func addressCovers(held, want procnet.Addr) bool {
	if !sameFamily(held.IP, want.IP) {
		return false
	}
	if held.IsWildcard() || want.IsWildcard() {
		return true
	}
	return held.IP == want.IP
}

func sameFamily(a, b netip.Addr) bool {
	return a.IsValid() && b.IsValid() && a.Is4() == b.Is4()
}

// v6WildcardShadow finds an IPv6 wildcard listener on the queried port when the
// question is about IPv4.
func v6WildcardShadow(q Query, tables []procnet.Table) *procnet.Socket {
	if !q.Addr.IP.Is4() {
		return nil
	}
	for _, t := range tables {
		if t.Proto != q.Proto || t.Family != procnet.V6 || t.Err != nil {
			continue
		}
		for _, s := range t.Sockets {
			if s.State == procnet.StateListen && s.Local.Port == q.Addr.Port && s.Local.IsWildcard() {
				shadow := s
				return &shadow
			}
		}
	}
	return nil
}

// isMissingTable separates "the kernel has no such table" from "we could not
// read it". Only the second one is a hole in the evidence.
func isMissingTable(err error) bool {
	return errors.Is(err, procnet.ErrTableMissing)
}
