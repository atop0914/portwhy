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
	"time"

	"github.com/atop0914/portwhy/internal/probe"
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

	// Probe reason codes. The probe is the only evidence that can contradict a
	// table, so each way the two can disagree has its own code: folding them
	// together would make "the table is stale" and "the table cannot see this
	// kind of holder" read the same, and they need different fixes.
	//
	// ReasonProbeBound records that a plain bind really succeeded. It is the one
	// probe result that closes a gap instead of opening one, so it is stated
	// with the instant it happened and nothing more.
	ReasonProbeBound = "bind-succeeded-at-probe-time"
	// ReasonProbeRefused means the plain bind was refused. Consistent with a
	// table that already showed a holder, and damning for one that showed none.
	ReasonProbeRefused = "probe-bind-was-refused"
	// ReasonProbeHolds is the headline case: the table showed nothing and a
	// plain bind still failed. A socket bound without listen() is the only thing
	// that can produce it, and it is exactly what no table can show.
	ReasonProbeHolds = "bind-fails-but-table-shows-nothing"
	// ReasonProbeOption means plain failed and SO_REUSEADDR succeeded: the
	// reservation is a closed connection, and the fix is one socket option.
	ReasonProbeOption = "reuseaddr-would-succeed"
	// ReasonProbeDenied means the probe never got an answer about the address
	// (EACCES, EADDRNOTAVAIL, ENOMEM). It is a hole in the evidence, not a free
	// port.
	ReasonProbeDenied = "probe-could-not-run"
	// ReasonProbeGap means evidence was handed in without the attempt that the
	// conclusion needs.
	ReasonProbeGap = "probe-incomplete"
	// ReasonProbeConflict means the probe succeeded where the table said
	// something held the address. The table was read first, so the two describe
	// different instants and this version cannot say which one the user faces.
	ReasonProbeConflict = "table-and-probe-disagree"
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
	// Probe is what an empirical bind attempt found, handed in by the caller.
	// Nothing in this package executes a probe: the evidence is an argument, so
	// the judgement stays a function of its inputs and can be tested without a
	// machine. Nil means no bind was attempted, which is disclosed rather than
	// assumed away.
	Probe []probe.Attempt
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
	// Probe is the empirical evidence the answer was allowed to use, in the
	// order the attempts were made. Empty means no bind was attempted, which the
	// reasons state in words rather than leaving a reader to infer.
	Probe []probe.Attempt
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
		// The probe cannot repair a table that was never read: it can only say
		// what one instant looked like. It is still recorded, because a bind
		// that succeeded is worth knowing about next to an unreadable table.
		return applyProbe(v, env.Probe)
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

	// State only unless a probe was actually made; the wording lives in
	// applyProbe so that "not probed" and "probed, here is what happened" cannot
	// both be said in one report.
	return applyProbe(v, env.Probe)
}

// applyProbe folds the empirical evidence into the table-based answer.
//
// One direction only: a probe may make the answer more cautious, never more
// optimistic. It can collapse "free" into "unknown" — and does, whenever it
// disagrees with the table — but it may never promote anything to "free", even
// when the bind succeeded: a bind that worked at 12:00:00.1 says nothing about
// 12:00:00.2, and "free" is a claim about now. The single thing a successful
// probe is allowed to subtract is the bind-without-listen caveat, because that
// caveat has just been tested and found false at that instant.
func applyProbe(v Verdict, evidence []probe.Attempt) Verdict {
	v = foldProbe(v, evidence)
	if v.Kind != KindFree {
		// The caveat is a limit on a free answer and on nothing else. Once the
		// answer is no longer free, keeping it would put a blind spot next to a
		// diagnosis that already covers it, and a reader cannot tell the two
		// apart.
		v.dropReason(ReasonUnlistedBinding)
	}
	return v
}

func foldProbe(v Verdict, evidence []probe.Attempt) Verdict {
	v.Probe = evidence
	if len(evidence) == 0 {
		v.Reasons = append(v.Reasons, Reason{Code: ReasonProbeNotRun})
		return v
	}

	plain, reuse := byMode(evidence)
	if plain == nil {
		// Evidence without a plain attempt cannot answer the question a probe
		// exists to answer: SO_REUSEADDR succeeding while plain was never tried
		// is not the "one option away" diagnosis, and must not be read as one.
		v.Reasons = append(v.Reasons, Reason{
			Code:   ReasonProbeGap,
			Detail: "no plain attempt was recorded, so nothing is known about a plain bind",
		})
		if v.Kind == KindFree {
			v.Kind = KindUnknown
		}
		return v
	}
	if plain.Err != "" {
		// socket() refused or close() failed: this attempt is not evidence about
		// the address at all.
		v.Reasons = append(v.Reasons, Reason{
			Code:   ReasonProbeDenied,
			Detail: "the attempt did not complete cleanly: " + plain.Err,
		})
		if v.Kind == KindFree {
			v.Kind = KindUnknown
		}
		return v
	}

	switch plain.Outcome {
	case probe.OutcomeBound:
		return probeBound(v, *plain)
	case probe.OutcomeAddrInUse:
		return probeRefused(v, plain, reuse)
	default:
		// EACCES / EADDRNOTAVAIL / an errno this build does not classify / a
		// probe that never ran. None of these is a statement about occupation,
		// and the dangerous reading of any of them is "so the port is free".
		v.Reasons = append(v.Reasons, Reason{
			Code:   ReasonProbeDenied,
			Detail: probeFailure(*plain),
		})
		if v.Kind == KindFree {
			v.Kind = KindUnknown
		}
		return v
	}
}

// probeBound handles a bind the kernel accepted.
//
// It cannot produce "free": that word is reserved for "every table was read and
// nothing holds it", and a probe is not a table. What it can do is contradict a
// table that named a holder, and remove the caveat it has just disproved.
func probeBound(v Verdict, plain probe.Attempt) Verdict {
	switch v.Kind {
	case KindFree:
		v.dropReason(ReasonUnlistedBinding)
		v.Reasons = append(v.Reasons, Reason{
			Code: ReasonProbeBound,
			Detail: fmt.Sprintf("a plain bind succeeded at %s, so nothing — including a socket bound "+
				"without listen() — held this address at that instant", plain.At.Format(time.RFC3339)),
		})
	case KindListening, KindTimeWaitOnly, KindOccupiedNonListening:
		// The tables were read before the probe, so these describe two different
		// instants. Either the holder went away in between or one of the two
		// observations is wrong; this version cannot tell which, and naming a
		// process that no longer holds the port is the one failure that sends a
		// user to kill the wrong thing.
		held := v.Kind
		v.Kind = KindUnknown
		v.Reasons = append(v.Reasons, Reason{
			Code: ReasonProbeConflict,
			Detail: fmt.Sprintf("the tables showed %s but a plain bind succeeded at %s: "+
				"the tables were read first, so the two describe different instants",
				held, plain.At.Format(time.RFC3339)),
		})
	default:
		// A gap this version has no model for (an IPv6 wildcard that may shadow
		// IPv4, an unreadable table). The bind is recorded; the gap stands.
		v.Reasons = append(v.Reasons, Reason{
			Code: ReasonProbeBound,
			Detail: fmt.Sprintf("a plain bind succeeded at %s, but the evidence gap above still "+
				"decides the answer", plain.At.Format(time.RFC3339)),
		})
	}
	return v
}

// probeRefused handles a plain bind the kernel refused with EADDRINUSE.
func probeRefused(v Verdict, plain, reuse *probe.Attempt) Verdict {
	at := plain.At.Format(time.RFC3339)
	switch v.Kind {
	case KindFree:
		// The whole reason this package exists. No table row covers the address,
		// and the kernel still says someone holds it.
		v.Kind = KindUnknown
		// The blind spot has just been confirmed rather than closed, so it stops
		// being a "limits" line: it is the diagnosis now, and saying both would
		// read as two separate problems.
		v.dropReason(ReasonUnlistedBinding)
		v.Reasons = append(v.Reasons, Reason{
			Code:   ReasonProbeHolds,
			Detail: fmt.Sprintf("a plain bind returned %s at %s", plain.Errno, at),
		})
	case KindTimeWaitOnly:
		// The difference between the attempts is the diagnosis. Without a
		// successful SO_REUSEADDR attempt the reservation stays unexplained, and
		// recommending the option would be the folklore this tool replaces.
		if reuse != nil && reuse.Trustworthy() && reuse.Outcome == probe.OutcomeBound {
			v.Reasons = append(v.Reasons, Reason{
				Code:   ReasonProbeOption,
				Detail: fmt.Sprintf("plain refused with %s, SO_REUSEADDR bound at %s", plain.Errno, at),
			})
			return v
		}
		v.Reasons = append(v.Reasons, Reason{
			Code:   ReasonProbeRefused,
			Detail: fmt.Sprintf("plain bind returned %s at %s; %s", plain.Errno, at, reuseVerdict(reuse)),
		})
	default:
		// A visible holder (or an unreadable table). "Something holds it" is the
		// one sentence that is true of both, and the errno is what makes it
		// evidence rather than repetition.
		v.Reasons = append(v.Reasons, Reason{
			Code:   ReasonProbeRefused,
			Detail: fmt.Sprintf("plain bind returned %s at %s; %s", plain.Errno, at, reuseVerdict(reuse)),
		})
	}
	return v
}

// reuseVerdict says what the option attempt found, so that "SO_REUSEADDR did not
// help here" is as visible as the case where it did.
func reuseVerdict(reuse *probe.Attempt) string {
	switch {
	case reuse == nil:
		return "no SO_REUSEADDR attempt was recorded"
	case !reuse.Trustworthy():
		return fmt.Sprintf("the SO_REUSEADDR attempt itself failed: %s", reuseFailure(reuse))
	case reuse.Outcome == probe.OutcomeAddrInUse:
		return "SO_REUSEADDR was refused as well, so the option does not help here"
	default:
		return fmt.Sprintf("SO_REUSEADDR ended as %s", reuse.Outcome)
	}
}

// probeFailure states the fact and nothing else: what it means for the answer is
// the sentence the code carries, and repeating it here reads as two findings.
func probeFailure(a probe.Attempt) string {
	if a.Outcome == probe.OutcomeNotRun {
		return "no bind could be made: " + a.Err
	}
	return fmt.Sprintf("plain bind returned %s at %s", attemptFailure(a), a.At.Format(time.RFC3339))
}

func reuseFailure(a *probe.Attempt) string {
	return attemptFailure(*a)
}

// attemptFailure names what went wrong without pretending it was an answer.
func attemptFailure(a probe.Attempt) string {
	switch {
	case a.Outcome == probe.OutcomeNotRun:
		return "the attempt never ran: " + a.Err
	case a.Errno != "" && a.Message != "":
		return a.Errno + " (" + a.Message + ")"
	case a.Errno != "":
		return a.Errno
	case a.Message != "":
		return a.Message
	}
	return string(a.Outcome)
}

// byMode picks the attempts applyProbe needs. Later attempts for the same mode
// win: a caller that retried made the last observation, and mixing two
// observations of the same mode would produce a report no single moment
// supports.
func byMode(evidence []probe.Attempt) (plain, reuse *probe.Attempt) {
	for i := range evidence {
		a := &evidence[i]
		switch a.Mode {
		case probe.ModePlain:
			plain = a
		case probe.ModeReuseAddr:
			reuse = a
		}
	}
	return plain, reuse
}

// dropReason removes every instance of a code. It exists for exactly one case:
// a caveat that a probe has just disproved must not stay in the report, because
// a reader cannot tell a stale caveat from a live one.
func (v *Verdict) dropReason(code string) {
	kept := v.Reasons[:0]
	for _, r := range v.Reasons {
		if r.Code == code {
			continue
		}
		kept = append(kept, r)
	}
	v.Reasons = kept
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
