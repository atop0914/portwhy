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
)

// Owner is one process holding one socket, as this package needs to know it.
// Keeping it here rather than importing the /proc walker is what lets the whole
// judgement be tested without a machine.
type Owner struct {
	PID  int
	Comm string
	FD   int
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
}

// Verdict is the answer plus the evidence it rests on.
type Verdict struct {
	Query    Query
	Kind     Kind
	Findings []Finding
	Reasons  []Reason
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
			f := Finding{Socket: s}
			if env.Lookup != nil {
				f.Owners = env.Lookup(s)
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

	v.Kind = classify(v.Findings)

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
		} else {
			v.Reasons = append(v.Reasons, Reason{Code: ReasonNoSockets})
		}
	case KindListening:
		v.Reasons = append(v.Reasons, Reason{Code: ReasonListener})
	case KindTimeWaitOnly:
		v.Reasons = append(v.Reasons, Reason{Code: ReasonTimeWait})
	case KindOccupiedNonListening:
		v.Reasons = append(v.Reasons, Reason{Code: ReasonOtherState})
	}

	// A TIME_WAIT row has inode 0, so no amount of /proc walking will name an
	// owner. Saying that out loud stops the next question ("which process?").
	for _, f := range v.Findings {
		if f.Socket.State == procnet.StateTimeWait {
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

func classify(findings []Finding) Kind {
	if len(findings) == 0 {
		return KindFree
	}
	onlyTimeWait := true
	for _, f := range findings {
		if f.Socket.State == procnet.StateListen {
			return KindListening
		}
		if f.Socket.State != procnet.StateTimeWait {
			onlyTimeWait = false
		}
	}
	if onlyTimeWait {
		return KindTimeWaitOnly
	}
	return KindOccupiedNonListening
}

// occupies reports whether a socket row sits on the queried address.
//
// The rules are the ones bind() applies, not the ones a naive port comparison
// applies: a wildcard on either side covers the other, and a specific address
// only covers itself. Getting this wrong in the loose direction means reporting
// a conflict that does not exist, and users stop believing the tool after one.
func occupies(s procnet.Socket, q Query) bool {
	if s.Local.Port != q.Addr.Port {
		return false
	}
	if !sameFamily(s.Local.IP, q.Addr.IP) {
		return false
	}
	if s.Local.IsWildcard() || q.Addr.IsWildcard() {
		return true
	}
	return s.Local.IP == q.Addr.IP
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
