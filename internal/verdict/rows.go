package verdict

import (
	"sort"

	"github.com/atop0914/portwhy/internal/procnet"
)

// MatchCode says why a row on the queried port did or did not take part in the
// judgement.
//
// It is a code and not a sentence: a sentence cannot be asserted on, and the point
// of `--all` is that a reader can grep the reason instead of parsing prose.
type MatchCode string

const (
	// MatchMatched means the row covers the queried address and was judged.
	MatchMatched MatchCode = "matched"
	// MatchReleased means the row covers the address but the kernel has already
	// released it, so it was shown and not counted.
	MatchReleased MatchCode = "released"

	// MatchOtherPort means the port appears only as the row's remote end: a
	// connection *to* the port from somewhere else.
	MatchOtherPort MatchCode = "other-port"
	// MatchOtherProto means the same port number in the other transport: a UDP
	// row never blocks a TCP bind.
	MatchOtherProto MatchCode = "other-proto"
	// MatchOtherFamily means the other address family. It is its own code
	// because "other address" would be a different, and wrong, reason: an IPv6
	// socket on this port is not a socket on another address.
	MatchOtherFamily MatchCode = "other-family"
	// MatchOtherAddress means the same port and family, a different specific
	// address in both directions.
	MatchOtherAddress MatchCode = "other-address"
	// MatchWildcardShadowed means an IPv6 wildcard listener that may also occupy
	// IPv4, depending on net.ipv6.bindv6only. It is the one row from the other
	// family that can change an IPv4 answer.
	MatchWildcardShadowed MatchCode = "wildcard-shadowed"
)

// Row is one table line that mentions the queried port, with the reason it did or
// did not take part.
type Row struct {
	Socket procnet.Socket
	Match  MatchCode
	Owners []Owner
}

// ExplainAll returns the verdict Explain would give, plus every row that mentions
// the queried port number — including the ones that are nowhere near the answer.
//
// The judgement is Explain's, taken first and left alone; rows are attached
// afterwards and cannot reach it. That is the entire point of `--all`: looking at
// the neighbours of an answer must never move the answer.
func ExplainAll(q Query, tables []procnet.Table, env Env) Verdict {
	v := Explain(q, tables, env)
	// Allocated up front so "asked for every row and there were none" stays
	// distinguishable from "did not ask": a nil slice here means the caller used
	// Explain, and the JSON report relies on that difference.
	v.All = make([]Row, 0, 4)

	for _, t := range tables {
		for _, s := range t.Sockets {
			// "Mentions the port" is the filter: a row whose local end is the
			// port, or one connected *to* it. The second half is why other-port
			// exists — those rows are the far end of connections this tool
			// otherwise only sees from one side, and they are how a reader
			// explains a wall of TIME_WAIT rows.
			if s.Local.Port != q.Addr.Port && s.Remote.Port != q.Addr.Port {
				continue
			}
			row := Row{Socket: s, Match: matchCode(s, q)}
			if env.Lookup != nil {
				row.Owners = prepareOwners(env.Lookup(s), env.PPID)
			}
			v.All = append(v.All, row)
		}
	}

	// Matched rows first, then a total order over everything that identifies a
	// row, so two runs over the same table produce byte-identical output.
	sort.SliceStable(v.All, func(i, j int) bool {
		a, b := v.All[i], v.All[j]
		if (a.Match == MatchMatched) != (b.Match == MatchMatched) {
			return a.Match == MatchMatched
		}
		if a.Socket.Table != b.Socket.Table {
			return a.Socket.Table < b.Socket.Table
		}
		if a.Socket.State != b.Socket.State {
			return a.Socket.State < b.Socket.State
		}
		if a.Socket.Local.IP != b.Socket.Local.IP {
			return a.Socket.Local.IP.Less(b.Socket.Local.IP)
		}
		return a.Socket.Inode < b.Socket.Inode
	})
	return v
}

// matchCode explains one row's relationship to the question.
//
// The order of the checks is the order of the reasons: a row can be wrong about
// several things at once (a UDP socket on the other address), and the first thing
// that makes it irrelevant is the one worth reporting.
func matchCode(s procnet.Socket, q Query) MatchCode {
	switch {
	case s.Local.Port != q.Addr.Port:
		return MatchOtherPort
	case s.Proto != q.Proto:
		return MatchOtherProto
	case !sameFamily(s.Local.IP, q.Addr.IP):
		// A [::] listener is the only row from the other family that can matter:
		// with bindv6only=0 it occupies IPv4 too. The mirror does not hold — a
		// 0.0.0.0 listener never occupies an IPv6 address.
		if s.State == procnet.StateListen && s.Local.IsWildcard() && q.Addr.IP.Is4() {
			return MatchWildcardShadowed
		}
		return MatchOtherFamily
	case addressCovers(s.Local, q.Addr):
		if s.State.Binding() == procnet.EffectTeardown {
			return MatchReleased
		}
		return MatchMatched
	}
	return MatchOtherAddress
}
