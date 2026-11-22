package procnet

import (
	"fmt"
	"sort"
)

// BindEffect is what a row in a given state means for a later bind() on the same
// address and port.
//
// It is a table rather than a chain of comparisons because "what does this state
// do to my bind" is the actual question, and a table can be read in one pass
// against `man 7 tcp` instead of followed through branches.
type BindEffect uint8

const (
	// EffectUnknown means this build does not know the state code. It is not a
	// milder version of the others: with an unrecognised state the meaning of the
	// row is unknown, so any judgement resting on it has to say "unknown".
	EffectUnknown BindEffect = iota

	// EffectBlocks means a plain bind() on the same address and port fails while
	// this row exists. LISTEN is the only state with that property: SO_REUSEPORT
	// can share the port, but only between sockets that both asked for it, and a
	// plain bind is not one of them.
	EffectBlocks

	// EffectOptionsDecide means the row holds the address in a bound state, and
	// whether bind() fails depends on SO_REUSEADDR (and on whether the holder set
	// it too). Reporting the occupation without claiming the outcome is the only
	// honest option, because the answer differs between the two programs involved
	// and this tool is not either of them.
	EffectOptionsDecide

	// EffectTeardown means the socket is no longer in a hashed binding state, so
	// the kernel has already released the port and the row is a socket on its way
	// out. It is still worth reporting — a bind() a moment earlier may have
	// failed — but it does not explain an EADDRINUSE now.
	EffectTeardown
)

func (e BindEffect) String() string {
	switch e {
	case EffectBlocks:
		return "blocks"
	case EffectOptionsDecide:
		return "options-decide"
	case EffectTeardown:
		return "teardown"
	case EffectUnknown:
		return "unknown"
	}
	return fmt.Sprintf("effect(%d)", uint8(e))
}

// stateInfo is everything this build knows about one state code.
type stateInfo struct {
	// name is the kernel's own spelling, so output can be compared with `ss` and
	// with the kernel source without translation.
	name string
	// effect is the bind() consequence. It is the load-bearing field.
	effect BindEffect
	// note is one clause for a human: why that effect, in terms of the
	// connection's history.
	note string
}

// stateTable is the whole vocabulary. Every code from the kernel's
// tcp_state_str table is here, including the ones that only ever appear for a
// moment; an absent code would silently mean "no meaning known" for a state that
// is perfectly well defined.
var stateTable = map[State]stateInfo{
	StateEstablished: {name: "ESTABLISHED", effect: EffectOptionsDecide,
		note: "a connection is up and its local address stays bound"},
	StateSynSent: {name: "SYN_SENT", effect: EffectOptionsDecide,
		note: "an outbound connect is in flight; the local port is already chosen"},
	StateSynRecv: {name: "SYN_RECV", effect: EffectOptionsDecide,
		note: "an inbound handshake started but was not accepted yet"},
	StateFinWait1: {name: "FIN_WAIT1", effect: EffectOptionsDecide,
		note: "the local side closed first and awaits the peer's FIN"},
	StateFinWait2: {name: "FIN_WAIT2", effect: EffectOptionsDecide,
		note: "our FIN was acknowledged and the peer has not closed yet"},
	StateTimeWait: {name: "TIME_WAIT", effect: EffectOptionsDecide,
		note: "the connection is over but the 4-tuple is still reserved"},
	StateClose: {name: "CLOSE", effect: EffectTeardown,
		note: "not in a hashed state: either bound-but-never-listened (absent from this table) or already released"},
	StateCloseWait: {name: "CLOSE_WAIT", effect: EffectOptionsDecide,
		note: "the peer closed and the local side has not, so the local port stays bound"},
	StateLastAck: {name: "LAST_ACK", effect: EffectOptionsDecide,
		note: "the peer closed, our FIN is out, the last ACK is pending"},
	StateListen: {name: "LISTEN", effect: EffectBlocks,
		note: "a listener holds the address outright; a plain bind() fails with EADDRINUSE"},
	StateClosing: {name: "CLOSING", effect: EffectOptionsDecide,
		note: "both sides closed at once and the final ACKs are still in flight"},
	StateNewSynRecv: {name: "NEW_SYN_RECV", effect: EffectOptionsDecide,
		note: "a request socket from a SYN that the listener has not accepted yet"},
}

// udpStateTable is the UDP reading of the same column.
//
// It is a separate table rather than a patch on the TCP one because UDP has no
// connection state machine: there is no LISTEN, no TIME_WAIT and nothing to
// tear down. Two values occur, both verified against a live kernel:
//
//   - 0x07 CLOSE: bound and unconnected. Every bound UDP socket looks like this.
//   - 0x01 ESTABLISHED: connect()ed to a peer, so the local port stays bound.
//
// Both block a plain bind(). A socket that set SO_REUSEADDR can share the port
// with another that did too — the same "the option changes the answer" case as
// LISTEN with SO_REUSEPORT, which is why the note says so rather than the
// judgement pretending the option does not exist.
var udpStateTable = map[State]stateInfo{
	StateClose: {name: "CLOSE", effect: EffectBlocks,
		note: "bound and not connected — the ordinary state of a bound UDP socket; a plain bind() fails meanwhile"},
	StateEstablished: {name: "ESTABLISHED", effect: EffectBlocks,
		note: "connect()ed to a peer, so the local port stays bound and a plain bind() fails"},
}

// String names the state, and names the codes this build does not know as
// UNKNOWN(0x..): a reader must be able to tell "a state I do not understand"
// from "a state I understand, and it is CLOSE".
func (s State) String() string {
	if info, ok := stateTable[s]; ok {
		return info.name
	}
	return fmt.Sprintf("UNKNOWN(0x%02x)", uint8(s))
}

// BindingFor is the bind() consequence of a row in this state, read in the
// vocabulary of one protocol.
//
// The two vocabularies are not the same and must not be merged. /proc/net/udp
// uses the same numeric column as /proc/net/tcp, but only two of its values
// occur, and one of them means the opposite of what it means for a stream
// socket: st=07 (CLOSE) is a UDP socket that is bound and not connected — the
// normal state of any bound UDP socket, and one that makes a second bind() fail
// with EADDRINUSE. Read through the TCP table it is "already released", which
// would turn a port that is definitely taken into "free".
//
// An unrecognised code answers EffectUnknown rather than the most common effect:
// guessing here is what turns "I do not know" into a confident wrong answer.
func (s State) BindingFor(proto Proto) BindEffect {
	switch proto {
	case TCP:
		if info, ok := stateTable[s]; ok {
			return info.effect
		}
	case UDP:
		if info, ok := udpStateTable[s]; ok {
			return info.effect
		}
	}
	return EffectUnknown
}

// NoteFor is the one-clause explanation in one protocol's vocabulary, empty for
// a code that protocol does not use.
func (s State) NoteFor(proto Proto) string {
	switch proto {
	case TCP:
		return stateTable[s].note
	case UDP:
		return udpStateTable[s].note
	}
	return ""
}

// Binding is the bind() consequence of this row, read through the protocol the
// row itself carries.
//
// Callers must use this rather than State.BindingFor: a row knows which table it
// came from, and the same state number means different things in the two.
func (s Socket) Binding() BindEffect { return s.State.BindingFor(s.Proto) }

// KnownStates lists every state this build names, in numeric order.
//
// It exists so the vocabulary can be inspected as data (`portwhy states`) and
// so a test can assert that all twelve codes are covered — a missing entry is
// otherwise only noticed when that state shows up on a real machine.
func KnownStates() []State {
	out := make([]State, 0, len(stateTable))
	for s := range stateTable {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// KnownUDPStates lists the codes /proc/net/udp can carry, in numeric order.
//
// It is short on purpose. Printing the TCP vocabulary next to a UDP answer would
// suggest that a UDP socket can be in LISTEN or TIME_WAIT, and a reader who
// believed that would look for a state that cannot exist.
func KnownUDPStates() []State {
	out := make([]State, 0, len(udpStateTable))
	for s := range udpStateTable {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
