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

// String names the state, and names the codes this build does not know as
// UNKNOWN(0x..): a reader must be able to tell "a state I do not understand"
// from "a state I understand, and it is CLOSE".
func (s State) String() string {
	if info, ok := stateTable[s]; ok {
		return info.name
	}
	return fmt.Sprintf("UNKNOWN(0x%02x)", uint8(s))
}

// Binding is the bind() consequence of a row in this state. An unrecognised code
// answers EffectUnknown rather than the most common effect: guessing here is what
// turns "I do not know" into a confident wrong answer.
func (s State) Binding() BindEffect {
	if info, ok := stateTable[s]; ok {
		return info.effect
	}
	return EffectUnknown
}

// Note is the one-clause explanation, empty for an unrecognised code.
func (s State) Note() string { return stateTable[s].note }

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
