package procnet

import (
	"strings"
	"testing"
)

// The kernel's tcp_state_str table has exactly these twelve entries. A missing
// one is invisible until that state appears on a real machine, so the coverage is
// asserted here rather than discovered in production.
func TestEveryKernelStateIsNamed(t *testing.T) {
	want := []struct {
		state State
		name  string
	}{
		{StateEstablished, "ESTABLISHED"},
		{StateSynSent, "SYN_SENT"},
		{StateSynRecv, "SYN_RECV"},
		{StateFinWait1, "FIN_WAIT1"},
		{StateFinWait2, "FIN_WAIT2"},
		{StateTimeWait, "TIME_WAIT"},
		{StateClose, "CLOSE"},
		{StateCloseWait, "CLOSE_WAIT"},
		{StateLastAck, "LAST_ACK"},
		{StateListen, "LISTEN"},
		{StateClosing, "CLOSING"},
		{StateNewSynRecv, "NEW_SYN_RECV"},
	}
	if len(KnownStates()) != len(want) {
		t.Fatalf("KnownStates() has %d entries, want %d (01..0C)", len(KnownStates()), len(want))
	}
	for i, c := range want {
		if got := c.state.String(); got != c.name {
			t.Errorf("state 0x%02x prints %q, want %q", uint8(c.state), got, c.name)
		}
		if KnownStates()[i] != c.state {
			t.Errorf("KnownStates()[%d] = 0x%02x, want 0x%02x (numeric order)", i, uint8(KnownStates()[i]), uint8(c.state))
		}
	}
}

// Only a listener makes a plain bind() fail outright. If any other state claimed
// that, the tool would tell people a port is taken when SO_REUSEADDR would let
// them bind it — the false positive that ends trust in a diagnostic.
func TestOnlyListenClaimsToBlockBind(t *testing.T) {
	for _, s := range KnownStates() {
		if got := s.BindingFor(TCP); got == EffectBlocks && s != StateListen {
			t.Errorf("%v claims EffectBlocks; only LISTEN may", s)
		}
	}
	if StateListen.BindingFor(TCP) != EffectBlocks {
		t.Errorf("LISTEN binding = %v, want blocks", StateListen.BindingFor(TCP))
	}
	// The reverse: a TIME_WAIT reservation is real, so it must not be dismissed
	// as already released.
	if StateTimeWait.BindingFor(TCP) != EffectOptionsDecide {
		t.Errorf("TIME_WAIT binding = %v, want options-decide", StateTimeWait.BindingFor(TCP))
	}
}

func TestUnrecognisedStateIsNotGuessed(t *testing.T) {
	for _, code := range []State{0x00, 0x0D, 0x42, 0xFF} {
		if got := code.String(); !strings.HasPrefix(got, "UNKNOWN(0x") {
			t.Errorf("state 0x%02x prints %q, want UNKNOWN(0x..)", uint8(code), got)
		}
		if got := code.BindingFor(TCP); got != EffectUnknown {
			t.Errorf("state 0x%02x binding = %v, want unknown (a guess here becomes a confident wrong answer)", uint8(code), got)
		}
		if got := code.NoteFor(TCP); got != "" {
			t.Errorf("state 0x%02x has a note %q, but nothing is known about it", uint8(code), got)
		}
		if got := code.NoteFor(UDP); got != "" {
			t.Errorf("state 0x%02x has a udp note %q, but nothing is known about it", uint8(code), got)
		}
	}
}

// Every entry has to carry its own explanation: a table that names a state but
// cannot say what it means is a table of codes, not semantics.
func TestEveryStateExplainsItself(t *testing.T) {
	for _, s := range KnownStates() {
		if strings.TrimSpace(s.NoteFor(TCP)) == "" {
			t.Errorf("%v has no note", s)
		}
		if s.BindingFor(TCP) == EffectUnknown {
			t.Errorf("%v is in the table but its binding effect is unknown", s)
		}
	}
}
