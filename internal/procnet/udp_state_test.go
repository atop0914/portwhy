package procnet

import "testing"

// The same number means different things in the two tables, and this is the one
// that would do real damage: st=07 is a socket the kernel has already released
// for TCP, and a socket that is *bound* for UDP. Read through the TCP table, a
// port that a plain bind() cannot take would be reported free.
func TestCloseMeansReleasedForTCPAndBoundForUDP(t *testing.T) {
	if got := StateClose.BindingFor(TCP); got != EffectTeardown {
		t.Errorf("CLOSE for tcp = %v, want teardown (the kernel has released it)", got)
	}
	if got := StateClose.BindingFor(UDP); got != EffectBlocks {
		t.Errorf("CLOSE for udp = %v, want blocks (this is a bound udp socket, verified on a live kernel)", got)
	}
	if StateClose.NoteFor(TCP) == StateClose.NoteFor(UDP) {
		t.Error("CLOSE has the same note in both protocols; the two readings are not the same fact")
	}
}

// A connected UDP socket keeps its local port bound too, so it belongs in the
// same bucket — but it is a different sentence, which is why it has its own note.
func TestEstablishedUDPAlsoBlocksBind(t *testing.T) {
	if got := StateEstablished.BindingFor(UDP); got != EffectBlocks {
		t.Errorf("ESTABLISHED for udp = %v, want blocks", got)
	}
	if StateEstablished.NoteFor(UDP) == StateEstablished.NoteFor(TCP) {
		t.Error("the connected-udp note is the tcp one")
	}
}

// UDP has no listening state, no TIME_WAIT and nothing to tear down. Every other
// code answers unknown rather than borrowing the TCP meaning: a table that
// borrowed it would confidently answer a question UDP cannot ask.
func TestUDPMustNotInheritTheTCPVocabulary(t *testing.T) {
	used := map[State]bool{StateClose: true, StateEstablished: true}
	for _, s := range KnownStates() {
		if used[s] {
			continue
		}
		if got := s.BindingFor(UDP); got != EffectUnknown {
			t.Errorf("%v reads as %v for udp; only CLOSE and ESTABLISHED occur there", s, got)
		}
		if got := s.NoteFor(UDP); got != "" {
			t.Errorf("%v has a udp note %q, but udp has no such state", s, got)
		}
	}
	if len(KnownUDPStates()) != 2 {
		t.Errorf("KnownUDPStates() = %v, want exactly two codes", KnownUDPStates())
	}
}

// A row carries its protocol, so the row-level reading cannot be taken from the
// wrong table by accident. This is the API the judgement uses.
func TestSocketBindingFollowsTheRowsOwnProtocol(t *testing.T) {
	s := Socket{Proto: UDP, State: StateClose}
	if got := s.Binding(); got != EffectBlocks {
		t.Errorf("udp row in CLOSE reads as %v, want blocks", got)
	}
	s.Proto = TCP
	if got := s.Binding(); got != EffectTeardown {
		t.Errorf("tcp row in CLOSE reads as %v, want teardown", got)
	}
}

// An unknown protocol is not a synonym for TCP. Guessing here would be the same
// failure as guessing a state.
func TestUnknownProtocolHasNoVocabulary(t *testing.T) {
	for _, p := range []Proto{0, 9} {
		if got := StateListen.BindingFor(p); got != EffectUnknown {
			t.Errorf("LISTEN under proto %d reads as %v, want unknown", p, got)
		}
		if got := StateListen.NoteFor(p); got != "" {
			t.Errorf("LISTEN under proto %d has a note %q", p, got)
		}
	}
}
