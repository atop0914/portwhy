// Package probe asks the kernel the one question its tables cannot answer:
// "can I bind this address right now?".
//
// Everything up to this package reads state that the kernel chose to publish.
// A socket that was bound without listen() holds a port and appears in no table
// at all, so a table-only answer can never be more than "nothing readable is
// there". This package closes that gap by making the attempt for real.
//
// Two rules shape it. It never calls listen(): binding is enough to learn that
// the address is refused, and a listener would accept connections on the
// user's behalf. And it reports what happened at one instant, because that is
// all a probe can ever know — the port can be taken a microsecond later, so
// every consumer of these results has to pass that on rather than promise.
package probe

import "time"

// Mode is one way of asking for the address. The two differ in a socket option,
// and that difference is the point: "plain fails, SO_REUSEADDR succeeds" is the
// evidence that a TIME_WAIT reservation, not a process, is in the way.
type Mode string

const (
	// ModePlain sets no options at all.
	ModePlain Mode = "plain"
	// ModeReuseAddr sets SO_REUSEADDR, the option most advice on the internet
	// recommends without saying when it helps.
	ModeReuseAddr Mode = "reuseaddr"
)

// Outcome is what one bind() attempt produced, classified once here so that no
// report has to remember which errno means what.
type Outcome string

const (
	// OutcomeBound means the kernel accepted the bind. The socket was closed
	// immediately; nothing is left listening.
	OutcomeBound Outcome = "bound"
	// OutcomeAddrInUse means the address is held by something.
	OutcomeAddrInUse Outcome = "addr-in-use"
	// OutcomeNotPermitted means the attempt was refused before the address was
	// even considered (EACCES/EPERM, typically a privileged port as non-root).
	// It says nothing about who holds the port, and must never be read as
	// "free".
	OutcomeNotPermitted Outcome = "not-permitted"
	// OutcomeAddrNotAvailable means the address does not belong to this host
	// (EADDRNOTAVAIL). Also not an answer about occupation.
	OutcomeAddrNotAvailable Outcome = "addr-not-available"
	// OutcomeFailed is any other errno: a real failure this build does not
	// classify.
	OutcomeFailed Outcome = "failed"
	// OutcomeNotRun means no bind() was attempted: the socket could not be
	// created, the address cannot be expressed, or this platform has no
	// implementation. It is the only outcome that is not evidence at all.
	OutcomeNotRun Outcome = "not-run"
)

// Attempt is one bind() that was really made.
//
// Err is deliberately separate from Outcome. Outcome is what the kernel said
// about the address; Err records anything that makes the attempt untrustworthy
// (socket() refused, close() failed so the socket may still be held). An
// attempt with a non-empty Err is not evidence, whatever its Outcome says.
type Attempt struct {
	Mode    Mode
	At      time.Time
	Outcome Outcome
	// Errno is the kernel's own name for the failure ("EADDRINUSE"), empty when
	// no errno was involved.
	Errno string
	// Message is the kernel's sentence, or the Go error text when the failure
	// happened before bind().
	Message string
	// Err is set when the attempt did not complete cleanly.
	Err string
}

// Trustworthy reports whether this attempt may be used as evidence.
func (a Attempt) Trustworthy() bool {
	return a.Err == "" && a.Outcome != OutcomeNotRun
}
