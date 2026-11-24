// Package wait decides when to stop waiting for a port to become bindable.
//
// It exists because "wait until the port is free" is the most common thing an
// operator does after reading a portwhy answer, and it is the easiest command in
// this tool to turn into a liar: an implementation that reports success on a
// timeout is worse than no command at all, because the script that trusted it
// goes on to start a service that cannot bind.
//
// Two rules shape it, and they are the same two the rest of the tool follows:
//
//  1. Success has exactly one source: a plain bind() the kernel accepted. Not a
//     table, not a guess, not the passage of time. Timeout therefore is never
//     success, and the kind it reports is the last round's — taken or unknown.
//  2. A gap in the evidence never becomes optimism. A table that could not be
//     read makes its round unknown and the wait continues; nothing here converts
//     "I could not look" into "free".
//
// The loop does not touch the machine: it is handed an observer that returns one
// Round, and a clock. That is what lets the awkward cases — a bind accepted on
// the last round, a deadline shorter than the interval, an observer that must not
// be called again — be tested without waiting for real seconds to pass.
package wait

import (
	"time"

	"github.com/atop0914/portwhy/internal/probe"
	"github.com/atop0914/portwhy/internal/verdict"
)

// End is why the loop stopped. It is a code, not prose: the CLI turns it into a
// sentence and the tests assert on it.
type End string

const (
	// EndBound means a plain bind() was accepted. It is the only success.
	EndBound End = "bound"
	// EndTimeout means the deadline passed without one.
	EndTimeout End = "timeout"
	// EndStopped means the round found an answer that waiting cannot change.
	EndStopped End = "stopped"
)

// Stop codes name the answers a longer wait cannot improve.
const (
	// StopNotPermitted is EACCES/EPERM: the refusal happened before the address
	// was considered, so the port may well be free and this process may still
	// never bind it. Waiting is the wrong response to a capability boundary.
	StopNotPermitted = "not-permitted"
	// StopAddrNotAvailable is EADDRNOTAVAIL: the address is not on this host, and
	// it will not appear because time passed.
	StopAddrNotAvailable = "addr-not-available"
	// StopProbeFailed is an errno this build does not classify. It cannot be
	// waited out either: nobody knows what it means yet.
	StopProbeFailed = "probe-failed"
	// StopProbeNotRun means no bind was attempted (no socket, unsupported
	// platform, unrepresentable address). It is not evidence, so waiting would
	// only produce more of the same nothing.
	StopProbeNotRun = "probe-not-run"
	// StopProbeBroken means the attempt did not complete cleanly — typically a
	// failed close(), which may leave this process holding the very address it
	// is asking about. Continuing would measure our own socket.
	StopProbeBroken = "probe-not-evidence"
	// StopBadOptions means the loop was asked for something that cannot be run
	// honestly (a zero interval would be a tight loop of real bind() calls).
	StopBadOptions = "bad-options"
)

// Notes record that a round's answer is not the table's own answer.
const (
	// NoteBindRefusedWithNoRow is the bind-without-listen hole: the tables were
	// readable, said free, and a plain bind was refused anyway. Free would be a
	// lie and taken would name a holder no table lists, so the round is unknown.
	NoteBindRefusedWithNoRow = "bind-refused-with-no-row"
	// NoteTableSaidTaken records that the bind was accepted while the table, read
	// a moment earlier, still showed a holder: the port was released in between,
	// which is exactly what the caller is waiting for.
	NoteTableSaidTaken = "table-said-taken-bind-accepted"
	// NoteBlindTable marks a round whose tables could not be read. The bind result
	// still stands, but the diagnosis behind the round was blind, and a reader who
	// saw only "unknown" would not know whether the table was empty or missing.
	NoteBlindTable = "table-unreadable-this-round"
)

// holding reports whether a kind claims something occupies the address.
//
// "free" and "unknown" say the opposite in two different ways, and a note that
// said the tables "still showed a holder" about either of them would be inventing
// a finding.
func holding(k verdict.Kind) bool {
	return k != verdict.KindFree && k != verdict.KindUnknown && k != ""
}

// Round is one observation: the tables at one instant, and the plain bind that
// followed it immediately.
type Round struct {
	// Index is 1-based; At is monotonic, measured from the start of the wait.
	Index int
	At    time.Duration
	// Kind is what this round supports once the bind is taken into account.
	Kind verdict.Kind
	// TableKind is what the tables alone said. It is kept so that a disagreement
	// between the two measurements can be reported instead of averaged away.
	TableKind verdict.Kind
	// Holes are the tables this round could not read. A round with holes is never
	// free: the bind decides success, but a reader still has to be told that the
	// diagnosis behind it was blind.
	Holes []verdict.TableHole
	Bind  probe.Attempt
	// Note is set when Kind is not the table's own answer.
	Note string
	// Stop is set when this round found an answer that waiting cannot change.
	Stop string
}

// Judge turns one table answer and one bind attempt into the round they support.
//
// The bind is the newer measurement, so it decides — but only in ways it can
// prove: it may make the answer free by being accepted, and it may make it
// unknown by being refused where the tables were silent. It never promotes a
// refusal into free, and it never promotes an unreadable table into anything.
func Judge(table verdict.Verdict, bind probe.Attempt) Round {
	r := Round{TableKind: table.Kind, Holes: table.TablesUnreadable, Bind: bind}
	switch {
	case !bind.Trustworthy():
		// NotRun (no socket, unsupported platform, unrepresentable address) and a
		// failed close() are both "not evidence". The second is the dangerous one:
		// the descriptor may still exist, so this process could be the holder.
		r.Kind = verdict.KindUnknown
		if bind.Outcome == probe.OutcomeNotRun {
			r.Stop = StopProbeNotRun
		} else {
			r.Stop = StopProbeBroken
		}
	case bind.Outcome == probe.OutcomeBound:
		r.Kind = verdict.KindFree
		// A table that also failed to read cannot reach here with a holding kind:
		// a hole forces the verdict to unknown. So this note is only about a real
		// disagreement — the port was let go between the two measurements.
		if holding(table.Kind) {
			r.Note = NoteTableSaidTaken
		}
	case bind.Outcome == probe.OutcomeAddrInUse:
		switch table.Kind {
		case verdict.KindFree:
			r.Kind = verdict.KindUnknown
			r.Note = NoteBindRefusedWithNoRow
		case verdict.KindUnknown:
			// The table could not answer either — a hole, an unrecognised state
			// code, an unresolved wildcard. Nothing can be added to that, and a
			// note claiming "no row" would be inventing a reading.
			r.Kind = verdict.KindUnknown
			if len(r.Holes) > 0 {
				r.Note = NoteBlindTable
			}
		default:
			// The tables explain the refusal, so this round carries their answer:
			// listening, bound, time-wait-only, or another holding state.
			r.Kind = table.Kind
		}
	default:
		// EACCES, EADDRNOTAVAIL, or an errno this build does not classify. None of
		// them means "busy", so none of them may be reported as taken, and none of
		// them will change because time passed.
		r.Kind = verdict.KindUnknown
		switch bind.Outcome {
		case probe.OutcomeNotPermitted:
			r.Stop = StopNotPermitted
		case probe.OutcomeAddrNotAvailable:
			r.Stop = StopAddrNotAvailable
		default:
			r.Stop = StopProbeFailed
		}
	}
	return r
}

// Options is the deadline and the cadence.
type Options struct {
	// Timeout is the deadline; zero means no deadline. The zero is deliberate and
	// the caller has to say it out loud: a default that quietly becomes an
	// infinite wait is something a user discovers at the worst moment.
	Timeout time.Duration
	// Interval is the pause between rounds. Zero is refused rather than replaced
	// by a default: a tight loop of real bind() calls is a side effect nobody
	// asked for.
	Interval time.Duration
	// Now and Sleep are injected so a test can run a 30-second deadline in
	// microseconds. Nil means the real clock.
	Now   func() time.Time
	Sleep func(time.Duration)
}

// Result is what happened.
type Result struct {
	End End
	// Kind is the answer the wait ends on: free when a bind was accepted,
	// otherwise the last round's kind. It is never free without EndBound.
	Kind verdict.Kind
	// Stop names why EndStopped happened.
	Stop string
	// Timeline is the first round, every round whose kind differs from the one
	// before it, and the round the wait ended on. It is the shape of the wait, not
	// a log: N identical rounds collapse, but the first and the last are always
	// there because "how it started" and "how it ended" are the two things a
	// reader checks.
	Timeline []Round
	Rounds   int
	// Attempts counts the rounds in which a bind() was really made. A round whose
	// socket could not be created is a round but not an attempt, and a report
	// that conflated them would overstate how hard the tool tried.
	Attempts int
	// Unreadable counts the rounds in which at least one table could not be read.
	// It has to reach the conclusion: "I waited 30s and it never freed" reads very
	// differently when half the rounds were blind.
	Unreadable int
	// Waited is the monotonic duration the wait covered.
	Waited time.Duration
}

// Run observes until the answer cannot improve.
//
// observe is called once per round and must itself read the tables and make one
// plain bind: reading them once and reusing the answer would turn the timeline
// into fiction.
func Run(o Options, observe func() Round) Result {
	if o.Interval <= 0 || o.Timeout < 0 {
		// Refusing before the first observation keeps the refusal honest: no bind
		// was made, so nothing was learned and nothing is claimed.
		return Result{End: EndStopped, Kind: verdict.KindUnknown, Stop: StopBadOptions}
	}
	now, sleep := o.Now, o.Sleep
	if now == nil {
		now = time.Now
	}
	if sleep == nil {
		sleep = time.Sleep
	}

	start := now()
	var res Result
	var last verdict.Kind
	var final Round
	for {
		r := observe()
		// Stamped after the attempt: At is the instant the answer describes, not
		// the instant the round began.
		r.At = now().Sub(start)
		res.Rounds++
		r.Index = res.Rounds
		final = r
		if r.Bind.Outcome != probe.OutcomeNotRun {
			res.Attempts++
		}
		if len(r.Holes) > 0 {
			res.Unreadable++
		}
		if len(res.Timeline) == 0 || r.Kind != last {
			res.Timeline = append(res.Timeline, r)
		}
		last = r.Kind

		if r.Stop != "" {
			res.End, res.Kind, res.Stop = EndStopped, verdict.KindUnknown, r.Stop
			break
		}
		if r.Bind.Outcome == probe.OutcomeBound && r.Bind.Trustworthy() {
			res.End, res.Kind = EndBound, verdict.KindFree
			break
		}
		if o.Timeout > 0 && r.At >= o.Timeout {
			// The deadline is checked after the round, so the last observation is
			// made at the deadline rather than at the last interval before it: "it
			// was still held when I gave up" is a measurement, "it was held a while
			// ago" is not.
			res.End, res.Kind = EndTimeout, r.Kind
			break
		}
		pause := o.Interval
		if o.Timeout > 0 {
			if remaining := o.Timeout - r.At; remaining < pause {
				pause = remaining
			}
		}
		sleep(pause)
	}
	res.Waited = final.At
	// The round the wait ended on is part of the timeline even when its kind is
	// one already listed: a timeout is the last observation, and hiding it behind
	// an earlier round of the same kind would drop the instant that mattered.
	if n := len(res.Timeline); n == 0 || res.Timeline[n-1].Index != final.Index {
		res.Timeline = append(res.Timeline, final)
	}
	return res
}
