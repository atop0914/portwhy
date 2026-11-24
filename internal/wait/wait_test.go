package wait

import (
	"testing"
	"time"

	"github.com/atop0914/portwhy/internal/probe"
	"github.com/atop0914/portwhy/internal/verdict"
)

// fakeClock advances only when the loop sleeps, so every test states its timing
// as arithmetic instead of as wall-clock waiting.
type fakeClock struct {
	t      time.Duration
	sleeps []time.Duration
}

func (c *fakeClock) Now() time.Time { return time.Unix(0, 0).Add(c.t) }

func (c *fakeClock) Sleep(d time.Duration) {
	c.sleeps = append(c.sleeps, d)
	c.t += d
}

func (c *fakeClock) opts(timeout, interval time.Duration) Options {
	return Options{Timeout: timeout, Interval: interval, Now: c.Now, Sleep: c.Sleep}
}

// scripted hands out rounds in order and fails loudly when asked for one more.
//
// That panic is the reverse assertion in every test below that ends early: a loop
// which keeps polling after it has its answer, or after an answer waiting cannot
// change, asks for a round that was never scripted.
func scripted(t *testing.T, rounds ...Round) func() Round {
	t.Helper()
	i := 0
	return func() Round {
		if i >= len(rounds) {
			t.Fatalf("observer called %d time(s); the loop had no reason to keep waiting", i+1)
		}
		r := rounds[i]
		i++
		return r
	}
}

func bound() probe.Attempt {
	return probe.Attempt{Mode: probe.ModePlain, Outcome: probe.OutcomeBound}
}

func refused() probe.Attempt {
	return probe.Attempt{Mode: probe.ModePlain, Outcome: probe.OutcomeAddrInUse, Errno: "EADDRINUSE"}
}

func table(k verdict.Kind) verdict.Verdict { return verdict.Verdict{Kind: k} }

// round builds a round whose table answer and kind agree, which is the ordinary
// case; the disagreements are built by hand where a test needs one.
func round(kind verdict.Kind, bind probe.Attempt) Round {
	return Round{Kind: kind, TableKind: kind, Bind: bind}
}

// TestJudgeNeverInventsFreeWithoutAnAcceptedBind is the invariant the whole
// command rests on, asserted over every combination that can reach it.
func TestJudgeNeverInventsFreeWithoutAnAcceptedBind(t *testing.T) {
	cases := []struct {
		name  string
		table verdict.Kind
		bind  probe.Attempt
		want  verdict.Kind
		stop  string
		note  string
	}{
		{"free and accepted", verdict.KindFree, bound(), verdict.KindFree, "", ""},
		{"taken but accepted", verdict.KindListening, bound(), verdict.KindFree, "", NoteTableSaidTaken},
		{"free but refused", verdict.KindFree, refused(), verdict.KindUnknown, "", NoteBindRefusedWithNoRow},
		{"unreadable and refused", verdict.KindUnknown, refused(), verdict.KindUnknown, "", NoteBindRefusedWithNoRow},
		{"listening and refused", verdict.KindListening, refused(), verdict.KindListening, "", ""},
		{"time-wait and refused", verdict.KindTimeWaitOnly, refused(), verdict.KindTimeWaitOnly, "", ""},
		{"bound udp and refused", verdict.KindBound, refused(), verdict.KindBound, "", ""},
		{
			"denied", verdict.KindFree,
			probe.Attempt{Outcome: probe.OutcomeNotPermitted, Errno: "EACCES"},
			verdict.KindUnknown, StopNotPermitted, "",
		},
		{
			"denied despite a listener", verdict.KindListening,
			probe.Attempt{Outcome: probe.OutcomeNotPermitted, Errno: "EACCES"},
			verdict.KindUnknown, StopNotPermitted, "",
		},
		{
			"address not here", verdict.KindFree,
			probe.Attempt{Outcome: probe.OutcomeAddrNotAvailable, Errno: "EADDRNOTAVAIL"},
			verdict.KindUnknown, StopAddrNotAvailable, "",
		},
		{
			"unclassified errno", verdict.KindFree,
			probe.Attempt{Outcome: probe.OutcomeFailed, Errno: "ENOMEM"},
			verdict.KindUnknown, StopProbeFailed, "",
		},
		{
			"no attempt at all", verdict.KindFree,
			probe.Attempt{Outcome: probe.OutcomeNotRun, Err: "no socket"},
			verdict.KindUnknown, StopProbeNotRun, "",
		},
		{
			// A failed close may leave this process holding the address: the
			// attempt cannot be success, whatever bind() answered.
			"accepted but unclean", verdict.KindFree,
			probe.Attempt{Outcome: probe.OutcomeBound, Err: "close: bad file descriptor"},
			verdict.KindUnknown, StopProbeBroken, "",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := Judge(table(c.table), c.bind)
			if r.Kind != c.want {
				t.Errorf("kind = %s, want %s", r.Kind, c.want)
			}
			if r.Stop != c.stop {
				t.Errorf("stop = %q, want %q", r.Stop, c.stop)
			}
			if r.Note != c.note {
				t.Errorf("note = %q, want %q", r.Note, c.note)
			}
			if r.TableKind != c.table {
				t.Errorf("table kind = %s, want %s (the table's own answer must survive for the report)",
					r.TableKind, c.table)
			}
			// The invariant, restated as an assertion rather than trusted to the
			// branch table above: free needs an accepted, trustworthy attempt.
			if r.Kind == verdict.KindFree && (c.bind.Outcome != probe.OutcomeBound || !c.bind.Trustworthy()) {
				t.Errorf("free without an accepted bind: outcome %s, err %q", c.bind.Outcome, c.bind.Err)
			}
		})
	}
}

// A round that could not read a table must carry that hole into the result, even
// when the bind made the answer free: the success is real, the diagnosis behind
// it was blind, and the report has to be able to say both.
func TestJudgeKeepsTheHolesOfItsRound(t *testing.T) {
	v := verdict.Verdict{
		Kind:             verdict.KindUnknown,
		TablesUnreadable: []verdict.TableHole{{Name: "tcp", Err: "permission denied"}},
	}
	r := Judge(v, probe.Attempt{Outcome: probe.OutcomeAddrInUse, Errno: "EADDRINUSE"})
	if len(r.Holes) != 1 || r.Holes[0].Name != "tcp" {
		t.Fatalf("holes = %+v, want the unreadable tcp table", r.Holes)
	}
	if r.Kind != verdict.KindUnknown {
		t.Errorf("kind = %s, want unknown", r.Kind)
	}
}

func TestRunStopsOnTheFirstAcceptance(t *testing.T) {
	c := &fakeClock{}
	res := Run(c.opts(30*time.Second, 500*time.Millisecond), scripted(t, round(verdict.KindFree, bound())))

	if res.End != EndBound || res.Kind != verdict.KindFree {
		t.Fatalf("end = %s, kind = %s, want bound/free", res.End, res.Kind)
	}
	if res.Rounds != 1 || res.Attempts != 1 {
		t.Errorf("rounds = %d, attempts = %d, want 1/1", res.Rounds, res.Attempts)
	}
	if res.Waited != 0 {
		t.Errorf("waited = %s, want 0: the first attempt was accepted", res.Waited)
	}
	if len(c.sleeps) != 0 {
		t.Errorf("slept %v after a successful first attempt", c.sleeps)
	}
}

// The failure this command exists to avoid: a deadline reached is not a port
// freed. Asserted both on End and on Kind, because a caller may read either.
func TestRunTimeoutIsNeverSuccess(t *testing.T) {
	c := &fakeClock{}
	held := round(verdict.KindListening, refused())
	res := Run(c.opts(200*time.Millisecond, 50*time.Millisecond), scripted(t, held, held, held, held, held))

	if res.End != EndTimeout {
		t.Fatalf("end = %s, want timeout", res.End)
	}
	if res.Kind == verdict.KindFree || res.Kind == "" {
		t.Fatalf("kind = %q: a timeout must never report free", res.Kind)
	}
	if res.Kind != verdict.KindListening {
		t.Errorf("kind = %s, want the last round's answer (listening)", res.Kind)
	}
	if res.Rounds != 5 {
		t.Errorf("rounds = %d, want 5 (t=0,50,100,150,200ms)", res.Rounds)
	}
	if res.Waited != 200*time.Millisecond {
		t.Errorf("waited = %s, want 200ms", res.Waited)
	}
	if res.Attempts != res.Rounds {
		t.Errorf("attempts = %d, rounds = %d: every round made one bind", res.Attempts, res.Rounds)
	}
}

// A deadline shorter than the interval still gets one observation at the
// deadline. Sleeping a full interval past it would make the answer describe an
// instant that never was the one the user waited for.
func TestRunObservesAgainAtTheDeadlineInsteadOfSleepingPast(t *testing.T) {
	c := &fakeClock{}
	held := round(verdict.KindListening, refused())
	res := Run(c.opts(200*time.Millisecond, 500*time.Millisecond), scripted(t, held, held))

	if res.Rounds != 2 {
		t.Fatalf("rounds = %d, want 2 (one at 0, one at the deadline)", res.Rounds)
	}
	if len(c.sleeps) != 1 || c.sleeps[0] != 200*time.Millisecond {
		t.Errorf("sleeps = %v, want a single 200ms pause capped by the deadline", c.sleeps)
	}
	if res.Waited != 200*time.Millisecond {
		t.Errorf("waited = %s, want exactly the deadline", res.Waited)
	}
}

// Timeout 0 means no deadline. The loop must keep going — and must still end on
// the acceptance, not on a round count.
func TestRunWithoutADeadlineWaitsUntilAccepted(t *testing.T) {
	c := &fakeClock{}
	held := round(verdict.KindListening, refused())
	free := round(verdict.KindFree, bound())
	res := Run(c.opts(0, 100*time.Millisecond), scripted(t, held, held, free))

	if res.End != EndBound {
		t.Fatalf("end = %s, want bound", res.End)
	}
	if res.Rounds != 3 || res.Waited != 200*time.Millisecond {
		t.Errorf("rounds = %d, waited = %s; want 3 and 200ms", res.Rounds, res.Waited)
	}
	if len(c.sleeps) != 2 {
		t.Errorf("sleeps = %v, want two intervals", c.sleeps)
	}
}

func TestRunTimelineKeepsTheFirstRoundEveryChangeAndTheLast(t *testing.T) {
	c := &fakeClock{}
	held := round(verdict.KindListening, refused())
	blind := round(verdict.KindUnknown, refused())
	free := round(verdict.KindFree, bound())
	// Five rounds, three distinct kinds, with repeats that must collapse.
	res := Run(c.opts(0, 50*time.Millisecond),
		scripted(t, held, held, blind, blind, free))

	got := make([]verdict.Kind, 0, len(res.Timeline))
	gotRounds := make([]int, 0, len(res.Timeline))
	for _, r := range res.Timeline {
		got = append(got, r.Kind)
		gotRounds = append(gotRounds, r.Index)
	}
	want := []verdict.Kind{verdict.KindListening, verdict.KindUnknown, verdict.KindFree}
	if len(got) != len(want) {
		t.Fatalf("timeline kinds = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("timeline[%d] = %s, want %s", i, got[i], want[i])
		}
	}
	// The repeats collapse onto the observations that changed something.
	if gotRounds[0] != 1 || gotRounds[1] != 3 || gotRounds[2] != 5 {
		t.Errorf("timeline rounds = %v, want [1 3 5]", gotRounds)
	}
	// The first row is the first observation, at the instant it was made.
	if res.Timeline[0].At != 0 {
		t.Errorf("first row at = %s, want 0", res.Timeline[0].At)
	}
}

// A wait that never changes kind still reports two instants: the first look and
// the one the wait gave up on. One row would hide the fact that it kept looking.
func TestRunTimelineKeepsTheFirstAndTheFinalRound(t *testing.T) {
	c := &fakeClock{}
	held := round(verdict.KindListening, refused())
	res := Run(c.opts(200*time.Millisecond, 50*time.Millisecond),
		scripted(t, held, held, held, held, held))

	if len(res.Timeline) != 2 {
		t.Fatalf("timeline = %d rows, want 2 (first and final)", len(res.Timeline))
	}
	if res.Timeline[0].Index != 1 || res.Timeline[1].Index != 5 {
		t.Errorf("timeline rounds = [%d %d], want [1 5]", res.Timeline[0].Index, res.Timeline[1].Index)
	}
	if res.Timeline[1].At != 200*time.Millisecond {
		t.Errorf("final row at = %s, want 200ms", res.Timeline[1].At)
	}
	for i, r := range res.Timeline {
		if r.Kind != verdict.KindListening {
			t.Errorf("timeline[%d] kind = %s, want listening", i, r.Kind)
		}
	}
}

// A blind wait must end unknown, and must count the blind rounds. "It never
// freed in 200ms" is a very different sentence when every round was blind.
func TestRunCountsBlindRoundsAndEndsUnknown(t *testing.T) {
	c := &fakeClock{}
	blind := Round{
		Kind:      verdict.KindUnknown,
		TableKind: verdict.KindUnknown,
		Holes:     []verdict.TableHole{{Name: "tcp", Err: "is a directory"}},
		Bind:      probe.Attempt{Outcome: probe.OutcomeAddrInUse, Errno: "EADDRINUSE"},
	}
	res := Run(c.opts(100*time.Millisecond, 50*time.Millisecond), scripted(t, blind, blind, blind))

	if res.End != EndTimeout {
		t.Fatalf("end = %s, want timeout", res.End)
	}
	if res.Kind != verdict.KindUnknown {
		t.Errorf("kind = %s, want unknown: no round could read the table", res.Kind)
	}
	if res.Unreadable != res.Rounds {
		t.Errorf("unreadable = %d of %d rounds, want every round counted", res.Unreadable, res.Rounds)
	}
}

// EACCES and EADDRNOTAVAIL are answers, not delays: the loop stops at once.
func TestRunStopsOnAnAnswerWaitingCannotChange(t *testing.T) {
	c := &fakeClock{}
	held := round(verdict.KindListening, refused())
	denied := Round{
		Kind:      verdict.KindUnknown,
		TableKind: verdict.KindFree,
		Bind:      probe.Attempt{Outcome: probe.OutcomeNotPermitted, Errno: "EACCES"},
		Stop:      StopNotPermitted,
	}
	// A third round is scripted but must never be asked for.
	res := Run(c.opts(0, 50*time.Millisecond), scripted(t, held, denied, held))

	if res.End != EndStopped {
		t.Fatalf("end = %s, want stopped", res.End)
	}
	if res.Stop != StopNotPermitted {
		t.Errorf("stop = %q, want %q", res.Stop, StopNotPermitted)
	}
	if res.Rounds != 2 {
		t.Errorf("rounds = %d, want 2: the loop must not keep waiting on a capability boundary", res.Rounds)
	}
	if res.Kind != verdict.KindUnknown {
		t.Errorf("kind = %s, want unknown (neither free nor taken)", res.Kind)
	}
	// One sleep between the two rounds, and none after the stop.
	if len(c.sleeps) != 1 {
		t.Errorf("sleeps = %v, want exactly one", c.sleeps)
	}
}

// A round whose socket could not be created is a round but not an attempt, and
// it must not be waited out: every further round would fail the same way.
func TestRunDoesNotCountAnAttemptThatNeverHappened(t *testing.T) {
	c := &fakeClock{}
	noSocket := Round{
		Kind:      verdict.KindUnknown,
		TableKind: verdict.KindFree,
		Bind:      probe.Attempt{Outcome: probe.OutcomeNotRun, Err: "socket: too many open files"},
		Stop:      StopProbeNotRun,
	}
	res := Run(c.opts(0, 50*time.Millisecond), scripted(t, noSocket))

	if res.Attempts != 0 {
		t.Errorf("attempts = %d, want 0: no bind() was made", res.Attempts)
	}
	if res.Rounds != 1 {
		t.Errorf("rounds = %d, want 1", res.Rounds)
	}
	if res.End != EndStopped || res.Stop != StopProbeNotRun {
		t.Errorf("end = %s stop = %q, want stopped/probe-not-run", res.End, res.Stop)
	}
}

// Zero or negative cadence would be a tight loop of real bind() calls. It is
// refused before the first observation, so nothing is claimed about a port.
func TestRunRefusesACadenceThatWouldSpin(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts Options
	}{
		{"zero interval", Options{Timeout: time.Second, Interval: 0}},
		{"negative interval", Options{Timeout: time.Second, Interval: -time.Millisecond}},
		{"negative timeout", Options{Timeout: -time.Second, Interval: time.Millisecond}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := Run(tc.opts, func() Round {
				t.Fatal("observer called: a refused cadence must not touch the machine")
				return Round{}
			})
			if res.End != EndStopped || res.Stop != StopBadOptions {
				t.Fatalf("end = %s stop = %q, want stopped/bad-options", res.End, res.Stop)
			}
			if res.Rounds != 0 || res.Attempts != 0 {
				t.Errorf("rounds = %d, attempts = %d, want 0/0", res.Rounds, res.Attempts)
			}
		})
	}
}
