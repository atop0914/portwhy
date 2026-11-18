package verdict

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/atop0914/portwhy/internal/probe"
	"github.com/atop0914/portwhy/internal/procnet"
)

// probeAt is the instant every synthetic attempt is stamped with: a fixed time
// keeps the reason details diffable between runs, and it is the one thing the
// report must show for a probe.
var probeAt = time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

func attempt(mode probe.Mode, outcome probe.Outcome, errno string) probe.Attempt {
	a := probe.Attempt{Mode: mode, At: probeAt, Outcome: outcome, Errno: errno}
	switch outcome {
	case probe.OutcomeBound:
		a.Errno = ""
	case probe.OutcomeAddrInUse:
		a.Message = "address already in use"
	case probe.OutcomeNotPermitted:
		a.Message = "permission denied"
	default:
		a.Message = string(outcome)
	}
	return a
}

func reasonDetail(v Verdict, code string) (string, bool) {
	for _, r := range v.Reasons {
		if r.Code == code {
			return r.Detail, true
		}
	}
	return "", false
}

func freeTables() []procnet.Table {
	return []procnet.Table{table("tcp", procnet.TCP, procnet.V4)}
}

// The case this whole package exists for: the tables show nothing and the kernel
// still refuses the bind. The answer must stop being "free".
func TestProbeContradictsAFreeTableWithInvisibleHolder(t *testing.T) {
	v := Explain(query("127.0.0.1", 8080, procnet.TCP), freeTables(), Env{
		Probe: []probe.Attempt{attempt(probe.ModePlain, probe.OutcomeAddrInUse, "EADDRINUSE")},
	})
	if v.Kind != KindUnknown {
		t.Fatalf("kind = %v, want unknown: a refused bind must not leave a free answer standing", v.Kind)
	}
	detail, ok := reasonDetail(v, ReasonProbeHolds)
	if !ok {
		t.Fatal("missing bind-fails-but-table-shows-nothing reason")
	}
	if !strings.Contains(detail, "EADDRINUSE") {
		t.Errorf("detail %q does not name the errno", detail)
	}
	if !strings.Contains(detail, probeAt.Format(time.RFC3339)) {
		t.Errorf("detail %q does not say when the bind was refused", detail)
	}
	if hasReason(v, ReasonUnlistedBinding) {
		t.Error("the caveat is now the answer, not a limit: it should not be listed as a blind spot")
	}
}

// A successful plain bind closes the one gap a table cannot close — and closes
// nothing else. The kind stays "free" (which it already was) and the caveat it
// just disproved is removed.
func TestProbeBoundKeepsFreeAndDropsTheCaveatItDisproved(t *testing.T) {
	unprobed := Explain(query("127.0.0.1", 8080, procnet.TCP), freeTables(), Env{})
	if !hasReason(unprobed, ReasonUnlistedBinding) {
		t.Fatal("precondition: the unprobed answer must carry the blind-spot caveat")
	}

	v := Explain(query("127.0.0.1", 8080, procnet.TCP), freeTables(), Env{
		Probe: []probe.Attempt{attempt(probe.ModePlain, probe.OutcomeBound, "")},
	})
	if v.Kind != KindFree {
		t.Fatalf("kind = %v, want free", v.Kind)
	}
	if hasReason(v, ReasonUnlistedBinding) {
		t.Error("a caveat that was just tested and found false must not stay in the report")
	}
	if hasReason(v, ReasonProbeNotRun) {
		t.Error("report says no bind was attempted after one was")
	}
	detail, ok := reasonDetail(v, ReasonProbeBound)
	if !ok {
		t.Fatal("missing bind-succeeded-at-probe-time reason")
	}
	if !strings.Contains(detail, probeAt.Format(time.RFC3339)) {
		t.Errorf("detail %q does not carry the instant the bind happened", detail)
	}
}

// A listener explains the refusal outright. The probe adds nothing and must not
// be dressed up as new evidence about an invisible holder.
func TestProbeRefusalOnAListenerIsCorroboration(t *testing.T) {
	tables := []procnet.Table{table("tcp", procnet.TCP, procnet.V4,
		sock(procnet.StateListen, "127.0.0.1", 8080, procnet.TCP))}
	v := Explain(query("127.0.0.1", 8080, procnet.TCP), tables, Env{
		Probe: []probe.Attempt{attempt(probe.ModePlain, probe.OutcomeAddrInUse, "EADDRINUSE")},
	})
	if v.Kind != KindListening {
		t.Fatalf("kind = %v, want listening", v.Kind)
	}
	if !hasReason(v, ReasonProbeRefused) {
		t.Error("missing probe-bind-was-refused reason")
	}
	if hasReason(v, ReasonProbeHolds) {
		t.Error("the invisible-holder diagnosis must not be claimed when a visible holder explains it")
	}
}

// TIME_WAIT plus "plain refused, SO_REUSEADDR bound" is the sentence that saves
// someone from hunting a process that does not exist.
func TestProbeOptionEvidenceOnTimeWait(t *testing.T) {
	tables := []procnet.Table{table("tcp", procnet.TCP, procnet.V4,
		sock(procnet.StateTimeWait, "127.0.0.1", 8080, procnet.TCP))}
	v := Explain(query("127.0.0.1", 8080, procnet.TCP), tables, Env{
		Probe: []probe.Attempt{
			attempt(probe.ModePlain, probe.OutcomeAddrInUse, "EADDRINUSE"),
			attempt(probe.ModeReuseAddr, probe.OutcomeBound, ""),
		},
	})
	if v.Kind != KindTimeWaitOnly {
		t.Fatalf("kind = %v, want time-wait-only", v.Kind)
	}
	detail, ok := reasonDetail(v, ReasonProbeOption)
	if !ok {
		t.Fatal("missing reuseaddr-would-succeed reason")
	}
	for _, want := range []string{"EADDRINUSE", probeAt.Format(time.RFC3339), "SO_REUSEADDR"} {
		if !strings.Contains(detail, want) {
			t.Errorf("detail %q does not mention %q", detail, want)
		}
	}
	if hasReason(v, ReasonProbeHolds) {
		t.Error("TIME_WAIT is a visible row: it must not be reported as an invisible holder")
	}
}

// The reverse of the case above, and the one that matters for trust: when the
// option was tried and refused, recommending it would be folklore.
func TestProbeDoesNotRecommendAnOptionItCouldNotProve(t *testing.T) {
	tables := []procnet.Table{table("tcp", procnet.TCP, procnet.V4,
		sock(procnet.StateTimeWait, "127.0.0.1", 8080, procnet.TCP))}
	v := Explain(query("127.0.0.1", 8080, procnet.TCP), tables, Env{
		Probe: []probe.Attempt{
			attempt(probe.ModePlain, probe.OutcomeAddrInUse, "EADDRINUSE"),
			attempt(probe.ModeReuseAddr, probe.OutcomeAddrInUse, "EADDRINUSE"),
		},
	})
	if v.Kind != KindTimeWaitOnly {
		t.Fatalf("kind = %v, want time-wait-only", v.Kind)
	}
	if hasReason(v, ReasonProbeOption) {
		t.Fatal("SO_REUSEADDR was refused, so the report must not say it would work")
	}
	detail, ok := reasonDetail(v, ReasonProbeRefused)
	if !ok {
		t.Fatal("missing probe-bind-was-refused reason")
	}
	if !strings.Contains(detail, "does not help") {
		t.Errorf("detail %q should say the option did not help", detail)
	}
}

// A probe that could not be made is a hole in the evidence. Every variant of
// that hole has to keep "free" off the table.
func TestProbeThatCouldNotRunIsNeverFree(t *testing.T) {
	cases := map[string]probe.Attempt{
		"EACCES":             attempt(probe.ModePlain, probe.OutcomeNotPermitted, "EACCES"),
		"EADDRNOTAVAIL":      attempt(probe.ModePlain, probe.OutcomeAddrNotAvailable, "EADDRNOTAVAIL"),
		"unclassified errno": attempt(probe.ModePlain, probe.OutcomeFailed, "EBUSY"),
		"socket refused": {Mode: probe.ModePlain, At: probeAt, Outcome: probe.OutcomeNotRun,
			Err: "socket: too many open files"},
		"close failed": {Mode: probe.ModePlain, At: probeAt, Outcome: probe.OutcomeBound,
			Err: "close: bad file descriptor"},
	}
	for name, a := range cases {
		v := Explain(query("127.0.0.1", 8080, procnet.TCP), freeTables(), Env{
			Probe: []probe.Attempt{a},
		})
		if v.Kind != KindUnknown {
			t.Errorf("%s: kind = %v, want unknown: a probe that did not answer must not leave free", name, v.Kind)
		}
		if !hasReason(v, ReasonProbeDenied) {
			t.Errorf("%s: missing probe-could-not-run reason", name)
		}
		if hasReason(v, ReasonProbeBound) {
			t.Errorf("%s: an untrustworthy attempt must not be reported as a successful bind", name)
		}
	}
}

// Evidence without the attempt the conclusion needs is its own limit: a
// SO_REUSEADDR success with no plain attempt says nothing about a plain bind.
func TestProbeWithoutPlainAttemptIsAGap(t *testing.T) {
	v := Explain(query("127.0.0.1", 8080, procnet.TCP), freeTables(), Env{
		Probe: []probe.Attempt{attempt(probe.ModeReuseAddr, probe.OutcomeBound, "")},
	})
	if v.Kind != KindUnknown {
		t.Fatalf("kind = %v, want unknown", v.Kind)
	}
	if !hasReason(v, ReasonProbeGap) {
		t.Error("missing probe-incomplete reason")
	}
	if hasReason(v, ReasonProbeOption) {
		t.Error("one option attempt is not the two-attempt diagnosis")
	}
}

// Tables read first, probe second: a success where the table named a holder
// means the two describe different instants. Reporting the stale holder would
// send someone to kill a process that no longer holds the port.
func TestProbeSucceedingWhereTheTableSaidHeldIsAConflict(t *testing.T) {
	tables := []procnet.Table{table("tcp", procnet.TCP, procnet.V4,
		sock(procnet.StateListen, "127.0.0.1", 8080, procnet.TCP))}
	v := Explain(query("127.0.0.1", 8080, procnet.TCP), tables, Env{
		Probe: []probe.Attempt{attempt(probe.ModePlain, probe.OutcomeBound, "")},
	})
	if v.Kind != KindUnknown {
		t.Fatalf("kind = %v, want unknown", v.Kind)
	}
	detail, ok := reasonDetail(v, ReasonProbeConflict)
	if !ok {
		t.Fatal("missing table-and-probe-disagree reason")
	}
	if !strings.Contains(detail, string(KindListening)) {
		t.Errorf("detail %q does not name what the table said", detail)
	}
}

// A probe is evidence, not an override: a gap this version has no model for
// (here an IPv6 wildcard that may shadow IPv4) survives a successful bind.
func TestProbeBoundDoesNotResolveAGapItHasNoModelFor(t *testing.T) {
	tables := []procnet.Table{
		table("tcp", procnet.TCP, procnet.V4),
		table("tcp6", procnet.TCP, procnet.V6, sock(procnet.StateListen, "::", 8080, procnet.TCP)),
	}
	v := Explain(query("127.0.0.1", 8080, procnet.TCP), tables, Env{
		Probe: []probe.Attempt{attempt(probe.ModePlain, probe.OutcomeBound, "")},
	})
	if v.Kind != KindUnknown {
		t.Fatalf("kind = %v, want unknown: the shadow question is unanswered", v.Kind)
	}
	if !hasReason(v, ReasonV6Wildcard) {
		t.Error("the wildcard question must stay visible")
	}
	if !hasReason(v, ReasonProbeBound) {
		t.Error("the successful bind must still be recorded")
	}
}

// "The same table, probed twice" has to produce the same answer, or the probe
// itself becomes the source of irreproducible reports.
func TestProbeEvidenceIsDeterministic(t *testing.T) {
	evidence := []probe.Attempt{
		attempt(probe.ModePlain, probe.OutcomeAddrInUse, "EADDRINUSE"),
		attempt(probe.ModeReuseAddr, probe.OutcomeBound, ""),
	}
	q := query("127.0.0.1", 8080, procnet.TCP)
	first := Explain(q, freeTables(), Env{Probe: evidence})
	second := Explain(q, freeTables(), Env{Probe: evidence})
	if !reflect.DeepEqual(first, second) {
		t.Errorf("two runs over the same evidence differ:\n%v\n%v", first, second)
	}
}

// The caveat belongs to a free answer and to nothing else. Leaving it next to a
// diagnosis that already covers it gives a reader two problems to solve and no
// way to tell that they are one.
func TestTheUnlistedCaveatOnlyAppearsOnAFreeAnswer(t *testing.T) {
	cases := map[string]struct {
		probe []probe.Attempt
		want  bool
	}{
		"no probe, free":      {nil, true},
		"bound, free":         {[]probe.Attempt{attempt(probe.ModePlain, probe.OutcomeBound, "")}, false},
		"refused, unknown":    {[]probe.Attempt{attempt(probe.ModePlain, probe.OutcomeAddrInUse, "EADDRINUSE")}, false},
		"denied, unknown":     {[]probe.Attempt{attempt(probe.ModePlain, probe.OutcomeNotPermitted, "EACCES")}, false},
		"untidy, unknown":     {[]probe.Attempt{{Mode: probe.ModePlain, At: probeAt, Outcome: probe.OutcomeBound, Err: "close: bad file descriptor"}}, false},
		"not run, unknown":    {[]probe.Attempt{{Mode: probe.ModePlain, At: probeAt, Outcome: probe.OutcomeNotRun, Err: "socket: refused"}}, false},
		"incomplete, unknown": {[]probe.Attempt{attempt(probe.ModeReuseAddr, probe.OutcomeBound, "")}, false},
	}
	for name, tc := range cases {
		v := Explain(query("127.0.0.1", 8080, procnet.TCP), freeTables(), Env{Probe: tc.probe})
		got := hasReason(v, ReasonUnlistedBinding)
		if got != tc.want {
			t.Errorf("%s: caveat present = %v, want %v (kind %s)", name, got, tc.want, v.Kind)
		}
		if got && v.Kind != KindFree {
			t.Errorf("%s: the caveat survived an answer that is not free (%s)", name, v.Kind)
		}
	}
}

// Without evidence the report must still say no bind was attempted: a reader
// who cannot tell "not probed" from "probed and free" will trust the wrong line.
func TestNoProbeStillDisclosesThatNothingWasAttempted(t *testing.T) {
	for name, tables := range map[string][]procnet.Table{
		"free":       freeTables(),
		"listening":  {table("tcp", procnet.TCP, procnet.V4, sock(procnet.StateListen, "127.0.0.1", 8080, procnet.TCP))},
		"unreadable": {table("tcp", procnet.TCP, procnet.V4)},
	} {
		v := Explain(query("127.0.0.1", 8080, procnet.TCP), tables, Env{})
		if !hasReason(v, ReasonProbeNotRun) {
			t.Errorf("%s: missing bind-not-probed reason", name)
		}
	}
}
