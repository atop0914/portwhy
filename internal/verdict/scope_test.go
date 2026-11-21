package verdict

import (
	"strings"
	"testing"

	"github.com/atop0914/portwhy/internal/netns"
	"github.com/atop0914/portwhy/internal/probe"
	"github.com/atop0914/portwhy/internal/procnet"
	"github.com/atop0914/portwhy/internal/sysctl"
)

const privPath = "/proc/sys/net/ipv4/ip_unprivileged_port_start"

// measuredBoundary is what internal/sysctl hands in after a successful read. The
// real path is used so the details these tests assert on are the details a user
// reads.
func measuredBoundary(port uint16) sysctl.PrivilegedPortStart {
	return sysctl.PrivilegedPortStart{State: sysctl.PrivilegedStartMeasured, Port: port, Path: privPath}
}

func unreadableBoundary() sysctl.PrivilegedPortStart {
	return sysctl.PrivilegedPortStart{Path: privPath, Err: "open " + privPath + ": permission denied"}
}

func absentBoundary() sysctl.PrivilegedPortStart {
	return sysctl.PrivilegedPortStart{State: sysctl.PrivilegedStartAbsent, Path: privPath}
}

// heldBy is a lookup that names one process for every socket, so that a test can
// talk about an answer with findings without inventing an owner per row.
func heldBy(pid int) func(procnet.Socket) []Owner {
	return func(procnet.Socket) []Owner { return []Owner{{PID: pid, Comm: "service", FD: 3}} }
}

// The acceptance case: below the measured boundary, on a free port, the report
// states the capability rule with the number it compared against — and the kind
// does not move, because nothing holds the port.
func TestPrivilegedPortIsStatedOnAFreeAnswerAndStaysFree(t *testing.T) {
	v := Explain(query("127.0.0.1", 80, procnet.TCP), freeTables(), Env{
		Privileged: measuredBoundary(1024),
	})
	if v.Kind != KindFree {
		t.Fatalf("kind = %v, want free: needing root is not being taken", v.Kind)
	}
	detail, ok := reasonDetail(v, ReasonPrivilegedPort)
	if !ok {
		t.Fatalf("missing %s: %v", ReasonPrivilegedPort, v.Reasons)
	}
	for _, want := range []string{"80", "1024", privPath} {
		if !strings.Contains(detail, want) {
			t.Errorf("detail %q does not mention %q", detail, want)
		}
	}
	if hasReason(v, ReasonPrivilegedUnreadable) {
		t.Error("a measured boundary was reported as unreadable")
	}
}

// The container case, and the reason this reads the tunable at all: with the
// boundary at 0 nothing is privileged, so warning about port 80 would be wrong
// on every single run in a container.
func TestZeroBoundarySaysNothingAboutPort80(t *testing.T) {
	for _, port := range []uint16{1, 80, 1023} {
		v := Explain(query("127.0.0.1", port, procnet.TCP), freeTables(), Env{
			Privileged: measuredBoundary(0),
		})
		if hasReason(v, ReasonPrivilegedPort) {
			t.Errorf("port %d was reported as privileged on a host with boundary 0", port)
		}
	}
}

// Equality is not privileged: the tunable names the lowest port that may be
// bound without a capability.
func TestPortOnTheBoundaryIsNotPrivileged(t *testing.T) {
	v := Explain(query("127.0.0.1", 1024, procnet.TCP), freeTables(), Env{
		Privileged: measuredBoundary(1024),
	})
	if hasReason(v, ReasonPrivilegedPort) {
		t.Error("the boundary port itself was reported as needing root")
	}
}

// The reverse assertion for the noise rule: an answer that already names a
// holder does not also lecture about capabilities.
func TestPrivilegedPortIsSilentWhereTheAnswerIsAlreadyAboutAHolder(t *testing.T) {
	tables := []procnet.Table{table("tcp", procnet.TCP, procnet.V4,
		sock(procnet.StateListen, "127.0.0.1", 80, procnet.TCP))}
	v := Explain(query("127.0.0.1", 80, procnet.TCP), tables, Env{
		Privileged: measuredBoundary(1024),
		Lookup:     heldBy(4242),
	})
	if v.Kind != KindListening {
		t.Fatalf("kind = %v, want listening", v.Kind)
	}
	if hasReason(v, ReasonPrivilegedPort) {
		t.Error("a listening answer also carried the capability rule")
	}

	// Same rule for a TIME_WAIT answer: the reservation is the diagnosis.
	waiting := []procnet.Table{table("tcp", procnet.TCP, procnet.V4,
		sock(procnet.StateTimeWait, "127.0.0.1", 80, procnet.TCP))}
	if v := Explain(query("127.0.0.1", 80, procnet.TCP), waiting, Env{
		Privileged: measuredBoundary(1024),
	}); hasReason(v, ReasonPrivilegedPort) {
		t.Error("a time-wait answer also carried the capability rule")
	}
}

// The probe can explain an EACCES, and that is exactly where the boundary
// belongs: the answer is unknown, and the reason it is unknown has a name.
func TestPrivilegedPortExplainsAProbeRefusedWithEACCES(t *testing.T) {
	v := Explain(query("127.0.0.1", 80, procnet.TCP), freeTables(), Env{
		Privileged: measuredBoundary(1024),
		Probe:      []probe.Attempt{attempt(probe.ModePlain, probe.OutcomeNotPermitted, "EACCES")},
	})
	if v.Kind != KindUnknown {
		t.Fatalf("kind = %v, want unknown", v.Kind)
	}
	if !hasReason(v, ReasonProbeDenied) || !hasReason(v, ReasonPrivilegedPort) {
		t.Errorf("want both the probe refusal and the capability rule: %v", v.Reasons)
	}
}

// A boundary nobody could read is a hole, stated as one, with no number in it:
// printing 1024 here is the folklore this project replaces.
func TestUnreadableBoundaryIsALimitWithoutADefault(t *testing.T) {
	for name, boundary := range map[string]sysctl.PrivilegedPortStart{
		"failed read": unreadableBoundary(),
		"absent file": absentBoundary(),
		"unasked":     {},
	} {
		t.Run(name, func(t *testing.T) {
			v := Explain(query("127.0.0.1", 80, procnet.TCP), freeTables(), Env{Privileged: boundary})
			if v.Kind != KindFree {
				t.Fatalf("kind = %v, want free: an unread tunable is not evidence about holders", v.Kind)
			}
			detail, ok := reasonDetail(v, ReasonPrivilegedUnreadable)
			if !ok {
				t.Fatalf("missing %s: %v", ReasonPrivilegedUnreadable, v.Reasons)
			}
			if strings.Contains(detail, "1024") {
				t.Errorf("an unread boundary printed the traditional value: %q", detail)
			}
			if hasReason(v, ReasonPrivilegedPort) {
				t.Error("an unmeasured boundary still produced a capability claim")
			}
		})
	}
}

// The hole is stated on a free answer and nowhere else: a listening answer
// already answers the question the reader came with.
func TestUnreadableBoundaryIsSilentOnAHolderAnswer(t *testing.T) {
	tables := []procnet.Table{table("tcp", procnet.TCP, procnet.V4,
		sock(procnet.StateListen, "127.0.0.1", 80, procnet.TCP))}
	v := Explain(query("127.0.0.1", 80, procnet.TCP), tables, Env{
		Privileged: unreadableBoundary(),
		Lookup:     heldBy(4242),
	})
	if v.Kind != KindListening {
		t.Fatalf("kind = %v, want listening", v.Kind)
	}
	if hasReason(v, ReasonPrivilegedUnreadable) {
		t.Error("a listening answer also carried the missing-tunable caveat")
	}
}

// Port 0 is "pick one for me" and the kernel picks from the ephemeral pool, so
// there is no boundary to report against it in either direction.
func TestPortZeroSaysNothingAboutPrivilege(t *testing.T) {
	for name, env := range map[string]Env{
		"measured":   {Privileged: measuredBoundary(1024)},
		"unreadable": {Privileged: unreadableBoundary()},
	} {
		t.Run(name, func(t *testing.T) {
			v := Explain(query("0.0.0.0", 0, procnet.TCP), freeTables(), env)
			if hasReason(v, ReasonPrivilegedPort) || hasReason(v, ReasonPrivilegedUnreadable) {
				t.Errorf("port 0 carried a capability statement: %v", v.Reasons)
			}
		})
	}
}

// The dangerous case of the day: a free answer assembled from a walk that could
// not read every process. There is no socket to point at, so the missing
// processes are a holder nobody looked for — and the exit code stays 0, because
// this is a limit on the answer, not a different answer.
func TestIncompleteHolderLookupIsALimitOnAFreeAnswer(t *testing.T) {
	v := Explain(query("127.0.0.1", 8080, procnet.TCP), freeTables(), Env{
		Lookup:      heldBy(4242),
		ProcsRead:   12,
		ProcsDenied: 3,
	})
	if v.Kind != KindFree {
		t.Fatalf("kind = %v, want free: unreadable processes are a caveat, not a holder", v.Kind)
	}
	detail, ok := reasonDetail(v, ReasonHolderLookupIncomplete)
	if !ok {
		t.Fatalf("missing %s: %v", ReasonHolderLookupIncomplete, v.Reasons)
	}
	if !strings.Contains(detail, "3 of 15") {
		t.Errorf("detail %q does not say how much of the walk is missing", detail)
	}
	if hasReason(v, ReasonProcsDenied) {
		t.Error("the finding-scoped code was used on an answer with no finding")
	}
}

// Three reverse assertions, each a different mistake: no denials, no walk at
// all, and a full walk.
func TestIncompleteHolderLookupStaysQuietWhenItShould(t *testing.T) {
	t.Run("nothing denied", func(t *testing.T) {
		v := Explain(query("127.0.0.1", 8080, procnet.TCP), freeTables(), Env{
			Lookup: heldBy(4242), ProcsRead: 15,
		})
		if hasReason(v, ReasonHolderLookupIncomplete) {
			t.Error("a complete walk was reported as incomplete")
		}
	})
	t.Run("walk not attempted", func(t *testing.T) {
		// -no-holders: "not read" is not "could not read". Nothing was denied,
		// nothing was attempted, and the report already says no bind was probed.
		v := Explain(query("127.0.0.1", 8080, procnet.TCP), freeTables(), Env{
			ProcsDenied: 3,
		})
		if hasReason(v, ReasonHolderLookupIncomplete) || hasReason(v, ReasonProcsDenied) {
			t.Errorf("no walk was made, yet unreadable processes were reported: %v", v.Reasons)
		}
	})
	t.Run("answer is not free", func(t *testing.T) {
		tables := []procnet.Table{table("tcp", procnet.TCP, procnet.V4,
			sock(procnet.StateListen, "127.0.0.1", 8080, procnet.TCP))}
		v := Explain(query("127.0.0.1", 8080, procnet.TCP), tables, Env{
			Lookup: heldBy(4242), ProcsRead: 12, ProcsDenied: 3,
		})
		if hasReason(v, ReasonHolderLookupIncomplete) {
			t.Error("a holder answer also carried the free-answer caveat")
		}
	})
}

// A refused bind disproves the free answer, and with it every caveat that was
// attached to it. Leaving them behind would describe an answer nobody is
// looking at.
func TestProbeCollapseDropsTheFreeAnswerLimits(t *testing.T) {
	v := Explain(query("127.0.0.1", 8080, procnet.TCP), freeTables(), Env{
		Lookup:      heldBy(4242),
		ProcsRead:   12,
		ProcsDenied: 3,
		Privileged:  unreadableBoundary(),
		Probe:       []probe.Attempt{attempt(probe.ModePlain, probe.OutcomeAddrInUse, "EADDRINUSE")},
	})
	if v.Kind != KindUnknown {
		t.Fatalf("kind = %v, want unknown: a refused bind disproves free", v.Kind)
	}
	for _, code := range []string{ReasonHolderLookupIncomplete, ReasonPrivilegedUnreadable} {
		if hasReason(v, code) {
			t.Errorf("%s survived an answer that is no longer free", code)
		}
	}
	if !hasReason(v, ReasonProbeHolds) {
		t.Error("missing the reason the answer collapsed")
	}
}

// The finding-scoped code keeps its own meaning: a socket nobody can name is a
// different sentence from a walk that was incomplete, and neither may stand in
// for the other.
func TestUnnamedHolderStillUsesTheFindingScopedCode(t *testing.T) {
	// A real inode: inode 0 means "no descriptor exists", which is a different
	// sentence and would take this test off the path it is about.
	held := sock(procnet.StateListen, "127.0.0.1", 8080, procnet.TCP)
	held.Inode = 4242
	tables := []procnet.Table{table("tcp", procnet.TCP, procnet.V4, held)}
	v := Explain(query("127.0.0.1", 8080, procnet.TCP), tables, Env{
		Lookup:      func(procnet.Socket) []Owner { return nil },
		ProcsRead:   12,
		ProcsDenied: 3,
	})
	if !hasReason(v, ReasonProcsDenied) {
		t.Errorf("missing %s for a socket with no readable owner: %v", ReasonProcsDenied, v.Reasons)
	}
	if hasReason(v, ReasonHolderLookupIncomplete) {
		t.Error("the free-answer caveat was used on a finding")
	}
}

// The two new measurements are carried into the verdict rather than only used:
// a report that cites a number has to be able to show what it read, including
// when it read nothing.
func TestVerdictCarriesTheScopeEvidence(t *testing.T) {
	boundary := measuredBoundary(1024)
	ns := netns.Identity{Inode: 4026532488, Self: "net:[4026532488]", Same: netns.PIDOneSame}
	v := Explain(query("127.0.0.1", 80, procnet.TCP), freeTables(), Env{
		Privileged: boundary,
		NetNS:      ns,
	})
	if v.Privileged.Port != boundary.Port {
		t.Errorf("privileged = %+v, want the measurement that was handed in", v.Privileged)
	}
	if v.NetNS.Inode != ns.Inode {
		t.Errorf("netns = %+v, want the namespace that was handed in", v.NetNS)
	}
}
