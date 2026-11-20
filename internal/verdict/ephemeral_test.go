package verdict

import (
	"errors"
	"strings"
	"testing"

	"github.com/atop0914/portwhy/internal/procnet"
	"github.com/atop0914/portwhy/internal/sysctl"
)

const (
	rangePath    = "/proc/sys/net/ipv4/ip_local_port_range"
	reservedPath = "/proc/sys/net/ipv4/ip_local_reserved_ports"
)

// measuredRange is what internal/sysctl hands in after a successful read. The
// real path is used so the details these tests assert on are the details a user
// reads.
func measuredRange(low, high uint16) sysctl.PortRange {
	return sysctl.PortRange{State: sysctl.PortRangeMeasured, Low: low, High: high, Path: rangePath}
}

func unreadableRange() sysctl.PortRange {
	return sysctl.PortRange{Path: rangePath, Err: "open /proc/sys/net/ipv4/ip_local_port_range: permission denied"}
}

func malformedRange() sysctl.PortRange {
	return sysctl.PortRange{Path: rangePath, Err: `"abc" is not two port numbers`}
}

func noReserved() sysctl.ReservedPorts {
	return sysctl.ReservedPorts{State: sysctl.ReservedMeasured, Path: reservedPath, Raw: "\n"}
}

func reservedRange(low, high uint16) sysctl.ReservedPorts {
	return sysctl.ReservedPorts{
		State:     sysctl.ReservedMeasured,
		Path:      reservedPath,
		Raw:       "50000-50100\n",
		Intervals: []sysctl.PortInterval{{Low: low, High: high}},
	}
}

func unreadableReserved() sysctl.ReservedPorts {
	return sysctl.ReservedPorts{Path: reservedPath, Err: "open /proc/sys/net/ipv4/ip_local_reserved_ports: input/output error"}
}

func absentReserved() sysctl.ReservedPorts {
	return sysctl.ReservedPorts{State: sysctl.ReservedAbsent, Path: reservedPath}
}

func emptyTCP() []procnet.Table {
	return []procnet.Table{table("tcp", procnet.TCP, procnet.V4)}
}

// The acceptance case: a free port inside the measured range gets the risk
// reason, with the interval, the file it came from, and the mechanism. It stays
// free — that is the whole point of the day.
func TestEphemeralRangeIsRiskAndStaysFree(t *testing.T) {
	env := Env{Ephemeral: measuredRange(32768, 60999), Reserved: noReserved()}
	v := Explain(query("127.0.0.1", 50000, procnet.TCP), emptyTCP(), env)

	if v.Kind != KindFree {
		t.Fatalf("kind = %v, want free: a port in the ephemeral pool may still be free right now", v.Kind)
	}
	detail, ok := reasonDetail(v, ReasonEphemeralRange)
	if !ok {
		t.Fatal("missing port-in-ephemeral-range reason")
	}
	for _, want := range []string{"50000", "32768-60999", rangePath, "source port", "outbound"} {
		if !strings.Contains(detail, want) {
			t.Errorf("detail %q does not mention %q", detail, want)
		}
	}
	if hasReason(v, ReasonEphemeralReserved) {
		t.Error("a port that is not reserved was reported as reserved")
	}
	if hasReason(v, ReasonEphemeralUnreadable) {
		t.Error("a measured range was reported as unreadable")
	}
	// Free still owes its own caveat: the risk does not replace the blind spot.
	if !hasReason(v, ReasonUnlistedBinding) {
		t.Error("free answer lost the bind-without-listen caveat")
	}
}

// The reverse assertion: outside the pool the tool must say nothing at all about
// it. A report that mentions the ephemeral range for every port teaches readers
// to skip it.
func TestEphemeralRangeSaysNothingOutsideIt(t *testing.T) {
	env := Env{Ephemeral: measuredRange(32768, 60999), Reserved: noReserved()}
	for _, port := range []uint16{8080, 32767, 61000, 443} {
		v := Explain(query("127.0.0.1", port, procnet.TCP), emptyTCP(), env)
		if v.Kind != KindFree {
			t.Fatalf("port %d: kind = %v, want free", port, v.Kind)
		}
		for _, code := range []string{ReasonEphemeralRange, ReasonEphemeralReserved, ReasonEphemeralUnreadable} {
			if hasReason(v, code) {
				t.Errorf("port %d outside the range produced %s", port, code)
			}
		}
	}
}

// Reserved is the good news, and it replaces the risk rather than joining it:
// "the kernel will hand this out as a source port" and "the kernel will never
// hand this out" cannot both be in one report.
func TestEphemeralReservedReplacesTheRisk(t *testing.T) {
	env := Env{Ephemeral: measuredRange(32768, 60999), Reserved: reservedRange(50000, 50100)}
	v := Explain(query("127.0.0.1", 50000, procnet.TCP), emptyTCP(), env)

	if v.Kind != KindFree {
		t.Fatalf("kind = %v, want free", v.Kind)
	}
	if hasReason(v, ReasonEphemeralRange) {
		t.Error("a reserved port still carries the risk reason")
	}
	detail, ok := reasonDetail(v, ReasonEphemeralReserved)
	if !ok {
		t.Fatal("missing port-reserved-from-ephemeral reason")
	}
	for _, want := range []string{"50000", "excluded", "32768-60999"} {
		if !strings.Contains(detail, want) {
			t.Errorf("detail %q does not mention %q", detail, want)
		}
	}
}

// A reserved port outside the pool is not "good news" worth printing either: the
// reservation only means something to a port that would otherwise be in the pool.
func TestEphemeralReservedOutsideRangeSaysNothing(t *testing.T) {
	env := Env{Ephemeral: measuredRange(32768, 40000), Reserved: reservedRange(50000, 50100)}
	v := Explain(query("127.0.0.1", 50000, procnet.TCP), emptyTCP(), env)
	if hasReason(v, ReasonEphemeralReserved) || hasReason(v, ReasonEphemeralRange) {
		t.Errorf("a reservation for another interval was reported: %v", v.Reasons)
	}
}

// A range that could not be read is a hole, and a hole on a free answer has to
// be stated. What must never appear is the default interval: printing 32768-60999
// for a host nobody read is this project's origin story.
func TestEphemeralUnreadableIsALimitOnFreeOnly(t *testing.T) {
	cases := map[string]sysctl.PortRange{
		"unreadable": unreadableRange(),
		"malformed":  malformedRange(),
		"unasked":    {Path: rangePath},
	}
	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			v := Explain(query("127.0.0.1", 50000, procnet.TCP), emptyTCP(),
				Env{Ephemeral: r, Reserved: noReserved()})
			if v.Kind != KindFree {
				t.Fatalf("kind = %v, want free: an unread range says nothing about who holds the port", v.Kind)
			}
			detail, ok := reasonDetail(v, ReasonEphemeralUnreadable)
			if !ok {
				t.Fatal("missing ephemeral-range-unreadable limit on a free answer")
			}
			if r.Err != "" && !strings.Contains(detail, rangePath) {
				t.Errorf("detail %q does not name the file it tried", detail)
			}
			if r.Err == "" && !strings.Contains(detail, "not measured") {
				t.Errorf("detail %q does not say nothing was measured", detail)
			}
			if hasReason(v, ReasonEphemeralRange) || hasReason(v, ReasonEphemeralReserved) {
				t.Error("an unmeasured range produced a statement about the pool")
			}
			for _, r := range v.Reasons {
				if strings.Contains(r.Detail, "32768") || strings.Contains(r.Detail, "60999") {
					t.Errorf("reason %s printed the usual default: %q", r.Code, r.Detail)
				}
			}
		})
	}
}

// The limit belongs to the free answer. A listener already settles the question
// the reader came with, and an extra "also, I did not read the pool" there is the
// noise Day 3 outlawed.
func TestEphemeralUnreadableIsNotStatedOnATakenAnswer(t *testing.T) {
	tables := []procnet.Table{table("tcp", procnet.TCP, procnet.V4,
		sock(procnet.StateListen, "127.0.0.1", 50000, procnet.TCP))}
	v := Explain(query("127.0.0.1", 50000, procnet.TCP), tables,
		Env{Ephemeral: unreadableRange(), Reserved: noReserved()})
	if v.Kind != KindListening {
		t.Fatalf("kind = %v, want listening", v.Kind)
	}
	if hasReason(v, ReasonEphemeralUnreadable) {
		t.Error("a taken answer carried the ephemeral-range limit")
	}
}

// The kind is not allowed to move. A listening port inside the pool is still
// listening, and the risk is printed next to that diagnosis, not instead of it.
func TestEphemeralRiskDoesNotChangeAKnownKind(t *testing.T) {
	tables := []procnet.Table{table("tcp", procnet.TCP, procnet.V4,
		sock(procnet.StateListen, "127.0.0.1", 50000, procnet.TCP))}
	v := Explain(query("127.0.0.1", 50000, procnet.TCP), tables,
		Env{Ephemeral: measuredRange(32768, 60999), Reserved: noReserved()})
	if v.Kind != KindListening {
		t.Fatalf("kind = %v, want listening", v.Kind)
	}
	if !hasReason(v, ReasonEphemeralRange) {
		t.Error("the risk disappeared when the port was held")
	}
}

// Not knowing whether the port was carved out is part of the risk. Saying "not
// excluded" here would claim a check that never ran.
func TestEphemeralRiskDisclosesAnUnreadReservationList(t *testing.T) {
	for name, r := range map[string]sysctl.ReservedPorts{
		"unreadable": unreadableReserved(),
		"absent":     absentReserved(),
	} {
		t.Run(name, func(t *testing.T) {
			v := Explain(query("127.0.0.1", 50000, procnet.TCP), emptyTCP(),
				Env{Ephemeral: measuredRange(32768, 60999), Reserved: r})
			detail, ok := reasonDetail(v, ReasonEphemeralRange)
			if !ok {
				t.Fatal("missing port-in-ephemeral-range reason")
			}
			if !strings.Contains(detail, "could not be read") {
				t.Errorf("detail %q does not disclose the unread reservation list", detail)
			}
			if strings.Contains(detail, "does not exclude it") {
				t.Errorf("detail %q claims a reservation check that never ran", detail)
			}
		})
	}
}

// Port 0 means "any port". The pool is where such a request is answered from, so
// warning about the pool would be advice about a port nobody named.
func TestEphemeralSaysNothingAboutPortZero(t *testing.T) {
	v := Explain(query("0.0.0.0", 0, procnet.TCP), emptyTCP(),
		Env{Ephemeral: measuredRange(0, 65535), Reserved: noReserved()})
	for _, code := range []string{ReasonEphemeralRange, ReasonEphemeralReserved, ReasonEphemeralUnreadable} {
		if hasReason(v, code) {
			t.Errorf("port 0 produced %s", code)
		}
	}
}

// The measurements are recorded even on the path that returns early (an
// unreadable table): a report that says what it read must not lose the reading
// because the answer happened to be unknown for another reason.
func TestEphemeralMeasurementsSurviveAnUnreadableTable(t *testing.T) {
	tables := []procnet.Table{{Name: "tcp", Proto: procnet.TCP, Family: procnet.V4,
		Err: errors.New("read: permission denied")}}
	env := Env{Ephemeral: measuredRange(32768, 60999), Reserved: reservedRange(50000, 50100)}
	v := Explain(query("127.0.0.1", 50000, procnet.TCP), tables, env)
	if v.Kind != KindUnknown {
		t.Fatalf("kind = %v, want unknown", v.Kind)
	}
	if !v.Ephemeral.Known() || v.Ephemeral.Low != 32768 || v.Ephemeral.High != 60999 {
		t.Errorf("ephemeral measurement lost on the early return: %+v", v.Ephemeral)
	}
	if !v.Reserved.Known() || !v.Reserved.Contains(50000) {
		t.Errorf("reserved measurement lost on the early return: %+v", v.Reserved)
	}
}

// Same table, same measurements, two runs: the reason sequence must be identical
// byte for byte, or nothing downstream can diff reports.
func TestEphemeralReasonSequenceIsStable(t *testing.T) {
	env := Env{Ephemeral: measuredRange(32768, 60999), Reserved: noReserved()}
	first := Explain(query("127.0.0.1", 50000, procnet.TCP), emptyTCP(), env)
	second := Explain(query("127.0.0.1", 50000, procnet.TCP), emptyTCP(), env)
	if len(first.Reasons) != len(second.Reasons) {
		t.Fatalf("reason counts differ: %d vs %d", len(first.Reasons), len(second.Reasons))
	}
	for i := range first.Reasons {
		if first.Reasons[i] != second.Reasons[i] {
			t.Errorf("reason %d differs: %+v vs %+v", i, first.Reasons[i], second.Reasons[i])
		}
	}
}
