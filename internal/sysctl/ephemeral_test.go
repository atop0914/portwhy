package sysctl

import (
	"strings"
	"testing"
)

// The shapes the kernel really prints: two decimal numbers separated by a tab.
// The rest of the accepted forms are whitespace variants, because reading this
// file must not depend on which byte happens to separate the fields.
func TestParsePortRangeAcceptsKernelShapes(t *testing.T) {
	cases := []struct {
		raw       string
		low, high uint16
	}{
		{"32768\t60999\n", 32768, 60999},
		{"32768 60999\n", 32768, 60999},
		{"  1024   65535  ", 1024, 65535},
		{"0\t65535", 0, 65535},
		{"8080 8080", 8080, 8080},
	}
	for _, c := range cases {
		t.Run(strings.ReplaceAll(strings.TrimSpace(c.raw), "\t", "\\t"), func(t *testing.T) {
			low, high, err := parsePortRange(c.raw)
			if err != nil {
				t.Fatalf("parsePortRange(%q): %v", c.raw, err)
			}
			if low != c.low || high != c.high {
				t.Errorf("got %d-%d, want %d-%d", low, high, c.low, c.high)
			}
		})
	}
}

// Every malformed shape must produce an error and no numbers at all. The one
// outcome this must never have is a half-parsed interval, because a report that
// prints an interval is a report that claims to have measured one.
func TestParsePortRangeRejectsWithoutInventingNumbers(t *testing.T) {
	cases := map[string]string{
		"empty":         "",
		"whitespace":    " \t\n",
		"not numbers":   "abc\n",
		"one number":    "40000\n",
		"three numbers": "40000 40999 1\n",
		"reversed":      "60000 30000\n",
		"out of range":  "0 70000\n",
		"negative":      "-1 100\n",
		"hexadecimal":   "0x8000 0xee67\n",
		"words":         "low high\n",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			low, high, err := parsePortRange(raw)
			if err == nil {
				t.Fatalf("accepted %q as %d-%d", raw, low, high)
			}
			if low != 0 || high != 0 {
				t.Errorf("a rejected input still produced %d-%d", low, high)
			}
		})
	}
}

// An empty reserved-ports file is a measurement, and the most common one:
// nothing has been carved out of the ephemeral pool. Parsing it as an error
// would erase the distinction the whole type exists to keep.
func TestParseReservedPortsEmptyIsMeasuredEmpty(t *testing.T) {
	for _, raw := range []string{"", "\n", "  \t\n"} {
		iv, err := parseReservedPorts(raw)
		if err != nil {
			t.Fatalf("parseReservedPorts(%q): %v", raw, err)
		}
		if len(iv) != 0 {
			t.Errorf("parseReservedPorts(%q) = %v, want nothing reserved", raw, iv)
		}
	}
}

func TestParseReservedPortsReadsPortsAndRanges(t *testing.T) {
	cases := []struct {
		raw  string
		want []PortInterval
	}{
		{"50000\n", []PortInterval{{50000, 50000}}},
		{"50000,50100-50200\n", []PortInterval{{50000, 50000}, {50100, 50200}}},
		{" 50000 , 50100-50200 \n", []PortInterval{{50000, 50000}, {50100, 50200}}},
		// Sorted and merged: two runs over one file must print one thing.
		{"50100-50200,50000\n", []PortInterval{{50000, 50000}, {50100, 50200}}},
		{"50000-50010,50005-50020\n", []PortInterval{{50000, 50020}}},
		{"50000,50001\n", []PortInterval{{50000, 50001}}},
		{"0-1023\n", []PortInterval{{0, 1023}}},
		{"65535\n", []PortInterval{{65535, 65535}}},
	}
	for _, c := range cases {
		t.Run(strings.TrimSpace(c.raw), func(t *testing.T) {
			iv, err := parseReservedPorts(c.raw)
			if err != nil {
				t.Fatalf("parseReservedPorts(%q): %v", c.raw, err)
			}
			if len(iv) != len(c.want) {
				t.Fatalf("got %v, want %v", iv, c.want)
			}
			for i := range iv {
				if iv[i] != c.want[i] {
					t.Errorf("interval %d = %v, want %v", i, iv[i], c.want[i])
				}
			}
		})
	}
}

// Malformed reservation lists are rejected whole. Half-reading "50000,abc" would
// report 50000 as reserved on the strength of a file the tool does not
// understand, and the user would trust it.
func TestParseReservedPortsRejectsWholeList(t *testing.T) {
	cases := map[string]string{
		"word":            "abc\n",
		"empty entry":     "50000,,50100\n",
		"trailing comma":  "50000,\n",
		"reversed range":  "50200-50100\n",
		"out of range":    "50000,70000\n",
		"negative":        "-5\n",
		"missing end":     "50000-\n",
		"missing start":   "-50000\n",
		"hexadecimal":     "0xc350\n",
		"words in a list": "50000,abc\n",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if iv, err := parseReservedPorts(raw); err == nil {
				t.Fatalf("accepted %q as %v", raw, iv)
			}
		})
	}
}

// A measurement prints its numbers and its source; a failure prints its reason
// and no number. The reverse — a number without a source, or a failure without
// a reason — is what makes a diagnostic tool unquotable.
func TestDescribeCitesSourceOrReason(t *testing.T) {
	measured := PortRange{State: PortRangeMeasured, Low: 32768, High: 60999,
		Path: "/proc/sys/net/ipv4/ip_local_port_range"}
	if got := measured.Describe(); !strings.Contains(got, "32768-60999") || !strings.Contains(got, measured.Path) {
		t.Errorf("Describe() = %q, want the range and the path", got)
	}
	if !measured.Contains(32768) || !measured.Contains(60999) || measured.Contains(61000) || measured.Contains(32767) {
		t.Error("Contains does not match the measured interval edges")
	}
	if measured.Contains(0) {
		t.Error("an interval that starts at 32768 contains port 0")
	}

	broken := PortRange{Path: "/proc/sys/net/ipv4/ip_local_port_range", Err: "abc is not two port numbers"}
	if got := broken.Describe(); !strings.Contains(got, "abc is not two port numbers") || !strings.Contains(got, broken.Path) {
		t.Errorf("Describe() = %q, want the reason and the path", got)
	}
	if broken.Contains(40000) {
		t.Error("an unmeasured range claims to contain a port")
	}
	if strings.Contains(broken.Describe(), "32768") {
		t.Errorf("an unmeasured range printed a default: %q", broken.Describe())
	}

	unasked := PortRange{Path: "/proc/sys/net/ipv4/ip_local_port_range"}
	if got := unasked.Describe(); !strings.Contains(got, "not measured") {
		t.Errorf("Describe() = %q, want it to say nothing was measured", got)
	}
}

// The four states of the reservation file have to read differently, because
// three of them are "no reservation is known" for three different reasons.
func TestReservedPortsStatesReadDifferently(t *testing.T) {
	path := "/proc/sys/net/ipv4/ip_local_reserved_ports"

	empty := ReservedPorts{State: ReservedMeasured, Path: path, Raw: "\n"}
	if !empty.Known() || !empty.Empty() || empty.Contains(50000) {
		t.Errorf("empty file = %+v, want known and empty", empty)
	}
	if got := empty.Describe(); !strings.Contains(got, "is empty") {
		t.Errorf("Describe() = %q, want the measurement", got)
	}

	some := ReservedPorts{State: ReservedMeasured, Path: path, Raw: "50000,50100-50200\n",
		Intervals: []PortInterval{{50000, 50000}, {50100, 50200}}}
	if !some.Contains(50000) || !some.Contains(50150) || some.Contains(50300) {
		t.Error("Contains does not follow the parsed intervals")
	}
	if got := some.Describe(); !strings.Contains(got, "50100-50200") {
		t.Errorf("Describe() = %q, want the raw list", got)
	}

	absent := ReservedPorts{State: ReservedAbsent, Path: path}
	if absent.Known() || !absent.Absent() {
		t.Errorf("absent = %+v, want absent and not known", absent)
	}
	if got := absent.Describe(); !strings.Contains(got, "does not exist") {
		t.Errorf("Describe() = %q, want it to say the file is not there", got)
	}

	broken := ReservedPorts{Path: path, Err: "abc is not a port number 0-65535"}
	if broken.Known() || broken.Absent() || !strings.Contains(broken.Describe(), "abc") {
		t.Errorf("malformed = %+v / %q", broken, broken.Describe())
	}
	if broken.Contains(50000) {
		t.Error("a malformed file claims a port is reserved")
	}
}
