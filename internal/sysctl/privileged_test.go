package sysctl

import (
	"strings"
	"testing"
)

// The kernel prints one decimal number. Everything else is not a measurement,
// and a half-read boundary is worse than none: the sentence it feeds is about
// capabilities, so a wrong number sends someone to sudo for a port that needs no
// sudo, or to file a bug about a port that does.
func TestParsePortStartAcceptsOnlyOnePortNumber(t *testing.T) {
	cases := map[string]uint16{
		"0\n":      0,
		"1024\n":   1024,
		"  1024  ": 1024,
		"80":       80,
		"65535\n":  65535,
	}
	for raw, want := range cases {
		got, err := parsePortStart(raw)
		if err != nil {
			t.Errorf("parsePortStart(%q): %v", raw, err)
			continue
		}
		if got != want {
			t.Errorf("parsePortStart(%q) = %d, want %d", raw, got, want)
		}
	}
}

func TestParsePortStartRejectsEverythingElse(t *testing.T) {
	for name, raw := range map[string]string{
		"empty":        "",
		"whitespace":   " \t\n",
		"two numbers":  "1024 1024",
		"range":        "1024 65535",
		"negative":     "-1",
		"hexadecimal":  "0x400",
		"out of range": "65536",
		"words":        "yes",
	} {
		t.Run(name, func(t *testing.T) {
			got, err := parsePortStart(raw)
			if err == nil {
				t.Fatalf("accepted %q as %d", raw, got)
			}
			if got != 0 {
				t.Errorf("a rejected input still produced %d", got)
			}
		})
	}
}

// The comparison itself, at the three points that matter: below the boundary,
// exactly on it (the kernel's own definition is "lowest port you may bind
// unprivileged", so equality is not privileged), and above it.
func TestNeedsRootComparesAgainstTheMeasuredBoundary(t *testing.T) {
	p := PrivilegedPortStart{State: PrivilegedStartMeasured, Port: 1024, Path: "/proc/sys/x"}
	for _, c := range []struct {
		port uint16
		want bool
	}{
		{80, true},
		{1023, true},
		{1024, false},
		{1025, false},
		{8080, false},
	} {
		if got := p.NeedsRoot(c.port); got != c.want {
			t.Errorf("NeedsRoot(%d) = %v, want %v", c.port, got, c.want)
		}
	}
}

// Port 0 is "pick one for me", and the kernel picks from the ephemeral range
// where no capability is needed. Reporting it as privileged would be advice
// about a port the user never named.
func TestPortZeroIsNeverPrivileged(t *testing.T) {
	p := PrivilegedPortStart{State: PrivilegedStartMeasured, Port: 1024, Path: "/proc/sys/x"}
	if p.NeedsRoot(0) {
		t.Error("port 0 was reported as needing root")
	}
}

// The reverse assertion that matters most: an unmeasured or absent boundary may
// not answer "yes". "I did not look" is never "this port needs root".
func TestUnmeasuredBoundaryNeverClaimsPrivilege(t *testing.T) {
	for name, p := range map[string]PrivilegedPortStart{
		"unmeasured": {},
		"failed":     {Path: "/proc/sys/x", Err: "permission denied"},
		"absent":     {State: PrivilegedStartAbsent, Path: "/proc/sys/x"},
	} {
		t.Run(name, func(t *testing.T) {
			if p.Known() {
				t.Fatalf("%s reported itself as known", name)
			}
			for _, port := range []uint16{0, 22, 80, 1023, 1024, 8080} {
				if p.NeedsRoot(port) {
					t.Errorf("%s claimed port %d needs root", name, port)
				}
			}
		})
	}
}

// No fallback to 1024 anywhere in the sentences: a report that names the usual
// boundary on a host nobody read is the folklore this tool replaces.
func TestUnmeasuredBoundaryNeverPrintsTheUsualValue(t *testing.T) {
	for name, p := range map[string]PrivilegedPortStart{
		"unmeasured": {},
		"failed":     {Path: "/proc/sys/x", Err: "permission denied"},
		"absent":     {State: PrivilegedStartAbsent, Path: "/proc/sys/x"},
	} {
		t.Run(name, func(t *testing.T) {
			desc := p.Describe()
			if strings.Contains(desc, "1024") {
				t.Errorf("describe printed the traditional boundary: %q", desc)
			}
			if strings.TrimSpace(desc) == "" {
				t.Error("describe said nothing at all")
			}
		})
	}
}

// The measured sentence carries both halves: the number and the file, so a
// reader can check it without trusting the tool.
func TestMeasuredBoundaryDescribeCitesTheFile(t *testing.T) {
	p := PrivilegedPortStart{State: PrivilegedStartMeasured, Port: 1024, Raw: "1024\n",
		Path: "/proc/sys/net/ipv4/ip_unprivileged_port_start"}
	desc := p.Describe()
	for _, want := range []string{"1024", "ip_unprivileged_port_start", p.Path} {
		if !strings.Contains(desc, want) {
			t.Errorf("describe %q does not mention %q", desc, want)
		}
	}
}
