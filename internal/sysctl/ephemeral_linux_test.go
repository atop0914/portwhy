//go:build linux

package sysctl

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// writeTunable lays out <dir>/net/ipv4/<name>, the path shape the readers
// expect, so a test can state what the host has without changing it.
func writeTunable(t *testing.T, name, body string) string {
	t.Helper()
	dir := t.TempDir()
	full := filepath.Join(dir, "net", "ipv4")
	if err := os.MkdirAll(full, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(full, name), []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return dir
}

func TestReadPortRangeFromFile(t *testing.T) {
	p := ReadPortRange(writeTunable(t, "ip_local_port_range", "40000\t40999\n"))
	if !p.Known() {
		t.Fatalf("not known: %s", p.Describe())
	}
	if p.Low != 40000 || p.High != 40999 {
		t.Errorf("range = %d-%d, want 40000-40999", p.Low, p.High)
	}
	if !strings.HasSuffix(p.Path, filepath.Join("net", "ipv4", "ip_local_port_range")) {
		t.Errorf("path = %q, want it to name the tunable", p.Path)
	}
	if p.Raw != "40000\t40999\n" {
		t.Errorf("raw = %q, want the file's own bytes", p.Raw)
	}
}

// The three ways of not getting a range. None of them may produce 32768-60999,
// and none may produce a half-range.
func TestReadPortRangeFailureIsNeverTheUsualDefault(t *testing.T) {
	cases := map[string]string{
		"malformed": "abc\n",
		"reversed":  "60000 30000\n",
		"one field": "40000\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			p := ReadPortRange(writeTunable(t, "ip_local_port_range", body))
			if p.Known() {
				t.Fatalf("accepted %q as %d-%d", body, p.Low, p.High)
			}
			if p.Err == "" {
				t.Error("no reason recorded")
			}
			if p.Low != 0 || p.High != 0 {
				t.Errorf("a failed read left an interval behind: %d-%d", p.Low, p.High)
			}
			if p.Contains(40000) {
				t.Error("a failed read claims a port is inside the range")
			}
		})
	}

	t.Run("missing", func(t *testing.T) {
		p := ReadPortRange(t.TempDir())
		if p.Known() || p.Err == "" {
			t.Fatalf("missing file = %+v, want an unmeasured value with a reason", p)
		}
	})
}

// An empty reservation file is the measurement "none". It must not be confused
// with the two states that are not measurements.
func TestReadReservedPortsDistinguishesEmptyFromUnreadableAndAbsent(t *testing.T) {
	t.Run("empty is measured", func(t *testing.T) {
		r := ReadReservedPorts(writeTunable(t, "ip_local_reserved_ports", "\n"))
		if !r.Known() || !r.Empty() {
			t.Fatalf("empty file = %+v, want a measured empty list", r)
		}
		if r.Absent() {
			t.Error("an empty file was reported as absent")
		}
	})

	t.Run("empty with no newline is measured too", func(t *testing.T) {
		r := ReadReservedPorts(writeTunable(t, "ip_local_reserved_ports", ""))
		if !r.Known() || !r.Empty() {
			t.Fatalf("zero-byte file = %+v, want a measured empty list", r)
		}
	})

	t.Run("absent is not empty", func(t *testing.T) {
		r := ReadReservedPorts(t.TempDir())
		if !r.Absent() {
			t.Fatalf("missing file = %+v, want absent", r)
		}
		if r.Known() || r.Empty() {
			t.Error("a missing file was treated as a measurement")
		}
	})

	t.Run("malformed is not empty", func(t *testing.T) {
		r := ReadReservedPorts(writeTunable(t, "ip_local_reserved_ports", "abc\n"))
		if r.Known() || r.Absent() || r.Err == "" {
			t.Fatalf("malformed file = %+v, want an unmeasured value with a reason", r)
		}
		if r.Empty() {
			t.Error("a file that could not be parsed was reported as 'nothing reserved'")
		}
	})
}

func TestReadReservedPortsFromFile(t *testing.T) {
	r := ReadReservedPorts(writeTunable(t, "ip_local_reserved_ports", "50000,50100-50200\n"))
	if !r.Known() || r.Empty() {
		t.Fatalf("not known or empty: %+v", r)
	}
	for _, port := range []uint16{50000, 50100, 50150, 50200} {
		if !r.Contains(port) {
			t.Errorf("port %d should be reserved", port)
		}
	}
	for _, port := range []uint16{49999, 50201} {
		if r.Contains(port) {
			t.Errorf("port %d should not be reserved", port)
		}
	}
}

// The live reading: whatever this kernel says has to come back unchanged. The
// fixture tests above pass just as well for a tool that prints a constant.
func TestReadPortRangeLive(t *testing.T) {
	p := ReadPortRange(DefaultDir)
	if !p.Known() {
		t.Fatalf("cannot read %s: %s", p.Path, p.Describe())
	}
	raw, err := os.ReadFile(p.Path)
	if err != nil {
		t.Fatalf("read %s: %v", p.Path, err)
	}
	fields := strings.Fields(string(raw))
	if len(fields) != 2 {
		t.Fatalf("kernel printed %q", raw)
	}
	low, err := strconv.Atoi(fields[0])
	if err != nil {
		t.Fatalf("kernel printed %q: %v", raw, err)
	}
	high, err := strconv.Atoi(fields[1])
	if err != nil {
		t.Fatalf("kernel printed %q: %v", raw, err)
	}
	if int(p.Low) != low || int(p.High) != high {
		t.Errorf("range = %d-%d, kernel says %d-%d", p.Low, p.High, low, high)
	}
	if !p.Contains(uint16(low)) || !p.Contains(uint16(high)) {
		t.Error("the measured range does not contain its own edges")
	}
	t.Logf("this host: %s", p.Describe())
}

func TestReadReservedPortsLive(t *testing.T) {
	r := ReadReservedPorts(DefaultDir)
	switch {
	case r.Known():
		raw, err := os.ReadFile(r.Path)
		if err != nil {
			t.Fatalf("read %s: %v", r.Path, err)
		}
		if r.Raw != string(raw) {
			t.Errorf("raw = %q, file says %q", r.Raw, raw)
		}
	case r.Absent():
		// A kernel without the tunable. Reported, not papered over.
		t.Logf("this kernel provides no reserved-ports tunable: %s", r.Describe())
	default:
		t.Fatalf("cannot read %s: %s", r.Path, r.Describe())
	}
	t.Logf("this host: %s", r.Describe())
}
