//go:build linux

package sysctl

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestReadPrivilegedPortStartFromFile(t *testing.T) {
	p := ReadPrivilegedPortStart(writeTunable(t, "ip_unprivileged_port_start", "1024\n"))
	if !p.Known() {
		t.Fatalf("not known: %s", p.Describe())
	}
	if p.Port != 1024 {
		t.Errorf("port = %d, want 1024", p.Port)
	}
	if !strings.HasSuffix(p.Path, filepath.Join("net", "ipv4", "ip_unprivileged_port_start")) {
		t.Errorf("path = %q, want it to name the tunable", p.Path)
	}
	if p.Raw != "1024\n" {
		t.Errorf("raw = %q, want the file's own bytes", p.Raw)
	}
	// The boundary this file states is the boundary the answer uses.
	if !p.NeedsRoot(80) || p.NeedsRoot(1024) {
		t.Errorf("NeedsRoot disagrees with the file: 80 -> %v, 1024 -> %v",
			p.NeedsRoot(80), p.NeedsRoot(1024))
	}
}

// Zero is a real measurement, and it means "no port needs root". It must be
// read as a value, not as "nothing was read" — containers run this way, and
// warning about port 80 there would be wrong on every single run.
func TestZeroBoundaryIsMeasuredAndPrivilegesNothing(t *testing.T) {
	p := ReadPrivilegedPortStart(writeTunable(t, "ip_unprivileged_port_start", "0\n"))
	if !p.Known() {
		t.Fatalf("0 was not read as a measurement: %s", p.Describe())
	}
	if p.NeedsRoot(80) || p.NeedsRoot(1) {
		t.Error("a host with boundary 0 still reported privileged ports")
	}
}

// A missing file is its own state: a kernel without the tunable is not a
// broken host, and neither is a -sysctl directory without that file.
func TestMissingTunableIsAbsentNotFailed(t *testing.T) {
	dir := writeTunable(t, "ip_local_port_range", "40000 40999\n")
	p := ReadPrivilegedPortStart(dir)
	if !p.Absent() {
		t.Fatalf("state = %v (err %q), want absent", p.State, p.Err)
	}
	if p.Known() {
		t.Error("an absent tunable reported itself as known")
	}
	if !strings.Contains(p.Describe(), "does not exist") {
		t.Errorf("describe does not say the file is missing: %q", p.Describe())
	}
}

// A file that cannot be understood is a hole, and the value stays unset.
func TestMalformedTunableIsUnmeasured(t *testing.T) {
	for name, body := range map[string]string{
		"words":        "yes\n",
		"two numbers":  "1024 1024\n",
		"out of range": "70000\n",
		"blank":        "\n",
	} {
		t.Run(name, func(t *testing.T) {
			p := ReadPrivilegedPortStart(writeTunable(t, "ip_unprivileged_port_start", body))
			if p.Known() {
				t.Fatalf("accepted %q as %d", body, p.Port)
			}
			if p.Port != 0 {
				t.Errorf("a rejected file still produced %d", p.Port)
			}
			if strings.TrimSpace(p.Err) == "" {
				t.Error("no error recorded for the rejected file")
			}
		})
	}
}

// The live cross-check: what the reader reports is what this kernel publishes,
// read here independently. No fixture, and no assertion about which value it is
// — the point is agreement, not the number.
func TestReadPrivilegedPortStartMatchesThisHost(t *testing.T) {
	const path = "/proc/sys/net/ipv4/ip_unprivileged_port_start"
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("%s is not readable here: %v", path, err)
	}
	want, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Skipf("%s printed %q", path, raw)
	}

	p := ReadPrivilegedPortStart(DefaultDir)
	if !p.Known() {
		t.Fatalf("reader failed on a file this test just read: %s", p.Describe())
	}
	if int(p.Port) != want {
		t.Errorf("port = %d, want %d (the value in %s)", p.Port, want, path)
	}
	t.Logf("this host: boundary %d, so port 80 needs root: %v", p.Port, p.NeedsRoot(80))
}
