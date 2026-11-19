//go:build linux

package sysctl

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// writeV6Only lays out <dir>/net/ipv6/bindv6only so ReadBindV6Only sees the
// same path shape as procfs.
func writeV6Only(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	full := filepath.Join(dir, "net", "ipv6")
	if err := os.MkdirAll(full, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(full, "bindv6only"), []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return dir
}

func TestReadBindV6OnlyReadsBothValues(t *testing.T) {
	cases := []struct {
		body      string
		want      BindV6OnlyState
		dualStack bool
	}{
		{"0\n", BindV6OnlyDualStack, true},
		{"1\n", BindV6OnlyIPv6Only, false},
		{"1", BindV6OnlyIPv6Only, false},
	}
	for _, c := range cases {
		t.Run(c.body, func(t *testing.T) {
			b := ReadBindV6Only(writeV6Only(t, c.body))
			if !b.Known() {
				t.Fatalf("not known: %s", b.Describe())
			}
			if b.State != c.want {
				t.Errorf("state = %v, want %v", b.State, c.want)
			}
			if b.DualStack() != c.dualStack {
				t.Errorf("DualStack() = %v, want %v", b.DualStack(), c.dualStack)
			}
			if !strings.HasSuffix(b.Path, filepath.Join("net", "ipv6", "bindv6only")) {
				t.Errorf("path = %q, want it to name the tunable", b.Path)
			}
			if !strings.Contains(b.Describe(), b.Path) {
				t.Errorf("Describe() = %q, want it to cite the path", b.Describe())
			}
		})
	}
}

// Every way of not getting a value has to end in "unknown", never in 0. The
// three below are the ones that happen: the tunable is absent (a kernel without
// IPv6, or a mount we cannot see), unreadable as a file, and holding something
// that is not a number.
func TestReadBindV6OnlyFailureIsNeverDualStack(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		b := ReadBindV6Only(t.TempDir())
		if b.Known() || b.DualStack() {
			t.Fatalf("missing file reported as %v", b)
		}
		if b.Err == "" {
			t.Error("no reason recorded for the missing value")
		}
	})

	t.Run("not a regular file", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "net", "ipv6", "bindv6only"), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		b := ReadBindV6Only(dir)
		if b.Known() {
			t.Fatalf("a directory was read as a value: %s", b.Describe())
		}
		if b.Err == "" {
			t.Error("no reason recorded")
		}
	})

	t.Run("not a number", func(t *testing.T) {
		b := ReadBindV6Only(writeV6Only(t, "2\n"))
		if b.Known() {
			t.Fatalf("out-of-range value was accepted: %s", b.Describe())
		}
		if !strings.Contains(b.Err, "not 0 or 1") {
			t.Errorf("err = %q, want it to say the value is not 0 or 1", b.Err)
		}
	})

	t.Run("empty", func(t *testing.T) {
		b := ReadBindV6Only(writeV6Only(t, ""))
		if b.Known() {
			t.Fatalf("empty file was accepted: %s", b.Describe())
		}
	})
}

// The live reading, against the kernel this test runs on: the value has to
// match the file byte for byte, and it has to be one of the two states. A tool
// that reports a tunable it did not read would pass every fixture test above.
func TestReadBindV6OnlyLive(t *testing.T) {
	b := ReadBindV6Only(DefaultDir)
	if !b.Known() {
		t.Fatalf("cannot read %s: %s", b.Path, b.Describe())
	}
	raw, err := os.ReadFile(b.Path)
	if err != nil {
		t.Fatalf("read %s: %v", b.Path, err)
	}
	want, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatalf("kernel printed %q: %v", raw, err)
	}
	got, ok := b.Value()
	if !ok {
		t.Fatalf("no value although Known() is true: %s", b.Describe())
	}
	if got != want {
		t.Errorf("value = %d, file says %d", got, want)
	}
	t.Logf("this host: %s", b.Describe())
}
