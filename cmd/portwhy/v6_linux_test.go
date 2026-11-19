//go:build linux

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sysctlDir lays out <dir>/net/ipv6/bindv6only, the path shape the reader
// expects, so a test can state the value the host has without changing the host.
func sysctlDir(t *testing.T, body string) string {
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

// v6WildcardPort opens a real [::] listener and returns its port. The row this
// creates in tcp6 is exactly the shape the question is about: a wildcard in
// another family, on the queried port.
func v6WildcardPort(t *testing.T, addr string) int {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen on %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().(*net.TCPAddr).Port
}

// The acceptance case for bindv6only=0: a real [::] listener, a real tcp6 row,
// and the tool says the IPv4 address is taken — with the measured value and the
// process that holds it.
func TestWhyDualStackWildcardHoldsIPv4(t *testing.T) {
	port := v6WildcardPort(t, "[::]:0")
	dir := sysctlDir(t, "0\n")

	code, out, errb := runCLI(t, "why", fmt.Sprintf("127.0.0.1:%d", port), "-sysctl", dir)
	if code != exitTaken {
		t.Fatalf("exit = %d, want %d (stderr: %s)\n%s", code, exitTaken, errb, out)
	}
	if !strings.Contains(out, "a listening socket holds it") {
		t.Errorf("missing listening verdict:\n%s", out)
	}
	if !strings.Contains(out, "= 0") {
		t.Errorf("output does not print the measured bindv6only value:\n%s", out)
	}
	if !strings.Contains(out, "does not hold this IPv4 address") &&
		!strings.Contains(out, "holds this IPv4 address too") {
		t.Errorf("output does not explain the wildcard:\n%s", out)
	}
	if want := fmt.Sprintf("pid %d", os.Getpid()); !strings.Contains(out, want) {
		t.Errorf("the process holding the wildcard is not named (%q):\n%s", want, out)
	}
}

// The other value: bindv6only=1 means the wildcard is IPv6 only, so the IPv4
// answer returns to free, and the measurement that produced it is printed.
func TestWhyIPv6OnlyWildcardLeavesIPv4Free(t *testing.T) {
	port := v6WildcardPort(t, "[::]:0")
	dir := sysctlDir(t, "1\n")

	code, out, errb := runCLI(t, "why", fmt.Sprintf("127.0.0.1:%d", port), "-sysctl", dir)
	if code != exitFree {
		t.Fatalf("exit = %d, want %d (stderr: %s)\n%s", code, exitFree, errb, out)
	}
	if !strings.Contains(out, "= 1") {
		t.Errorf("output does not print the measured bindv6only value:\n%s", out)
	}
	if !strings.Contains(out, "does not hold this IPv4 address") {
		t.Errorf("output does not say the wildcard is irrelevant:\n%s", out)
	}
	// Free still owes the one caveat no tunable can close.
	if !strings.Contains(out, "bound without listen") {
		t.Errorf("free answer lost the bind-without-listen caveat:\n%s", out)
	}
}

// A specific IPv6 address is a different address in every setting. This is the
// reverse assertion: [::1] must never make 127.0.0.1 look taken.
func TestWhySpecificIPv6ListenerLeavesIPv4Free(t *testing.T) {
	port := v6WildcardPort(t, "[::1]:0")
	dir := sysctlDir(t, "0\n")

	code, out, errb := runCLI(t, "why", fmt.Sprintf("127.0.0.1:%d", port), "-sysctl", dir)
	if code != exitFree {
		t.Fatalf("exit = %d, want %d (stderr: %s)\n%s", code, exitFree, errb, out)
	}
	if strings.Contains(out, "holds this IPv4 address too") {
		t.Errorf("invented a shadow from a specific address:\n%s", out)
	}
}

// With no measurement there is no answer: the wildcard might hold IPv4 and might
// not, and "might not" is not something a diagnostic tool may print as free.
func TestWhyUnreadableBindV6OnlyExitsUnknown(t *testing.T) {
	port := v6WildcardPort(t, "[::]:0")
	code, out, errb := runCLI(t, "why", fmt.Sprintf("127.0.0.1:%d", port), "-sysctl", t.TempDir())
	if code != exitUnknown {
		t.Fatalf("exit = %d, want %d (stderr: %s)\n%s", code, exitUnknown, errb, out)
	}
	if !strings.Contains(out, "cannot be determined") {
		t.Errorf("missing unknown verdict:\n%s", out)
	}
	if !strings.Contains(out, "bindv6only was not readable") {
		t.Errorf("output does not say which measurement was missing:\n%s", out)
	}
	if strings.Contains(out, "nothing in the kernel tables occupies it") {
		t.Errorf("an unreadable tunable produced a free answer:\n%s", out)
	}
}

// The JSON half of the same contract: a value that was not read must not appear
// as 0, because 0 is the answer "dual-stack".
func TestWhyJSONCarriesBindV6Only(t *testing.T) {
	port := v6WildcardPort(t, "[::]:0")

	t.Run("measured", func(t *testing.T) {
		dir := sysctlDir(t, "0\n")
		code, out, errb := runCLI(t, "why", fmt.Sprintf("127.0.0.1:%d", port), "-json", "-sysctl", dir)
		if code != exitTaken {
			t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitTaken, errb)
		}
		var rep struct {
			Kind     string `json:"kind"`
			Evidence struct {
				BindV6Only struct {
					Measured bool   `json:"measured"`
					Value    *int   `json:"value"`
					Raw      string `json:"raw"`
					Path     string `json:"path"`
					Error    string `json:"error"`
				} `json:"bindv6only"`
			} `json:"evidence"`
		}
		if err := json.Unmarshal([]byte(out), &rep); err != nil {
			t.Fatalf("not JSON: %v\n%s", err, out)
		}
		if rep.Kind != "listening" {
			t.Errorf("kind = %q, want listening", rep.Kind)
		}
		b := rep.Evidence.BindV6Only
		if !b.Measured || b.Value == nil || *b.Value != 0 {
			t.Errorf("bindv6only = %+v, want measured 0", b)
		}
		if !strings.HasPrefix(b.Path, dir) {
			t.Errorf("path = %q, want the file that was read (%s)", b.Path, dir)
		}
		if b.Error != "" {
			t.Errorf("error = %q on a successful read", b.Error)
		}
	})

	t.Run("unreadable", func(t *testing.T) {
		code, out, errb := runCLI(t, "why", fmt.Sprintf("127.0.0.1:%d", port), "-json", "-sysctl", t.TempDir())
		if code != exitUnknown {
			t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitUnknown, errb)
		}
		var rep struct {
			Evidence struct {
				BindV6Only map[string]any `json:"bindv6only"`
			} `json:"evidence"`
		}
		if err := json.Unmarshal([]byte(out), &rep); err != nil {
			t.Fatalf("not JSON: %v\n%s", err, out)
		}
		b := rep.Evidence.BindV6Only
		if b["measured"] != false {
			t.Errorf("measured = %v, want false", b["measured"])
		}
		if _, present := b["value"]; present {
			t.Errorf("a failed read still carried a value: %v", b["value"])
		}
		if s, _ := b["error"].(string); strings.TrimSpace(s) == "" {
			t.Error("no error recorded for the failed read")
		}
	})
}
