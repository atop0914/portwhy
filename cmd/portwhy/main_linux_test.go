//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const headerTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode`

// tablesDir writes the given table files into a temp dir and returns it. Files
// that are not written simply do not exist, which is how a kernel without IPv6
// looks from the caller's side.
func tablesDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

func runCLI(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	return runCLIStdin(t, "", args...)
}

// runCLIStdin is runCLI with something on standard input, which is what -batch
// reads. The empty reader is not a nil: a command that reads stdin must get the
// same "nothing was there" answer a terminal would give it.
func runCLIStdin(t *testing.T, stdin string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = run(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

func TestWhyFreeExitsZero(t *testing.T) {
	dir := tablesDir(t, map[string]string{"tcp": headerTCP + "\n"})
	code, out, errb := runCLI(t, "why", "127.0.0.1:8080", "-tables", dir, "-no-holders")
	if code != exitFree {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitFree, errb)
	}
	if !strings.Contains(out, "nothing in the kernel tables occupies it") {
		t.Errorf("output does not state the free verdict:\n%s", out)
	}
	// The disclosure that nothing was probed must survive into the output.
	if !strings.Contains(out, "no bind was attempted") {
		t.Errorf("output hides that no bind was attempted:\n%s", out)
	}
}

func TestWhyListenerNamesTheHolder(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	target := ln.Addr().String()

	code, out, errb := runCLI(t, "why", target)
	if code != exitTaken {
		t.Fatalf("exit = %d, want %d (stderr: %s, stdout: %s)", code, exitTaken, errb, out)
	}
	if !strings.Contains(out, "a listening socket holds it") {
		t.Errorf("missing listening verdict:\n%s", out)
	}
	if !strings.Contains(out, "LISTEN") {
		t.Errorf("missing LISTEN row:\n%s", out)
	}
	wantPID := fmt.Sprintf("pid %d", os.Getpid())
	if !strings.Contains(out, wantPID) {
		t.Errorf("holder %q missing from report:\n%s", wantPID, out)
	}
}

// The central promise, as a test: an unreadable table must not become "free".
func TestWhyUnreadableTableExitsUnknown(t *testing.T) {
	dir := tablesDir(t, map[string]string{"tcp": "this is not a socket table\n"})
	code, out, errb := runCLI(t, "why", "127.0.0.1:8080", "-tables", dir, "-no-holders")
	if code != exitUnknown {
		t.Fatalf("exit = %d, want %d (unknown must not be free)\nstdout: %s\nstderr: %s", code, exitUnknown, out, errb)
	}
	if !strings.Contains(out, "cannot be determined") {
		t.Errorf("missing unknown verdict:\n%s", out)
	}
	if !strings.Contains(out, "unreadable tables") {
		t.Errorf("output does not name the unreadable table:\n%s", out)
	}
}

func TestWhyJSONIsAStableContract(t *testing.T) {
	dir := tablesDir(t, map[string]string{"tcp": headerTCP + "\n"})
	code, out, errb := runCLI(t, "why", ":9000", "-json", "-tables", dir, "-no-holders")
	if code != exitFree {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitFree, errb)
	}
	var rep struct {
		Target   string `json:"target"`
		Proto    string `json:"proto"`
		Kind     string `json:"kind"`
		Findings []any  `json:"findings"`
		Evidence struct {
			TablesRead       int `json:"tables_read"`
			TablesUnreadable []struct {
				Name    string `json:"name"`
				Present bool   `json:"present"`
				Error   string `json:"error"`
			} `json:"tables_unreadable"`
			Holders struct {
				Attempted bool `json:"attempted"`
				ProcsRead *int `json:"procs_read"`
				Denied    *int `json:"procs_denied"`
			} `json:"holder_lookup"`
		} `json:"evidence"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	if rep.Kind != "free" {
		t.Errorf("kind = %q, want free", rep.Kind)
	}
	if rep.Proto != "tcp" {
		t.Errorf("proto = %q, want tcp", rep.Proto)
	}
	if rep.Target != "0.0.0.0:9000" {
		t.Errorf("target = %q, want 0.0.0.0:9000 (the bare :port form means every interface)", rep.Target)
	}
	if rep.Findings == nil {
		t.Error("findings is null; an empty list is the contract")
	}
	if rep.Evidence.TablesUnreadable == nil {
		t.Error("tables_unreadable is null; an empty list is the contract")
	}
	// This run used -no-holders, so the walk did not happen. A report that said
	// procs_read: 0 would be claiming to have walked and found nothing.
	if rep.Evidence.Holders.Attempted {
		t.Error("holder_lookup.attempted is true with -no-holders")
	}
	if rep.Evidence.Holders.ProcsRead != nil || rep.Evidence.Holders.Denied != nil {
		t.Error("holder_lookup carries counts for a walk that never ran")
	}
}

// The other half of the same rule: when the walk does run, the counts are there.
// Without this, a report could satisfy the test above by never reporting counts.
func TestWhyJSONHolderLookupCarriesCountsWhenWalked(t *testing.T) {
	dir := tablesDir(t, map[string]string{"tcp": headerTCP + "\n"})
	code, out, errb := runCLI(t, "why", ":9000", "-json", "-tables", dir)
	if code != exitFree {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitFree, errb)
	}
	var rep struct {
		Evidence struct {
			Holders struct {
				Attempted bool `json:"attempted"`
				ProcsRead *int `json:"procs_read"`
				Denied    *int `json:"procs_denied"`
			} `json:"holder_lookup"`
		} `json:"evidence"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	if !rep.Evidence.Holders.Attempted {
		t.Fatal("holder_lookup.attempted is false without -no-holders")
	}
	if rep.Evidence.Holders.ProcsRead == nil || rep.Evidence.Holders.Denied == nil {
		t.Fatal("holder_lookup is missing its counts for a walk that ran")
	}
	if *rep.Evidence.Holders.ProcsRead < 1 {
		t.Errorf("procs_read = %d, want at least this process", *rep.Evidence.Holders.ProcsRead)
	}
}

// A required field is not optional: dropping procs_read must be visible, which
// is what makes the null above meaningful rather than merely absent.
func TestWhyJSONSkippedWalkHasNullCountsNotZero(t *testing.T) {
	dir := tablesDir(t, map[string]string{"tcp": headerTCP + "\n"})
	_, out, _ := runCLI(t, "why", ":9000", "-json", "-tables", dir, "-no-holders")
	if strings.Contains(out, `"procs_read": 0`) {
		t.Errorf("skipped walk reported procs_read: 0 instead of null:\n%s", out)
	}
}

func TestUsageErrors(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"no args", nil},
		{"unknown command", []string{"explain"}},
		{"no target", []string{"why"}},
		{"bad target", []string{"why", "8080"}},
		{"bad port", []string{"why", "127.0.0.1:99999"}},
		{"bad proto", []string{"why", "127.0.0.1:80", "-proto", "sctp"}},
		{"too many targets", []string{"why", "127.0.0.1:80", "127.0.0.1:81"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, _, errb := runCLI(t, c.args...)
			if code != exitUsage {
				t.Fatalf("exit = %d, want %d", code, exitUsage)
			}
			if strings.TrimSpace(errb) == "" {
				t.Error("no error message on stderr")
			}
		})
	}
}

func TestVersionPrintsSomethingIdentifying(t *testing.T) {
	code, out, errb := runCLI(t, "version")
	if code != exitFree {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitFree, errb)
	}
	if !strings.HasPrefix(out, "portwhy ") {
		t.Errorf("output = %q, want it to start with the program name", out)
	}
}

func TestParseTarget(t *testing.T) {
	cases := []struct {
		in       string
		wantAddr string
		wantErr  bool
	}{
		{"127.0.0.1:8080", "127.0.0.1:8080", false},
		{":8080", "0.0.0.0:8080", false},
		{"[::1]:8080", "[::1]:8080", false},
		// 4-in-6 must collapse to the v4 form the tables use, or the answer
		// would be "free" for a port that is plainly taken.
		{"[::ffff:127.0.0.1]:8080", "127.0.0.1:8080", false},
		{"", "", true},
		{"localhost:8080", "", true},
		{":", "", true},
	}
	for _, c := range cases {
		got, err := parseTarget(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseTarget(%q) = %v, want an error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseTarget(%q): %v", c.in, err)
			continue
		}
		if got.String() != c.wantAddr {
			t.Errorf("parseTarget(%q) = %q, want %q", c.in, got.String(), c.wantAddr)
		}
	}
}
