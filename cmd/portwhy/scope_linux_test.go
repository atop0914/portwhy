//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/atop0914/portwhy/internal/netns"
	"github.com/atop0914/portwhy/internal/verdict"
)

// scopeRoot lays out the two links the way procfs does, so a test can state
// which namespace the report is about without being in one.
func scopeRoot(t *testing.T, self, pidOne *string) string {
	t.Helper()
	dir := t.TempDir()
	for rel, target := range map[string]*string{"self/ns/net": self, "1/ns/net": pidOne} {
		if target == nil {
			continue
		}
		full := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.Symlink(*target, full); err != nil {
			t.Fatalf("symlink: %v", err)
		}
	}
	return dir
}

// boundaryDir lays out the capability tunable alone: an absent tunable is the
// shape in which the tool has to admit it did not measure anything.
func boundaryDir(t *testing.T, body *string) string {
	t.Helper()
	dir := t.TempDir()
	full := filepath.Join(dir, "net", "ipv4")
	if err := os.MkdirAll(full, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if body != nil {
		if err := os.WriteFile(filepath.Join(full, "ip_unprivileged_port_start"), []byte(*body), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	return dir
}

func pstr(s string) *string { return &s }

// The acceptance case for the namespace: the report names the namespace it read,
// and the line is the link the kernel printed — not a number assembled from the
// inode, which would hide any disagreement with `readlink`.
func TestWhyNamesTheNamespaceItRead(t *testing.T) {
	root := scopeRoot(t, pstr("net:[4026532488]"), pstr("net:[4026532488]"))
	sys := boundaryDir(t, pstr("0\n"))
	code, out, errb := runCLI(t, "why", "127.0.0.1:8080", "-tables", emptyTCPTables(t),
		"-sysctl", sys, "-proc", root)
	if code != exitFree {
		t.Fatalf("exit = %d, want %d (stderr: %s)\n%s", code, exitFree, errb, out)
	}
	for _, want := range []string{
		"scope: net:[4026532488]",
		"this process's network namespace",
		"the same one pid 1 runs in",
		"a holder in another one cannot be ruled out",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("scope output does not mention %q:\n%s", want, out)
		}
	}
}

// The reverse assertion on the whole day: a namespace that could not be read is
// reported as such, and no inode is invented for it.
func TestWhyUnreadableNamespaceInventsNothing(t *testing.T) {
	root := scopeRoot(t, nil, pstr("net:[4026532488]"))
	sys := boundaryDir(t, pstr("0\n"))
	code, out, errb := runCLI(t, "why", "127.0.0.1:8080", "-tables", emptyTCPTables(t),
		"-sysctl", sys, "-proc", root)
	if code != exitFree {
		t.Fatalf("exit = %d, want %d: the namespace is scope, not evidence about holders (stderr: %s)\n%s",
			code, exitFree, errb, out)
	}
	if !strings.Contains(out, "could not be read") {
		t.Errorf("an unread namespace is not disclosed:\n%s", out)
	}
	if strings.Contains(out, "net:[") {
		t.Errorf("an inode was printed for a namespace nobody read:\n%s", out)
	}
}

// The boundary is the machine's, not the tradition's: 1024 here because the
// fixture says 1024, and the sentence carries the number and the file.
func TestWhyPrivilegedPortUsesTheMeasuredBoundary(t *testing.T) {
	sys := boundaryDir(t, pstr("1024\n"))
	code, out, errb := runCLI(t, "why", "127.0.0.1:80", "-tables", emptyTCPTables(t),
		"-sysctl", sys, "-no-holders")
	if code != exitFree {
		t.Fatalf("exit = %d, want %d: needing root is not being taken (stderr: %s)\n%s",
			code, exitFree, errb, out)
	}
	for _, want := range []string{"needs a capability", "80 is below 1024", "ip_unprivileged_port_start"} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not mention %q:\n%s", want, out)
		}
	}
}

// The container case: boundary 0 means no port needs root, so port 80 is
// reported without any capability talk. Warning here would be wrong on every
// run in a default container.
func TestWhyZeroBoundarySaysNothingAboutCapabilities(t *testing.T) {
	sys := boundaryDir(t, pstr("0\n"))
	code, out, errb := runCLI(t, "why", "127.0.0.1:80", "-tables", emptyTCPTables(t),
		"-sysctl", sys, "-no-holders")
	if code != exitFree {
		t.Fatalf("exit = %d, want %d (stderr: %s)\n%s", code, exitFree, errb, out)
	}
	if strings.Contains(out, "needs a capability") || strings.Contains(out, "privileged") {
		t.Errorf("boundary 0 still produced a capability statement:\n%s", out)
	}
}

// A boundary nobody read is a limit, and no number appears in it: 1024 is what
// Linux usually has, which is exactly why it must not be printed here.
func TestWhyUnreadableBoundaryIsALimitWithoutADefault(t *testing.T) {
	sys := boundaryDir(t, nil)
	code, out, errb := runCLI(t, "why", "127.0.0.1:80", "-tables", emptyTCPTables(t),
		"-sysctl", sys, "-no-holders")
	if code != exitFree {
		t.Fatalf("exit = %d, want %d (stderr: %s)\n%s", code, exitFree, errb, out)
	}
	if !strings.Contains(out, "boundary could not be read") {
		t.Errorf("the missing boundary is not disclosed:\n%s", out)
	}
	if !strings.Contains(out, "limits") {
		t.Errorf("the hole is not listed under limits:\n%s", out)
	}
	if strings.Contains(out, "1024") {
		t.Errorf("output printed the traditional boundary for a host nobody read:\n%s", out)
	}
	if strings.Contains(out, "needs a capability") {
		t.Errorf("an unmeasured boundary produced a capability claim:\n%s", out)
	}
}

// The JSON contract for both new measurements: the namespace as read, the
// boundary with a measured switch that no zero value can fake.
func TestWhyJSONCarriesScopeEvidence(t *testing.T) {
	t.Run("measured", func(t *testing.T) {
		root := scopeRoot(t, pstr("net:[4026532488]"), pstr("net:[4026532223]"))
		sys := boundaryDir(t, pstr("1024\n"))
		code, out, errb := runCLI(t, "why", "127.0.0.1:80", "-json", "-tables", emptyTCPTables(t),
			"-sysctl", sys, "-proc", root)
		if code != exitFree {
			t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitFree, errb)
		}
		var rep struct {
			Evidence struct {
				NetNS struct {
					Inode        uint64 `json:"inode"`
					Self         string `json:"self"`
					PIDOne       string `json:"pid_one"`
					SameAsPIDOne *bool  `json:"same_as_pid_one"`
					Path         string `json:"path"`
				} `json:"netns"`
				Boundary struct {
					Measured bool   `json:"measured"`
					Present  bool   `json:"present"`
					Value    *int   `json:"value"`
					Path     string `json:"path"`
				} `json:"unprivileged_port_start"`
			} `json:"evidence"`
		}
		if err := json.Unmarshal([]byte(out), &rep); err != nil {
			t.Fatalf("not JSON: %v\n%s", err, out)
		}
		n := rep.Evidence.NetNS
		if n.Inode != 4026532488 || n.Self != "net:[4026532488]" || n.PIDOne != "net:[4026532223]" {
			t.Errorf("netns = %+v, want the links this fixture states", n)
		}
		if n.SameAsPIDOne == nil || *n.SameAsPIDOne {
			t.Errorf("same_as_pid_one = %v, want false for two different links", n.SameAsPIDOne)
		}
		if !strings.HasPrefix(n.Path, root) {
			t.Errorf("netns path = %q, want the link that was read", n.Path)
		}
		b := rep.Evidence.Boundary
		if !b.Measured || !b.Present || b.Value == nil || *b.Value != 1024 {
			t.Errorf("unprivileged_port_start = %+v, want measured 1024", b)
		}
	})

	t.Run("unreadable", func(t *testing.T) {
		root := scopeRoot(t, nil, nil)
		sys := boundaryDir(t, nil)
		code, out, errb := runCLI(t, "why", "127.0.0.1:80", "-json", "-tables", emptyTCPTables(t),
			"-sysctl", sys, "-proc", root)
		if code != exitFree {
			t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitFree, errb)
		}
		var rep struct {
			Evidence struct {
				NetNS struct {
					Inode        uint64 `json:"inode"`
					SameAsPIDOne *bool  `json:"same_as_pid_one"`
					Error        string `json:"error"`
				} `json:"netns"`
				Boundary map[string]any `json:"unprivileged_port_start"`
			} `json:"evidence"`
		}
		if err := json.Unmarshal([]byte(out), &rep); err != nil {
			t.Fatalf("not JSON: %v\n%s", err, out)
		}
		n := rep.Evidence.NetNS
		if n.Inode != 0 {
			t.Errorf("inode = %d, want 0 for a namespace nobody read", n.Inode)
		}
		if n.SameAsPIDOne != nil {
			t.Errorf("same_as_pid_one = %v, want null: nothing was compared", *n.SameAsPIDOne)
		}
		if strings.TrimSpace(n.Error) == "" {
			t.Error("no error recorded for the failed read")
		}
		b := rep.Evidence.Boundary
		if b["measured"] != false || b["present"] != false {
			t.Errorf("unprivileged_port_start = %v, want measured=false present=false", b)
		}
		if _, present := b["value"]; present {
			t.Error("a boundary nobody read still carried a value")
		}
	})
}

// The same table, the same measurements, twice: the report is diffable. A scope
// line that changed between runs would make every claim in it unfalsifiable.
func TestWhyScopeOutputIsReproducible(t *testing.T) {
	root := scopeRoot(t, pstr("net:[4026532488]"), pstr("net:[4026532488]"))
	sys := boundaryDir(t, pstr("1024\n"))
	first := ""
	for i := 0; i < 2; i++ {
		_, out, errb := runCLI(t, "why", "127.0.0.1:80", "-tables", emptyTCPTables(t),
			"-sysctl", sys, "-proc", root)
		if errb != "" {
			t.Fatalf("stderr: %s", errb)
		}
		if i == 0 {
			first = out
			continue
		}
		if out != first {
			t.Errorf("two runs differ:\n%s\n---\n%s", first, out)
		}
	}
}

// The limit that matters most is printed where a reader looks for it. The state
// is built here rather than produced by a walk, because a container running as
// root cannot make another process unreadable on demand — the real-machine run
// as uid 65534 did that, and this keeps the rendering side honest regardless.
func TestHolderLookupIncompleteIsPrintedUnderLimits(t *testing.T) {
	addr, err := parseTarget("127.0.0.1:8080")
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}
	var buf bytes.Buffer
	v := verdict.Verdict{
		Query: verdict.Query{Addr: addr},
		Kind:  verdict.KindFree,
		Reasons: []verdict.Reason{
			{Code: verdict.ReasonNoSockets},
			{Code: verdict.ReasonHolderLookupIncomplete, Detail: "3 of 15 process(es) could not be read"},
		},
		ProcsRead: 12, ProcsDenied: 3,
		NetNS: netns.Identity{Inode: 4026532488, Self: "net:[4026532488]", Same: netns.PIDOneSame},
	}
	if err := renderText(&buf, v); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	why, limits, found := strings.Cut(out, "\nlimits\n")
	if !found {
		t.Fatalf("no limits section:\n%s", out)
	}
	if strings.Contains(why, "never checked against all of them") {
		t.Errorf("the caveat was printed as a diagnosis:\n%s", why)
	}
	if !strings.Contains(limits, "never checked against all of them") {
		t.Errorf("limits does not state the incomplete walk:\n%s", limits)
	}
	if !strings.Contains(limits, "3 of 15") {
		t.Errorf("limits does not say how much is missing:\n%s", limits)
	}
}
