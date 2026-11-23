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

	"github.com/atop0914/portwhy/internal/verdict"
)

// A real listening socket file: bind() fails, the report names the process, and
// the answer is exit 1.
func TestUnixReportsRealListener(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer func() { _ = ln.Close() }()

	code, out, errb := runCLI(t, "unix", path)
	if code != exitTaken {
		t.Fatalf("exit = %d, want %d (stderr: %s)\n%s", code, exitTaken, errb, out)
	}
	if !strings.Contains(out, "a socket is bound to this name") {
		t.Errorf("answer does not say a socket holds the name:\n%s", out)
	}
	// The holder is this very process: the walk has to name it, or the tool has
	// told the user everything except the one thing they need.
	if !strings.Contains(out, fmt.Sprintf("pid %d", os.Getpid())) {
		t.Errorf("holder pid is not named:\n%s", out)
	}
	if !strings.Contains(out, "listening") {
		t.Errorf("a listening socket is not reported as listening:\n%s", out)
	}
}

// The failure no port has. The premise is checked first: after the listener is
// closed and the file left behind, a real bind() must fail with EADDRINUSE —
// otherwise the test would be asserting a story about nothing.
func TestUnixReportsStaleSocketFileAndUnlinkFreesIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	// Keep the file when the listener closes: this is what an unclean shutdown
	// leaves behind, and the case this command exists for.
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	if err := ln.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("premise: the socket file is gone (%v), so there is nothing stale to report", err)
	}

	second, err := net.Listen("unix", path)
	if err == nil {
		_ = second.Close()
		t.Fatal("premise failed: binding over the stale file succeeded")
	}
	if !strings.Contains(err.Error(), "address already in use") {
		t.Fatalf("premise failed: bind returned %v, want EADDRINUSE", err)
	}

	code, out, errb := runCLI(t, "unix", path)
	if code != exitTaken {
		t.Fatalf("exit = %d, want %d (stderr: %s)\n%s", code, exitTaken, errb, out)
	}
	if !strings.Contains(out, "the name is in the way, but no running socket holds it") {
		t.Errorf("answer does not say the holder is gone:\n%s", out)
	}
	if !strings.Contains(out, "until that file is removed") {
		t.Errorf("answer does not name the fix:\n%s", out)
	}
	// The answer must not send the reader looking for a process.
	if strings.Contains(out, "holders") {
		t.Errorf("a stale file is reported with a holder section:\n%s", out)
	}

	// And the fix works: removing the file makes the name free.
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}
	code, out, errb = runCLI(t, "unix", path)
	if code != exitFree {
		t.Fatalf("after unlink exit = %d, want %d (stderr: %s)\n%s", code, exitFree, errb, out)
	}
	if !strings.Contains(out, "nothing holds this name") {
		t.Errorf("free answer is wrong:\n%s", out)
	}
}

// A regular file in the way is a different sentence from a stale socket, because
// the user is looking at a different thing.
func TestUnixReportsNonSocketPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	code, out, errb := runCLI(t, "unix", path)
	if code != exitTaken {
		t.Fatalf("exit = %d, want %d (stderr: %s)\n%s", code, exitTaken, errb, out)
	}
	if !strings.Contains(out, "not a unix socket") {
		t.Errorf("answer does not name what is in the way:\n%s", out)
	}
	if !strings.Contains(out, "regular file") {
		t.Errorf("answer does not name the kind of entry:\n%s", out)
	}
}

// Abstract names: no file, so nothing is inspected, and the answer must not
// mention a path at all.
func TestUnixAbstractNameHasNoPath(t *testing.T) {
	name := fmt.Sprintf("@portwhy-cli-%d", os.Getpid())
	ln, err := net.Listen("unix", name)
	if err != nil {
		t.Fatalf("listen abstract: %v", err)
	}
	defer func() { _ = ln.Close() }()

	code, out, errb := runCLI(t, "unix", name)
	if code != exitTaken {
		t.Fatalf("exit = %d, want %d (stderr: %s)\n%s", code, exitTaken, errb, out)
	}
	if !strings.Contains(out, "abstract namespace") {
		t.Errorf("answer does not say the name is abstract:\n%s", out)
	}
	if strings.Contains(out, "\npath:") {
		t.Errorf("an abstract name reported a filesystem path:\n%s", out)
	}

	// The reverse: a different abstract name is free, and a filesystem path with
	// the same text is a different socket entirely.
	code, out, errb = runCLI(t, "unix", name+"-free")
	if code != exitFree {
		t.Fatalf("free abstract name exited %d (stderr: %s)\n%s", code, errb, out)
	}
}

// A missing table is a hole, not a free name: the CLI has to exit 3 with an
// unreadable-table reason rather than telling the user to go ahead.
func TestUnixMissingTableIsUnknownNotFree(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.sock")
	code, out, errb := runCLI(t, "unix", path, "-tables", t.TempDir())
	if code != exitUnknown {
		t.Fatalf("exit = %d, want %d (stderr: %s)\n%s", code, exitUnknown, errb, out)
	}
	if !strings.Contains(out, "unix socket table could not be read") {
		t.Errorf("answer does not say the table was unreadable:\n%s", out)
	}
}

// The JSON shape is a contract: a consumer needs the kind, whether the name is
// abstract, what the path measurement was, and who holds it.
func TestUnixJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer func() { _ = ln.Close() }()

	code, out, errb := runCLI(t, "unix", path, "-json", "-no-holders")
	if code != exitTaken {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitTaken, errb)
	}
	var rep struct {
		Target   string `json:"target"`
		Abstract bool   `json:"abstract"`
		Kind     string `json:"kind"`
		Holders  []struct {
			Inode     uint64 `json:"inode"`
			Type      string `json:"type"`
			Listening bool   `json:"listening"`
		} `json:"holders"`
		Path *struct {
			Measured bool   `json:"measured"`
			Exists   bool   `json:"exists"`
			Kind     string `json:"kind"`
		} `json:"path"`
		Evidence struct {
			Table struct {
				Read    bool `json:"read"`
				Present bool `json:"present"`
			} `json:"table"`
		} `json:"evidence"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("bad JSON: %v\n%s", err, out)
	}
	if rep.Target != path || rep.Abstract || rep.Kind != "bound" {
		t.Errorf("target/abstract/kind = %q/%v/%q", rep.Target, rep.Abstract, rep.Kind)
	}
	if rep.Path == nil || !rep.Path.Measured || !rep.Path.Exists || rep.Path.Kind != "socket" {
		t.Errorf("path = %+v, want measured socket", rep.Path)
	}
	if !rep.Evidence.Table.Read || !rep.Evidence.Table.Present {
		t.Errorf("evidence.table = %+v, want read and present", rep.Evidence.Table)
	}
	if len(rep.Holders) != 1 || !rep.Holders[0].Listening || rep.Holders[0].Inode == 0 {
		t.Errorf("holders = %+v", rep.Holders)
	}

	// An abstract name carries no path object at all: absence of the field is the
	// honest form of "nothing was measured there".
	name := fmt.Sprintf("@portwhy-json-%d", os.Getpid())
	al, err := net.Listen("unix", name)
	if err != nil {
		t.Fatalf("listen abstract: %v", err)
	}
	defer func() { _ = al.Close() }()
	_, aout, _ := runCLI(t, "unix", name, "-json", "-no-holders")
	if strings.Contains(aout, `"path"`) {
		t.Errorf("abstract JSON carries a path object:\n%s", aout)
	}
}

// Every code the unix judgement can emit has a sentence here. Without this a new
// code prints as a bare identifier and the report reads like a stack trace.
func TestEveryUnixReasonCodeHasASentence(t *testing.T) {
	for _, code := range verdict.AllUnixReasonCodes() {
		if _, ok := reasonSentence[code]; !ok {
			t.Errorf("reason %q has no sentence in reasonSentence", code)
		}
	}
	// And the direction that catches a typo: a sentence registered under a code
	// the judgement never emits is dead wording, and the real code would then
	// print as a bare identifier.
	known := make(map[string]bool, len(verdict.AllUnixReasonCodes()))
	for _, c := range verdict.AllUnixReasonCodes() {
		known[c] = true
	}
	for code := range reasonSentence {
		if !strings.HasPrefix(code, "unix-") {
			continue
		}
		if !known[code] {
			t.Errorf("reasonSentence has an entry for %q, which no unix code produces", code)
		}
	}
}

// The command takes exactly one name, and says so instead of guessing.
func TestUnixUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{"unix"},
		{"unix", "a", "b"},
	} {
		code, _, errb := runCLI(t, args...)
		if code != exitUsage {
			t.Errorf("%v exited %d, want %d", args, code, exitUsage)
		}
		if !strings.Contains(errb, "exactly one name") {
			t.Errorf("%v stderr does not explain: %s", args, errb)
		}
	}
}

// "unix:/path" is accepted because it is the spelling people reach for when a
// command has more than one kind of target; the prefix is not part of the name.
func TestUnixPrefixIsStripped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer func() { _ = ln.Close() }()

	code, out, errb := runCLI(t, "unix", "unix:"+path, "-no-holders")
	if code != exitTaken {
		t.Fatalf("exit = %d, want %d (stderr: %s)\n%s", code, exitTaken, errb, out)
	}
	if !strings.Contains(out, path+" — ") {
		t.Errorf("the report does not name the bare path:\n%s", out)
	}
}
