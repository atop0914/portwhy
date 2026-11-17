//go:build linux

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// row renders one /proc/net/tcp line with no peer. Addresses are the kernel's
// little-endian hex, so 127.0.0.1 is 0100007F and 10.1.2.3 is 0302010A.
func row(localHex string, port uint16, state string, inode int) string {
	return rowPeer(localHex, port, "00000000", 0, state, inode)
}

// rowPeer renders a row with a peer, which is how a connection is spelled. Used
// for the "--all includes the far end of a connection" case.
func rowPeer(localHex string, localPort uint16, remoteHex string, remotePort uint16, state string, inode int) string {
	return fmt.Sprintf(
		"   0: %s:%04X %s:%04X %s 00000000:00000000 00:00000000 00000000     0        0 %d 1 0000000000000000 100 0 0 10 0",
		localHex, localPort, remoteHex, remotePort, state, inode)
}

// rawKindLine returns the JSON line carrying "kind", so two runs can be compared
// on the bytes rather than on a decoded value that would hide formatting drift.
func rawKindLine(t *testing.T, out string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, `"kind"`) {
			return line
		}
	}
	t.Fatalf("no kind field in output:\n%s", out)
	return ""
}

type allReport struct {
	Kind string `json:"kind"`
	Rows *[]struct {
		Match  string `json:"match"`
		State  string `json:"state"`
		Effect string `json:"effect"`
	} `json:"rows"`
}

// The flag is a viewer, not a switch. Whatever the neighbours are — another port,
// another protocol, another family, a wildcard shadow — the kind and the exit code
// must be byte-identical to the run without the flag.
func TestAllFlagNeverChangesTheAnswer(t *testing.T) {
	cases := map[string]map[string]string{
		"listener on the address": {
			"tcp": headerTCP + "\n" + row("0100007F", 8080, "0A", 101),
		},
		"only a neighbour port": {
			"tcp": headerTCP + "\n" + row("0100007F", 8081, "0A", 102),
		},
		"only a neighbour address": {
			"tcp": headerTCP + "\n" + row("0302010A", 8080, "0A", 103),
		},
		"neighbour protocol only": {
			"tcp": headerTCP + "\n",
			"udp": headerTCP + "\n" + row("0100007F", 8080, "07", 104),
		},
		"ipv6 wildcard shadow": {
			"tcp":  headerTCP + "\n",
			"tcp6": headerTCP + "\n" + row("00000000000000000000000000000000", 8080, "0A", 105),
		},
		"time-wait only": {
			"tcp": headerTCP + "\n" + row("0100007F", 8080, "06", 0),
		},
		"listener plus noise": {
			"tcp": headerTCP + "\n" +
				row("0100007F", 8080, "0A", 106) +
				"\n" + row("0302010A", 8080, "01", 107) +
				"\n" + row("0100007F", 8081, "0A", 108),
		},
	}
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			dir := tablesDir(t, files)
			base := []string{"why", "127.0.0.1:8080", "-json", "-tables", dir, "-no-holders"}

			plainCode, plainOut, plainErr := runCLI(t, base...)
			allCode, allOut, allErr := runCLI(t, append(append([]string{}, base...), "-all")...)

			if plainCode != allCode {
				t.Fatalf("exit %d without --all, %d with (stderr: %s / %s)", plainCode, allCode, plainErr, allErr)
			}
			if got, want := rawKindLine(t, allOut), rawKindLine(t, plainOut); got != want {
				t.Errorf("kind changed with --all:\n with: %s\nwithout: %s", got, want)
			}
			if strings.Contains(plainOut, `"rows"`) {
				t.Error("rows emitted without --all")
			}
			var rep allReport
			if err := json.Unmarshal([]byte(allOut), &rep); err != nil {
				t.Fatalf("output with --all is not JSON: %v\n%s", err, allOut)
			}
			if rep.Rows == nil {
				t.Error("no rows field with --all: an empty list and a missing flag must stay distinguishable")
			}
		})
	}
}

// Every row on the port gets a machine-readable reason. A user greps these; prose
// in that column would be unusable in a script.
func TestAllRowsCarryTheirMatchCode(t *testing.T) {
	dir := tablesDir(t, map[string]string{
		"tcp": headerTCP + "\n" +
			row("0100007F", 8080, "0A", 201) + // matched
			"\n" + row("0302010A", 8080, "0A", 202) + // other-address
			"\n" + rowPeer("0100007F", 45678, "0100007F", 8080, "01", 203), // other-port: a connection to it
		"udp": headerTCP + "\n" + row("0100007F", 8080, "07", 204), // other-proto
	})
	code, out, errb := runCLI(t, "why", "127.0.0.1:8080", "-json", "-all", "-tables", dir, "-no-holders")
	if code != exitTaken {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitTaken, errb)
	}

	var rep allReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("bad JSON: %v\n%s", err, out)
	}
	if rep.Rows == nil {
		t.Fatal("no rows field")
	}
	got := make(map[string]bool, len(*rep.Rows))
	for _, r := range *rep.Rows {
		got[r.Match] = true
		if r.Effect == "" {
			t.Errorf("row %q has no bind effect", r.State)
		}
	}
	for _, want := range []string{"matched", "other-address", "other-port", "other-proto"} {
		if !got[want] {
			t.Errorf("no row labelled %q (got %v)", want, got)
		}
	}
	// Matched rows come first: the answer before the surroundings.
	if (*rep.Rows)[0].Match != "matched" {
		t.Errorf("first row = %q, want matched", (*rep.Rows)[0].Match)
	}
}

// The state table has to be inspectable without reading the source, or "it says
// CLOSE_WAIT depends on options" is folklore the user has to take on trust.
func TestStatesListsEveryStateWithItsEffect(t *testing.T) {
	code, out, errb := runCLI(t, "states")
	if code != exitFree {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitFree, errb)
	}
	for s := 1; s <= 12; s++ {
		if !strings.Contains(out, fmt.Sprintf("0x%02x", s)) {
			t.Errorf("state 0x%02x missing from output:\n%s", s, out)
		}
	}
	if !strings.Contains(out, "LISTEN") || !strings.Contains(out, "blocks") {
		t.Errorf("LISTEN is not shown as blocking:\n%s", out)
	}
	if !strings.Contains(out, "TIME_WAIT") || !strings.Contains(out, "options-decide") {
		t.Errorf("TIME_WAIT is not shown as options-decide:\n%s", out)
	}
	if !strings.Contains(out, "UNKNOWN(0x") {
		t.Errorf("output does not say what happens to unknown codes:\n%s", out)
	}
	if code, _, _ := runCLI(t, "states", "extra"); code != exitUsage {
		t.Errorf("states with an argument exited %d, want %d", code, exitUsage)
	}
}

// One listener, two processes: the report has to name both and say which one the
// other inherited from. Killing the inherited one leaves the port taken, so this
// distinction is the difference between a fix and a second attempt.
func TestWhyNamesTheCreatorAndTheInheritedHolder(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	f, err := ln.(*net.TCPListener).File()
	if err != nil {
		t.Fatalf("file: %v", err)
	}
	defer f.Close()
	target := ln.Addr().String()

	cmd := exec.Command("sleep", "30")
	cmd.ExtraFiles = []*os.File{f}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	// The child needs a moment to reach exec() with the descriptor in place.
	deadline := time.Now().Add(3 * time.Second)
	for {
		code, out, errb := runCLI(t, "why", target)
		if code != exitTaken {
			t.Fatalf("exit = %d, want %d (stderr: %s, stdout: %s)", code, exitTaken, errb, out)
		}
		if strings.Contains(out, fmt.Sprintf("pid %d", cmd.Process.Pid)) {
			if !strings.Contains(out, "[inherited]") {
				t.Errorf("the forked child is not marked inherited:\n%s", out)
			}
			if !strings.Contains(out, "[creator]") {
				t.Errorf("the process that opened the listener is not marked creator:\n%s", out)
			}
			return
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("child pid %d never appeared in the report:\n%s", cmd.Process.Pid, out)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The caveat belongs on the answer it can invalidate. A "free" answer that omitted
// it would be claiming more than /proc/net/tcp can support, because a socket bound
// without listen() holds the port and has no row anywhere.
func TestFreeDisclosesTheUnlistedBindingCaveat(t *testing.T) {
	dir := tablesDir(t, map[string]string{"tcp": headerTCP + "\n"})
	code, out, errb := runCLI(t, "why", "127.0.0.1:8080", "-tables", dir, "-no-holders")
	if code != exitFree {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitFree, errb)
	}
	if !strings.Contains(out, "bound without listen()") {
		t.Errorf("free answer hides the bind-without-listen blind spot:\n%s", out)
	}

	taken := tablesDir(t, map[string]string{"tcp": headerTCP + "\n" + row("0100007F", 8080, "0A", 301)})
	if _, out, _ := runCLI(t, "why", "127.0.0.1:8080", "-tables", taken, "-no-holders"); strings.Contains(out, "bound without listen()") {
		t.Errorf("listening answer carries the free-answer caveat:\n%s", out)
	}
}
