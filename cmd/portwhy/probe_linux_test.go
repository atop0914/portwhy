//go:build linux

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/atop0914/portwhy/internal/procnet"
)

// bindWithoutListen creates the socket no table can show: bound, never listened,
// held open until the test ends. It is the only shape of holder that makes a
// probe worth running.
func bindWithoutListen(t *testing.T) uint16 {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Close(fd) })
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	name, err := syscall.Getsockname(fd)
	if err != nil {
		t.Fatalf("getsockname: %v", err)
	}
	port := uint16(name.(*syscall.SockaddrInet4).Port)

	// Premise check: a second bind must fail, or the port is not held and the
	// test would pass while proving nothing.
	second, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	defer func() { _ = syscall.Close(second) }()
	if err := syscall.Bind(second, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}, Port: int(port)}); err == nil {
		t.Fatalf("a second bind on port %d succeeded; the port is not held", port)
	}
	return port
}

// freePort hands back a port the kernel just gave us and we released.
func freePort(t *testing.T) uint16 {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := uint16(l.Addr().(*net.TCPAddr).Port)
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return port
}

// The headline case: the tables say free, the kernel refuses the bind, and the
// answer has to stop being free. This is the gap the whole probe exists for.
func TestWhyProbeTurnsFreeIntoUnknownWhenTheBindIsRefused(t *testing.T) {
	port := bindWithoutListen(t)
	target := fmt.Sprintf("127.0.0.1:%d", port)

	// Baseline: without the probe the same port is "free" plus a caveat. If this
	// ever stops being true, the probe is proving something that changed
	// underneath it.
	code, out, errb := runCLI(t, "why", target, "-no-holders")
	if code != exitFree {
		t.Fatalf("baseline exit = %d, want %d (stderr: %s)\n%s", code, exitFree, errb, out)
	}

	code, out, errb = runCLI(t, "why", target, "-no-holders", "-probe")
	if code != exitUnknown {
		t.Fatalf("exit = %d, want %d (unknown): a refused bind must not leave free standing\n%s%s",
			code, exitUnknown, out, errb)
	}
	if first, _, _ := strings.Cut(out, "\n"); strings.Contains(first, "nothing in the kernel tables occupies it") {
		t.Errorf("the answer is still free:\n%s", out)
	}
	for _, want := range []string{"probe", "plain", "EADDRINUSE", "bound this port without listen()"} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not mention %q:\n%s", want, out)
		}
	}
	// The caveat has become the diagnosis: printing it as a blind spot as well
	// would read as a second, separate problem.
	if strings.Contains(out, "cannot rule that out") {
		t.Errorf("the report still lists the caveat as a limits line:\n%s", out)
	}
}

func TestWhyProbeOnAListenerReportsAddrInUse(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	target := ln.Addr().String()

	code, out, errb := runCLI(t, "why", target, "-no-holders", "-probe")
	if code != exitTaken {
		t.Fatalf("exit = %d, want %d (stderr: %s)\n%s", code, exitTaken, errb, out)
	}
	if !strings.Contains(out, "EADDRINUSE") {
		t.Errorf("probe section does not name the errno:\n%s", out)
	}
	if !strings.Contains(out, "a listening socket holds it") {
		t.Errorf("probe changed the verdict it should only corroborate:\n%s", out)
	}
	// Both attempts were made: the report says so per line, with a timestamp.
	if strings.Count(out, " at 2") < 2 {
		t.Errorf("each attempt must carry its own instant:\n%s", out)
	}
}

// The second headline case: TIME_WAIT is a reservation, not a process, and only
// the difference between the two attempts can say so.
func TestWhyProbeSplitsPlainFromReuseAddrOnTimeWait(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := uint16(l.Addr().(*net.TCPAddr).Port)
	target := fmt.Sprintf("127.0.0.1:%d", port)

	conn, err := net.Dial("tcp4", target)
	if err != nil {
		l.Close()
		t.Fatalf("dial: %v", err)
	}
	server, err := l.Accept()
	if err != nil {
		l.Close()
		conn.Close()
		t.Fatalf("accept: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	// The side bound to the port closes first: TIME_WAIT lives on the side that
	// initiated the close.
	if err := server.Close(); err != nil {
		t.Fatalf("close server side: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close client side: %v", err)
	}
	waitForRowState(t, port, procnet.StateTimeWait)

	code, out, errb := runCLI(t, "why", target, "-no-holders", "-probe")
	if code != exitTaken {
		t.Fatalf("exit = %d, want %d (stderr: %s)\n%s", code, exitTaken, errb, out)
	}
	if !strings.Contains(out, "only TIME_WAIT rows hold it") {
		t.Errorf("the probe changed a verdict it should only support:\n%s", out)
	}
	if !strings.Contains(out, "EADDRINUSE") {
		t.Errorf("plain attempt result missing:\n%s", out)
	}
	if !strings.Contains(out, "SO_REUSEADDR") {
		t.Errorf("the option attempt result missing:\n%s", out)
	}
	if !strings.Contains(out, "a closed connection, not to a running process") {
		t.Errorf("the report does not say what the reservation belongs to:\n%s", out)
	}
}

func TestWhyProbeOnAFreePortStaysFree(t *testing.T) {
	target := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	code, out, errb := runCLI(t, "why", target, "-no-holders", "-probe")
	if code != exitFree {
		t.Fatalf("exit = %d, want %d (stderr: %s)\n%s", code, exitFree, errb, out)
	}
	if !strings.Contains(out, "bind succeeded") {
		t.Errorf("probe section does not report the successful bind:\n%s", out)
	}
	// The blind spot was tested and did not materialise, so it must be gone.
	if strings.Contains(out, "cannot rule that out") {
		t.Errorf("the caveat survived the bind that disproved it:\n%s", out)
	}
}

func TestWhyProbeJSONCarriesAttemptsWithoutAPromise(t *testing.T) {
	port := bindWithoutListen(t)
	code, out, errb := runCLI(t, "why", fmt.Sprintf("127.0.0.1:%d", port), "-no-holders", "-probe", "-json")
	if code != exitUnknown {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitUnknown, errb)
	}

	var rep struct {
		Kind  string `json:"kind"`
		Probe *struct {
			Attempts []struct {
				Mode             string `json:"mode"`
				At               string `json:"at"`
				Outcome          string `json:"outcome"`
				Errno            string `json:"errno"`
				UsableAsEvidence bool   `json:"usable_as_evidence"`
			} `json:"attempts"`
			Note string `json:"note"`
		} `json:"probe"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	if rep.Probe == nil {
		t.Fatalf("no probe object in the report:\n%s", out)
	}
	if len(rep.Probe.Attempts) != 2 {
		t.Fatalf("attempts = %d, want 2", len(rep.Probe.Attempts))
	}
	for i, want := range []string{"plain", "reuseaddr"} {
		a := rep.Probe.Attempts[i]
		if a.Mode != want {
			t.Errorf("attempt %d mode = %q, want %q", i, a.Mode, want)
		}
		if !a.UsableAsEvidence {
			t.Errorf("attempt %d is not usable as evidence: %+v", i, a)
		}
		if _, err := time.Parse(time.RFC3339, a.At); err != nil {
			t.Errorf("attempt %d has no parseable instant: %q", i, a.At)
		}
	}
	if got := rep.Probe.Attempts[0].Outcome; got != "addr-in-use" {
		t.Errorf("plain outcome = %q, want addr-in-use", got)
	}
	if got := rep.Probe.Attempts[0].Errno; got != "EADDRINUSE" {
		t.Errorf("plain errno = %q, want EADDRINUSE", got)
	}
	if strings.TrimSpace(rep.Probe.Note) == "" {
		t.Error("probe carried no note about the instant it describes")
	}
	// A consumer looking for a promise must not find one.
	if strings.Contains(out, "guarantee") {
		t.Errorf("report offers a guarantee it cannot make:\n%s", out)
	}
}

// The absent flag must not be readable as "probed and found nothing".
func TestWhyWithoutProbeHasNoProbeObject(t *testing.T) {
	code, out, errb := runCLI(t, "why", fmt.Sprintf("127.0.0.1:%d", freePort(t)), "-no-holders", "-json")
	if code != exitFree {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitFree, errb)
	}
	if strings.Contains(out, `"probe"`) {
		t.Errorf("a report without -probe must not carry a probe object:\n%s", out)
	}
}

func TestWhyProbeRefusesUDP(t *testing.T) {
	code, _, errb := runCLI(t, "why", ":5353", "-proto", "udp", "-probe")
	if code != exitUsage {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitUsage, errb)
	}
	if !strings.Contains(errb, "udp") {
		t.Errorf("refusal does not say what is unsupported: %s", errb)
	}
}
