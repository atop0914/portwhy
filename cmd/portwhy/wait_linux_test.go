//go:build linux

package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// listenOn starts a real listener and returns its address and a function that
// releases it. Everything below drives the command against real sockets: a wait
// that only ever saw a fake clock would prove nothing about the product.
func listenOn(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return ln.Addr().String(), func() {
		if err := ln.Close(); err != nil {
			t.Errorf("close listener: %v", err)
		}
	}
}

// TestWaitSucceedsWhenTheHolderExits is the headline case: something holds the
// port, it lets go, and the command must notice and say so.
func TestWaitSucceedsWhenTheHolderExits(t *testing.T) {
	addr, release := listenOn(t)

	// The holder exits on its own, the way a restarting container does. The
	// release is a real socket being closed, not a scripted clock: the command
	// has to see the kernel change, not a fake.
	go func() {
		time.Sleep(200 * time.Millisecond)
		release()
	}()

	start := time.Now()
	code, out, errb := runCLI(t, "wait", addr, "-timeout", "10s", "-interval", "50ms")
	elapsed := time.Since(start)

	if code != exitFree {
		t.Fatalf("exit = %d, want %d (free):\n%s%s", code, exitFree, out, errb)
	}
	for _, want := range []string{
		"bindable: a plain bind() was accepted",
		"changed from listening",
		"timeline",
		"note",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not mention %q:\n%s", want, out)
		}
	}
	if elapsed < 200*time.Millisecond {
		t.Errorf("returned after %s, before the holder let go at 200ms", elapsed)
	}
	// The wait must not claim to have held the port: the note says it closes what
	// it binds, and the exit that follows must find the port free.
	if code, again, _ := runCLI(t, "why", addr, "-no-holders"); code != exitFree {
		t.Errorf("the port is not free after wait returned (%d):\n%s", code, again)
	}
}

// The failure this command exists to avoid: a deadline is not a port. Asserted on
// the exit code, on the absence of a success sentence, and on the presence of the
// last round's answer.
func TestWaitTimeoutIsNotSuccess(t *testing.T) {
	addr, release := listenOn(t)
	defer release()

	code, out, errb := runCLI(t, "wait", addr, "-timeout", "200ms", "-interval", "50ms")
	if code != exitTaken {
		t.Fatalf("exit = %d, want %d (taken) (stderr: %s)\n%s", code, exitTaken, errb, out)
	}
	if strings.Contains(out, "was accepted") {
		t.Errorf("a timeout claims an accepted bind:\n%s", out)
	}
	for _, want := range []string{
		`not bindable at the deadline`,
		`"listening"`,
		"none accepted",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not mention %q:\n%s", want, out)
		}
	}
}

// EADDRNOTAVAIL is an answer, not a delay. The command must stop in well under
// the deadline it was given, and must not call the port free or taken.
func TestWaitStopsWhenTheAddressIsNotOnThisHost(t *testing.T) {
	start := time.Now()
	code, out, errb := runCLI(t, "wait", "192.0.2.1:8080", "-timeout", "30s", "-interval", "50ms")
	elapsed := time.Since(start)

	if code != exitUnknown {
		t.Fatalf("exit = %d, want %d (unknown) (stderr: %s)\n%s", code, exitUnknown, errb, out)
	}
	if elapsed > 5*time.Second {
		t.Errorf("waited %s: an address that is not here will never appear, so the deadline is not the reason to stop", elapsed)
	}
	for _, want := range []string{"EADDRNOTAVAIL", "not on this host", "waiting"} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not mention %q:\n%s", want, out)
		}
	}
}

// The bind-without-listen hole, driven through wait: the tables show nothing, the
// bind is refused anyway, and the honest answer is unknown — not free (the bind
// proved otherwise) and not taken (no row names a holder).
func TestWaitTreatsABindWithoutListenAsUnknown(t *testing.T) {
	port := bindWithoutListen(t)
	target := fmt.Sprintf("127.0.0.1:%d", port)

	code, out, errb := runCLI(t, "wait", target, "-timeout", "200ms", "-interval", "50ms")
	if code != exitUnknown {
		t.Fatalf("exit = %d, want %d (unknown): a refused bind with no row is not taken either (stderr: %s)\n%s",
			code, exitUnknown, errb, out)
	}
	if !strings.Contains(out, "the tables had no row for it and the bind was refused anyway") {
		t.Errorf("output does not explain the disagreement it acted on:\n%s", out)
	}
}

// UDP is a separate namespace with its own answer shape, and the probe that
// serves it is a datagram socket: a tcp-only implementation would report the
// port free while a DNS server holds it.
func TestWaitSpeaksUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen packet: %v", err)
	}
	addr := pc.LocalAddr().String()

	code, out, errb := runCLI(t, "wait", addr, "-proto", "udp", "-timeout", "200ms", "-interval", "50ms")
	if code != exitTaken {
		t.Fatalf("exit = %d, want %d (taken) (stderr: %s)\n%s", code, exitTaken, errb, out)
	}
	if !strings.Contains(out, "udp") || !strings.Contains(out, "a bound socket holds it") {
		t.Errorf("the udp answer is not spelled as a bound socket:\n%s", out)
	}

	if err := pc.Close(); err != nil {
		t.Fatalf("close packet conn: %v", err)
	}
	if code, out, errb := runCLI(t, "wait", addr, "-proto", "udp", "-timeout", "5s", "-interval", "50ms"); code != exitFree {
		t.Fatalf("after the holder closed, exit = %d, want %d (stderr: %s)\n%s", code, exitFree, errb, out)
	}
}

// A table that cannot be read must not become a free answer, and the blind rounds
// must be counted in the conclusion.
func TestWaitDoesNotTurnABlindRoundIntoFree(t *testing.T) {
	addr, release := listenOn(t)
	defer release()

	dir := t.TempDir()
	// A directory named tcp: present, and unreadable as a table. This is the
	// shape of a permissions problem or a truncated read, not of a kernel without
	// IPv4.
	if err := os.Mkdir(filepath.Join(dir, "tcp"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	code, out, errb := runCLI(t, "wait", addr, "-tables", dir, "-timeout", "200ms", "-interval", "50ms")
	if code != exitUnknown {
		t.Fatalf("exit = %d, want %d (unknown): no round could read the table (stderr: %s)\n%s",
			code, exitUnknown, errb, out)
	}
	if !strings.Contains(out, `"unknown"`) {
		t.Errorf("the last round is not reported as unknown:\n%s", out)
	}
	if !strings.Contains(out, "could not read the socket table") {
		t.Errorf("the blind rounds are missing from the conclusion:\n%s", out)
	}
}

// The other half of the same rule, and the decision it forces: a bind that really
// succeeded is evidence no table can overrule, so the wait says bindable — while
// still disclosing that every round was blind. Exit 0 with a stated blind spot is
// honest; exit 3 here would deny a measurement that happened.
func TestWaitReportsSuccessButDisclosesBlindRounds(t *testing.T) {
	port := freePort(t)
	target := fmt.Sprintf("127.0.0.1:%d", port)

	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "tcp"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	code, out, errb := runCLI(t, "wait", target, "-tables", dir, "-timeout", "200ms", "-interval", "50ms")
	if code != exitFree {
		t.Fatalf("exit = %d, want %d: the bind really was accepted (stderr: %s)\n%s", code, exitFree, errb, out)
	}
	if !strings.Contains(out, "bindable: a plain bind() was accepted") {
		t.Errorf("the success is not stated:\n%s", out)
	}
	if !strings.Contains(out, "could not read the socket table") {
		t.Errorf("a success on blind rounds must still disclose the blindness:\n%s", out)
	}
}

// The flags that exist to be refused. Each one would otherwise be an accepted
// command that quietly does something other than what it says.
func TestWaitRefusesWhatItCannotHonour(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"interval below the floor", []string{"wait", "127.0.0.1:9", "-interval", "10ms"}},
		{"zero interval", []string{"wait", "127.0.0.1:9", "-interval", "0s"}},
		{"negative timeout", []string{"wait", "127.0.0.1:9", "-timeout", "-1s"}},
		{"both protocols", []string{"wait", "127.0.0.1:9", "-proto", "both"}},
		{"unknown protocol", []string{"wait", "127.0.0.1:9", "-proto", "sctp"}},
		{"a condition that is not bindable", []string{"wait", "127.0.0.1:9", "-until-bindable", "free"}},
		{"no target", []string{"wait"}},
		{"two targets", []string{"wait", "127.0.0.1:9", "127.0.0.1:10"}},
		{"unparseable target", []string{"wait", "not-an-address"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, out, errb := runCLI(t, c.args...)
			if code != exitUsage {
				t.Fatalf("exit = %d, want %d (usage)\nstdout: %s\nstderr: %s", code, exitUsage, out, errb)
			}
			if strings.TrimSpace(errb) == "" {
				t.Error("refused without saying why")
			}
			if strings.Contains(out, "timeline") {
				t.Error("a refused command still produced a report")
			}
		})
	}
}

// The refusal of -proto both has to say why, not just "no": someone who typed it
// is asking the reasonable question "wait for whichever frees first".
func TestWaitExplainsWhyBothProtocolsAreRefused(t *testing.T) {
	_, _, errb := runCLI(t, "wait", "127.0.0.1:9", "-proto", "both")
	if !strings.Contains(errb, "independent") || !strings.Contains(errb, "one timeline") {
		t.Errorf("the refusal does not explain the two namespaces and the one timeline:\n%s", errb)
	}
}
