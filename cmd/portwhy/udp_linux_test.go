//go:build linux

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
)

// A real bound UDP socket, judged from the live tables.
//
// The premise is checked first: a second plain bind() on the same address must
// really fail. Without that step the test would be asserting the tool agrees with
// itself — and the whole point is that st=07 in /proc/net/udp is a bound socket,
// not a released one.
func TestWhyReportsRealBoundUDPPort(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind udp: %v", err)
	}
	defer func() { _ = conn.Close() }()
	addr := conn.LocalAddr().String()
	port := conn.LocalAddr().(*net.UDPAddr).Port

	second, err := net.ListenPacket("udp", addr)
	if err == nil {
		_ = second.Close()
		t.Fatalf("premise failed: a second bind on %s succeeded, so nothing holds it", addr)
	}
	if !strings.Contains(err.Error(), "address already in use") {
		t.Fatalf("premise failed: second bind returned %v, want EADDRINUSE", err)
	}

	code, out, errb := runCLI(t, "why", addr, "-proto", "udp", "-no-holders")
	if code != exitTaken {
		t.Fatalf("exit = %d, want %d (stderr: %s)\n%s", code, exitTaken, errb, out)
	}
	if !strings.Contains(out, "a bound socket holds it") {
		t.Errorf("answer does not say a bound socket holds it:\n%s", out)
	}
	if strings.Contains(out, "listening socket holds it") {
		t.Errorf("udp answer borrowed the tcp sentence:\n%s", out)
	}
	if !strings.Contains(out, fmt.Sprintf(":%d", port)) {
		t.Errorf("answer does not name port %d:\n%s", port, out)
	}

	// The reverse assertion, on the same live kernel: TCP on this port is free.
	// A UDP row must not leak into a TCP question.
	code, out, errb = runCLI(t, "why", addr, "-proto", "tcp", "-no-holders")
	if code != exitFree {
		t.Fatalf("tcp on a udp-bound port exited %d, want %d (stderr: %s)\n%s",
			code, exitFree, errb, out)
	}
	if strings.Contains(out, "bound socket holds it") {
		t.Errorf("tcp answer claims the udp holder:\n%s", out)
	}
}

// The JSON shape is a contract: a consumer keys on kind and effect, so the UDP
// answer must say "bound" and the row must carry the UDP reading of st=07.
func TestWhyUDPJSONSaysBoundAndBlocks(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind udp: %v", err)
	}
	defer func() { _ = conn.Close() }()

	code, out, errb := runCLI(t, "why", conn.LocalAddr().String(), "-proto", "udp", "-json", "-no-holders")
	if code != exitTaken {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitTaken, errb)
	}
	var rep struct {
		Proto    string `json:"proto"`
		Kind     string `json:"kind"`
		Findings []struct {
			State  string `json:"state"`
			Effect string `json:"effect"`
			Table  string `json:"table"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("bad JSON: %v\n%s", err, out)
	}
	if rep.Proto != "udp" || rep.Kind != "bound" {
		t.Errorf("proto/kind = %q/%q, want udp/bound", rep.Proto, rep.Kind)
	}
	if len(rep.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(rep.Findings))
	}
	if rep.Findings[0].State != "CLOSE" {
		t.Errorf("state = %q, want CLOSE (the kernel's spelling of a bound udp socket)",
			rep.Findings[0].State)
	}
	if rep.Findings[0].Effect != "blocks" {
		t.Errorf("effect = %q, want blocks", rep.Findings[0].Effect)
	}
	if !strings.HasPrefix(rep.Findings[0].Table, "udp") {
		t.Errorf("finding came from table %q, want a udp table", rep.Findings[0].Table)
	}
}

// A port with nothing on it at all: UDP free must not carry the TCP-only
// bind-without-listen caveat, because a bound UDP socket is always in the table.
func TestWhyFreeUDPHasNoTCPOnlyCaveat(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind udp: %v", err)
	}
	addr := conn.LocalAddr().String()
	_ = conn.Close()

	code, out, errb := runCLI(t, "why", addr, "-proto", "udp", "-no-holders")
	if code != exitFree {
		t.Fatalf("exit = %d, want %d (stderr: %s)\n%s", code, exitFree, errb, out)
	}
	if strings.Contains(out, "bound without listen()") {
		t.Errorf("udp free answer carries the tcp-only caveat:\n%s", out)
	}
}

// The state table prints both vocabularies, and the sentence that keeps them
// apart. Without it a reader would read st=07's UDP meaning as the TCP one.
func TestStatesShowsBothProtocolsAndTheTrap(t *testing.T) {
	code, out, errb := runCLI(t, "states")
	if code != exitFree {
		t.Fatalf("exit = %d (stderr: %s)", code, errb)
	}
	for _, want := range []string{"tcp effect", "udp effect", "UDP states", "bound-and-unconnected"} {
		if !strings.Contains(out, want) {
			t.Errorf("states output is missing %q:\n%s", want, out)
		}
	}
	// The UDP section must not offer states UDP cannot have.
	udpSection := out[strings.Index(out, "UDP states"):]
	for _, impossible := range []string{"TIME_WAIT", "LISTEN "} {
		if strings.Contains(udpSection, impossible) {
			t.Errorf("udp section names a state udp cannot be in (%q):\n%s", impossible, udpSection)
		}
	}
}
