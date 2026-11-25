//go:build linux

package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// Two protocols, two answers. The UDP half is taken and the TCP half is free,
// which is the normal state of a DNS host — and exactly the shape that a single
// folded kind would have to lie about.
func TestBothPrintsTwoIndependentAnswers(t *testing.T) {
	dir := tablesDir(t, map[string]string{
		"tcp": headerTCP + "\n",
		"udp": headerTCP + "\n" + row(v4Loopback, 5353, "07", 201),
	})
	code, out, errb := runCLI(t, "why", "127.0.0.1:5353", "-proto", "both", "-tables", dir, "-no-holders")
	// tcp is free, so the contract's code is 0 — and the report has to say the
	// udp answer alone would have been 1.
	if code != exitFree {
		t.Fatalf("exit = %d, want %d (stderr: %s)\n%s", code, exitFree, errb, out)
	}
	if !strings.Contains(out, "127.0.0.1:5353/tcp — nothing in the kernel tables occupies it") {
		t.Errorf("tcp answer missing or wrong:\n%s", out)
	}
	if !strings.Contains(out, "127.0.0.1:5353/udp — a bound socket holds it") {
		t.Errorf("udp answer missing or wrong:\n%s", out)
	}
	// The exit code had to pick one protocol; the report has to say so, with both
	// numbers, or a script would read 0 as "the port is free".
	if !strings.Contains(out, "exit code: 0, from the tcp answer; the udp answer alone would exit 1") {
		t.Errorf("the exit-code choice is not stated:\n%s", out)
	}
	if !strings.Contains(out, "separate namespaces") {
		t.Errorf("the report does not warn that the two answers are independent:\n%s", out)
	}
}

// The mirror case: tcp taken, udp free. exit 1, and the udp answer must not be
// swallowed by the tcp verdict.
func TestBothWithTakenTCPReportsFreeUDP(t *testing.T) {
	dir := tablesDir(t, map[string]string{
		"tcp": headerTCP + "\n" + row(v4Loopback, 8080, "0A", 301),
		"udp": headerTCP + "\n",
	})
	code, out, errb := runCLI(t, "why", "127.0.0.1:8080", "-proto", "both", "-tables", dir, "-no-holders")
	if code != exitTaken {
		t.Fatalf("exit = %d, want %d (stderr: %s)\n%s", code, exitTaken, errb, out)
	}
	if !strings.Contains(out, "127.0.0.1:8080/udp — nothing in the kernel tables occupies it") {
		t.Errorf("udp half was not answered:\n%s", out)
	}
	if !strings.Contains(out, "exit code: 1, from the tcp answer; the udp answer alone would exit 0") {
		t.Errorf("the exit-code choice is not stated:\n%s", out)
	}
}

// JSON has to keep the two reports apart: one object with two kinds and two sets
// of findings would leave a consumer unable to tell which row answered which.
func TestBothJSONKeepsReportsApart(t *testing.T) {
	dir := tablesDir(t, map[string]string{
		"tcp": headerTCP + "\n" + row(v4Loopback, 5353, "0A", 401),
		"udp": headerTCP + "\n" + row(v4Loopback, 5353, "07", 402),
	})
	code, out, errb := runCLI(t, "why", "127.0.0.1:5353", "-proto", "both", "-json", "-tables", dir, "-no-holders")
	if code != exitTaken {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitTaken, errb)
	}
	var rep struct {
		Target   string `json:"target"`
		Both     bool   `json:"both"`
		ExitFrom string `json:"exit_from"`
		TCP      struct {
			Proto    string `json:"proto"`
			Kind     string `json:"kind"`
			Findings []struct {
				State  string `json:"state"`
				Effect string `json:"effect"`
			} `json:"findings"`
		} `json:"tcp"`
		UDP struct {
			Proto    string `json:"proto"`
			Kind     string `json:"kind"`
			Findings []struct {
				State  string `json:"state"`
				Effect string `json:"effect"`
			} `json:"findings"`
		} `json:"udp"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("bad JSON: %v\n%s", err, out)
	}
	if !rep.Both || rep.ExitFrom != "tcp" || rep.Target != "127.0.0.1:5353" {
		t.Errorf("wrapper = %+v, want both=true exit_from=tcp target=127.0.0.1:5353", rep)
	}
	if rep.TCP.Proto != "tcp" || rep.TCP.Kind != "listening" {
		t.Errorf("tcp = %s/%s, want tcp/listening", rep.TCP.Proto, rep.TCP.Kind)
	}
	if rep.UDP.Proto != "udp" || rep.UDP.Kind != "bound" {
		t.Errorf("udp = %s/%s, want udp/bound", rep.UDP.Proto, rep.UDP.Kind)
	}
	if len(rep.TCP.Findings) != 1 || len(rep.UDP.Findings) != 1 {
		t.Fatalf("findings = %d tcp / %d udp, want 1 each", len(rep.TCP.Findings), len(rep.UDP.Findings))
	}
	// The same state number carries a different effect in the two reports. That
	// is the whole point of keeping them apart.
	if rep.TCP.Findings[0].Effect != "blocks" || rep.UDP.Findings[0].Effect != "blocks" {
		t.Errorf("effects = %q/%q, want blocks/blocks for a listener and a bound udp socket",
			rep.TCP.Findings[0].Effect, rep.UDP.Findings[0].Effect)
	}
}

// There is no bind experiment that answers both protocols at once, so the
// combination is refused instead of quietly probing the tcp half and letting the
// reader think the udp answer was measured.
func TestBothWithProbeIsUsageError(t *testing.T) {
	dir := tablesDir(t, map[string]string{"tcp": headerTCP + "\n", "udp": headerTCP + "\n"})
	code, _, errb := runCLI(t, "why", "127.0.0.1:5353", "-proto", "both", "-probe", "-tables", dir, "-no-holders")
	if code != exitUsage {
		t.Fatalf("exit = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(errb, "cannot answer -proto both") {
		t.Errorf("stderr does not explain why probing both is refused: %s", errb)
	}
}

// An unknown protocol is a usage error, not a silent fallback to tcp: a typo that
// answered anyway would be wrong in the most believable way.
func TestUnknownProtoIsUsageError(t *testing.T) {
	dir := tablesDir(t, map[string]string{"tcp": headerTCP + "\n"})
	code, _, errb := runCLI(t, "why", "127.0.0.1:5353", "-proto", "sctp", "-tables", dir, "-no-holders")
	if code != exitUsage {
		t.Fatalf("exit = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(errb, "tcp, udp or both") {
		t.Errorf("stderr does not name the accepted values: %s", errb)
	}
}

// -all must keep working in both mode. Rows are allowed to come from either
// table — the flag means "every row on this port", and the neighbours are how a
// reader sees the other protocol — but a row that took part in an answer has to
// belong to that answer's protocol. A tcp listener counted in the udp verdict
// would be the same leak as a udp row moving a tcp answer.
func TestBothWithAllKeepsEachVerdictOnItsOwnRows(t *testing.T) {
	dir := tablesDir(t, map[string]string{
		"tcp": headerTCP + "\n" + row(v4Loopback, 5353, "0A", 501) + "\n" + row(v4Loopback, 9999, "0A", 502),
		"udp": headerTCP + "\n" + row(v4Loopback, 5353, "07", 503),
	})
	code, out, errb := runCLI(t, "why", "127.0.0.1:5353", "-proto", "both", "-all", "-json",
		"-tables", dir, "-no-holders")
	if code != exitTaken {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitTaken, errb)
	}
	type allRows struct {
		Rows *[]struct {
			Match string `json:"match"`
			Table string `json:"table"`
		} `json:"rows"`
	}
	var rep struct {
		TCP allRows `json:"tcp"`
		UDP allRows `json:"udp"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("bad JSON: %v\n%s", err, out)
	}
	if rep.TCP.Rows == nil || rep.UDP.Rows == nil {
		t.Fatal("rows missing from a -all run")
	}
	for _, side := range []struct {
		name string
		rows []struct {
			Match string `json:"match"`
			Table string `json:"table"`
		}
		proto string
	}{
		{"tcp", *rep.TCP.Rows, "tcp"},
		{"udp", *rep.UDP.Rows, "udp"},
	} {
		matched := 0
		for _, r := range side.rows {
			if r.Match != "matched" {
				continue
			}
			matched++
			if !strings.HasPrefix(r.Table, side.proto) {
				t.Errorf("%s verdict counted a row from table %q", side.name, r.Table)
			}
		}
		if matched != 1 {
			t.Errorf("%s verdict matched %d rows, want 1", side.name, matched)
		}
	}
}
