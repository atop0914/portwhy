//go:build linux

package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// batchLines splits NDJSON output and insists that every line parses on its own.
// "On its own" is the contract: a consumer reading this stream line by line must
// never need the previous line to make sense of the next one.
func batchLines(t *testing.T, out string) []map[string]any {
	t.Helper()
	if out == "" {
		return nil
	}
	if !strings.HasSuffix(out, "\n") {
		t.Fatalf("output does not end with a newline: %q", out)
	}
	raw := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	lines := make([]map[string]any, 0, len(raw))
	for i, line := range raw {
		if strings.Count(line, "\n") != 0 {
			t.Fatalf("line %d contains a newline; NDJSON means one object per line", i+1)
		}
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Fatalf("line %d is not JSON on its own: %v\n%s", i+1, err, line)
		}
		lines = append(lines, obj)
	}
	return lines
}

// The three answers in one run, and an exit code that belongs to the worst of
// them. The unknown line is made by a row whose state code this build does not
// know, which is a per-target hole — the only kind of hole a batch can have,
// since the tables are read once for the whole run.
func TestBatchAnswersEveryLineAndExitsWithTheWorst(t *testing.T) {
	dir := tablesDir(t, map[string]string{
		"tcp": headerTCP + "\n" +
			row(v4Loopback, 9001, "0A", 111) + "\n" +
			row(v4Loopback, 9003, "3F", 112) + "\n",
	})
	stdin := "127.0.0.1:9000\n127.0.0.1:9001\n127.0.0.1:9003\n"
	code, out, errb := runCLIStdin(t, stdin, "why", "-batch", "-tables", dir, "-no-holders")
	if code != exitUnknown {
		t.Fatalf("exit = %d, want %d: one unknown line must not be washed out (stderr: %s)\n%s",
			code, exitUnknown, errb, out)
	}
	lines := batchLines(t, out)
	if len(lines) != 3 {
		t.Fatalf("got %d lines for 3 targets:\n%s", len(lines), out)
	}
	want := []struct{ target, kind string }{
		{"127.0.0.1:9000", "free"},
		{"127.0.0.1:9001", "listening"},
		{"127.0.0.1:9003", "unknown"},
	}
	for i, w := range want {
		if got := lines[i]["kind"]; got != w.kind {
			t.Errorf("line %d kind = %v, want %s", i+1, got, w.kind)
		}
		if got := lines[i]["target"]; got != w.target {
			t.Errorf("line %d target = %v, want %s (each line has to say who it is about)",
				i+1, got, w.target)
		}
		// The line is a port report, not a reduced one: the fields a single
		// -json run produces have to be here too.
		for _, field := range []string{"schema_version", "proto", "findings", "reasons", "evidence", "version"} {
			if _, ok := lines[i][field]; !ok {
				t.Errorf("line %d is missing %q", i+1, field)
			}
		}
	}
}

// A line that is not a target answers for itself and nothing else.
func TestBatchBadLineDoesNotDisturbTheOthers(t *testing.T) {
	dir := tablesDir(t, map[string]string{
		"tcp": headerTCP + "\n" + row(v4Loopback, 9001, "0A", 111),
	})
	// A blank line in the middle is not a target and not an error.
	stdin := "127.0.0.1:9000\nnonsense\n\n127.0.0.1:9001\n"
	code, out, errb := runCLIStdin(t, stdin, "why", "-batch", "-tables", dir, "-no-holders")
	if code != exitUsage {
		t.Fatalf("exit = %d, want %d: a line the tool cannot read outranks the answers (stderr: %s)",
			code, exitUsage, errb)
	}
	lines := batchLines(t, out)
	if len(lines) != 3 {
		t.Fatalf("got %d lines for 3 non-blank targets:\n%s", len(lines), out)
	}
	if lines[0]["kind"] != "free" || lines[2]["kind"] != "listening" {
		t.Errorf("the good lines changed: kinds = %v, %v", lines[0]["kind"], lines[2]["kind"])
	}
	bad := lines[1]
	if bad["kind"] != kindUsage {
		t.Errorf("bad line kind = %v, want %q", bad["kind"], kindUsage)
	}
	if msg, _ := bad["error"].(string); msg == "" {
		t.Error("bad line carries no reason")
	}
	if bad["target"] != "nonsense" {
		t.Errorf("bad line target = %v, want the text as typed", bad["target"])
	}
	// No evidence was gathered for a line that never became a question, and an
	// empty evidence object would say it was gathered and found nothing.
	if _, ok := bad["evidence"]; ok {
		t.Error("bad line carries an evidence object; nothing was measured")
	}
}

// An empty batch is a usage error. "Nothing was asked" is not "nothing is in the
// way", and a monitor whose input file failed to generate must not see exit 0.
func TestBatchEmptyInputIsAUsageError(t *testing.T) {
	dir := tablesDir(t, map[string]string{"tcp": headerTCP + "\n"})
	for _, stdin := range []string{"", "\n", "   \n\t\n"} {
		code, out, errb := runCLIStdin(t, stdin, "why", "-batch", "-tables", dir, "-no-holders")
		if code != exitUsage {
			t.Errorf("stdin %q: exit = %d, want %d", stdin, code, exitUsage)
		}
		if out != "" {
			t.Errorf("stdin %q: stdout = %q, want no objects", stdin, out)
		}
		if !strings.Contains(errb, "no target") {
			t.Errorf("stdin %q: stderr does not say why: %q", stdin, errb)
		}
	}
}

// A batch of probes is a batch of real binds. The refusal has to name the reason,
// not just say no.
func TestBatchRefusesProbeAndStrayTarget(t *testing.T) {
	dir := tablesDir(t, map[string]string{"tcp": headerTCP + "\n"})
	code, out, errb := runCLIStdin(t, "", "why", "-batch", "-probe", "-tables", dir)
	if code != exitUsage {
		t.Errorf("-batch -probe: exit = %d, want %d", code, exitUsage)
	}
	if out != "" {
		t.Errorf("-batch -probe wrote %q", out)
	}
	if !strings.Contains(errb, "N side effects") {
		t.Errorf("-batch -probe does not explain itself: %q", errb)
	}

	code, _, errb = runCLIStdin(t, "", "why", "127.0.0.1:9000", "-batch", "-tables", dir)
	if code != exitUsage {
		t.Errorf("-batch with a target: exit = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(errb, "stdin") {
		t.Errorf("-batch with a target does not say where targets come from: %q", errb)
	}
}

// Two kinds of question do not share one stream.
func TestUnixRefusesBatch(t *testing.T) {
	code, out, errb := runCLI(t, "unix", "@name", "-batch")
	if code != exitUsage {
		t.Errorf("exit = %d, want %d", code, exitUsage)
	}
	if out != "" {
		t.Errorf("stdout = %q, want nothing", out)
	}
	if !strings.Contains(errb, "port targets only") {
		t.Errorf("stderr does not explain: %q", errb)
	}
}

// Each line must reach the sink as its own write. A consumer reading this live
// (a pipe into a monitor, a terminal with head -3) depends on it, and a buffer
// that only fills at the end would pass every other test in this file.
func TestBatchFlushesEveryLine(t *testing.T) {
	dir := tablesDir(t, map[string]string{"tcp": headerTCP + "\n"})
	spy := &writeSpy{}
	code := run([]string{"why", "-batch", "-tables", dir, "-no-holders"},
		strings.NewReader("127.0.0.1:9000\n127.0.0.1:9001\n"), spy, &strings.Builder{})
	if code != exitFree {
		t.Fatalf("exit = %d, want %d", code, exitFree)
	}
	if len(spy.writes) != 2 {
		t.Fatalf("got %d writes for 2 lines, want one write per line", len(spy.writes))
	}
	for i, w := range spy.writes {
		if strings.Count(w, "\n") != 1 || !strings.HasSuffix(w, "\n") {
			t.Errorf("write %d = %q, want exactly one complete line", i+1, w)
		}
	}
}

type writeSpy struct{ writes []string }

func (s *writeSpy) Write(p []byte) (int, error) {
	s.writes = append(s.writes, string(p))
	return len(p), nil
}

// -proto both keeps its single-target rule inside a batch: two answers per line,
// and the exit code from the tcp half, which the line states in exit_from.
func TestBatchBothKeepsTwoAnswersAndTheTCPExitCode(t *testing.T) {
	dir := tablesDir(t, map[string]string{
		"tcp": headerTCP + "\n",
		"udp": headerTCP + "\n" + row(v4Loopback, 5353, "07", 201),
	})
	code, out, errb := runCLIStdin(t, "127.0.0.1:5353\n", "why", "-batch", "-proto", "both", "-tables", dir, "-no-holders")
	if code != exitFree {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitFree, errb)
	}
	lines := batchLines(t, out)
	if len(lines) != 1 {
		t.Fatalf("got %d lines, want 1:\n%s", len(lines), out)
	}
	line := lines[0]
	if line["exit_from"] != "tcp" {
		t.Errorf("exit_from = %v, want tcp", line["exit_from"])
	}
	tcp, ok := line["tcp"].(map[string]any)
	if !ok || tcp["kind"] != "free" {
		t.Errorf("tcp half = %v, want kind free", line["tcp"])
	}
	udp, ok := line["udp"].(map[string]any)
	if !ok || udp["kind"] != "bound" {
		t.Errorf("udp half = %v, want kind bound", line["udp"])
	}
}

// The aggregation order is a contract, so it is tested as one: usage outranks
// unknown, unknown outranks taken, taken outranks free.
func TestBatchSeverityOrder(t *testing.T) {
	cases := []struct {
		a, b, want int
	}{
		{exitFree, exitFree, exitFree},
		{exitFree, exitTaken, exitTaken},
		{exitTaken, exitFree, exitTaken},
		{exitTaken, exitUnknown, exitUnknown},
		{exitUnknown, exitTaken, exitUnknown},
		{exitUnknown, exitUsage, exitUsage},
		{exitUsage, exitUnknown, exitUsage},
		{exitFree, exitUsage, exitUsage},
	}
	for _, c := range cases {
		if got := worseOf(c.a, c.b); got != c.want {
			t.Errorf("worseOf(%d, %d) = %d, want %d", c.a, c.b, got, c.want)
		}
		if got := worseOf(c.b, c.a); got != c.want {
			t.Errorf("worseOf(%d, %d) = %d, want %d (the order must not depend on which came first)",
				c.b, c.a, got, c.want)
		}
	}
}
