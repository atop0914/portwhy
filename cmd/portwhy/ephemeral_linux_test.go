//go:build linux

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// poolDir lays out the two port-pool tunables the way procfs does, so a test can
// state the host's range without changing the host's range.
func poolDir(t *testing.T, portRange string, reserved *string) string {
	t.Helper()
	dir := t.TempDir()
	full := filepath.Join(dir, "net", "ipv4")
	if err := os.MkdirAll(full, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(full, "ip_local_port_range"), []byte(portRange), 0o600); err != nil {
		t.Fatalf("write range: %v", err)
	}
	if reserved != nil {
		if err := os.WriteFile(filepath.Join(full, "ip_local_reserved_ports"), []byte(*reserved), 0o600); err != nil {
			t.Fatalf("write reserved: %v", err)
		}
	}
	return dir
}

func strptr(s string) *string { return &s }

// The two sentences as they appear in the report. Asserting on a whole clause
// rather than a keyword keeps these tests from passing on a stray word.
const (
	riskSentence     = "is inside the kernel's ephemeral range"
	reservedSentence = "is excluded from the ephemeral range"
)

// emptyTCPTables is the table of a port nobody holds: the shape in which the
// ephemeral risk is the only thing left to say.
func emptyTCPTables(t *testing.T) string {
	t.Helper()
	return tablesDir(t, map[string]string{"tcp": headerTCP + "\n"})
}

// The acceptance case: a port inside the measured range is reported as a risk,
// and the answer is still free with exit 0. Anything else would turn a
// one-in-fifty failure into a permanent false positive.
func TestWhyEphemeralRangeIsReportedAndStaysFree(t *testing.T) {
	dir := poolDir(t, "40000\t40999\n", strptr("\n"))
	code, out, errb := runCLI(t, "why", "127.0.0.1:40500", "-tables", emptyTCPTables(t), "-sysctl", dir, "-no-holders")
	if code != exitFree {
		t.Fatalf("exit = %d, want %d (stderr: %s)\n%s", code, exitFree, errb, out)
	}
	if !strings.Contains(out, "nothing in the kernel tables occupies it") {
		t.Errorf("missing free verdict:\n%s", out)
	}
	for _, want := range []string{"ephemeral range", "40000-40999", "source port"} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not mention %q:\n%s", want, out)
		}
	}
	// The file it read is part of the sentence, not a footnote.
	if !strings.Contains(out, "ip_local_port_range") {
		t.Errorf("output does not cite the tunable:\n%s", out)
	}
	if strings.Contains(out, reservedSentence) {
		t.Errorf("an unreserved port was reported as reserved:\n%s", out)
	}
}

// The reverse assertion: outside the pool, the tool says nothing about the pool.
func TestWhyEphemeralSilentOutsideTheRange(t *testing.T) {
	dir := poolDir(t, "40000\t40999\n", strptr("\n"))
	for _, target := range []string{"127.0.0.1:8080", "127.0.0.1:39999", "127.0.0.1:41000"} {
		code, out, errb := runCLI(t, "why", target, "-tables", emptyTCPTables(t), "-sysctl", dir, "-no-holders")
		if code != exitFree {
			t.Fatalf("%s: exit = %d, want %d (stderr: %s)\n%s", target, code, exitFree, errb, out)
		}
		if strings.Contains(out, "ephemeral") {
			t.Errorf("%s outside the range still talked about it:\n%s", target, out)
		}
	}
}

// Reserved is the good news, and it replaces the risk instead of joining it.
func TestWhyReservedPortLosesTheRisk(t *testing.T) {
	dir := poolDir(t, "40000\t40999\n", strptr("40500,40600-40700\n"))
	code, out, errb := runCLI(t, "why", "127.0.0.1:40500", "-tables", emptyTCPTables(t), "-sysctl", dir, "-no-holders")
	if code != exitFree {
		t.Fatalf("exit = %d, want %d (stderr: %s)\n%s", code, exitFree, errb, out)
	}
	if !strings.Contains(out, reservedSentence) {
		t.Errorf("missing the reserved-port sentence:\n%s", out)
	}
	if strings.Contains(out, riskSentence) {
		t.Errorf("a reserved port still carries the risk:\n%s", out)
	}

	// The neighbouring reserved range is not the port either: 40600-40700 must
	// not make 40550 reserved.
	code, out, errb = runCLI(t, "why", "127.0.0.1:40550", "-tables", emptyTCPTables(t), "-sysctl", dir, "-no-holders")
	if code != exitFree {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitFree, errb)
	}
	if strings.Contains(out, reservedSentence) {
		t.Errorf("a port next to a reserved range was reported as reserved:\n%s", out)
	}
}

// A range nobody could read is a hole, and it is stated as one — with no
// interval in the output at all. Printing 32768-60999 here is the mistake this
// project exists to replace.
func TestWhyUnreadableRangeIsALimitWithoutADefault(t *testing.T) {
	for name, body := range map[string]string{
		"not numbers": "abc\n",
		"reversed":    "60000 30000\n",
		"one field":   "40000\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := poolDir(t, body, strptr("\n"))
			code, out, errb := runCLI(t, "why", "127.0.0.1:40500", "-tables", emptyTCPTables(t), "-sysctl", dir, "-no-holders")
			if code != exitFree {
				t.Fatalf("exit = %d, want %d: an unread range is not evidence about who holds the port (stderr: %s)\n%s",
					code, exitFree, errb, out)
			}
			if !strings.Contains(out, "not measured") {
				t.Errorf("output does not say the measurement is missing:\n%s", out)
			}
			if !strings.Contains(out, "limits") {
				t.Errorf("the hole was not listed under limits:\n%s", out)
			}
			for _, forbidden := range []string{"32768", "60999"} {
				if strings.Contains(out, forbidden) {
					t.Errorf("output printed the usual default (%s) for a host nobody read:\n%s", forbidden, out)
				}
			}
			if strings.Contains(out, riskSentence) {
				t.Errorf("an unmeasured range produced a risk statement:\n%s", out)
			}
		})
	}
}

// A missing reserved-ports file must not be read as "nothing is reserved": the
// risk stays, with the check that did not happen named in the sentence.
func TestWhyMissingReservedFileKeepsTheRiskWithACaveat(t *testing.T) {
	dir := poolDir(t, "40000\t40999\n", nil)
	code, out, errb := runCLI(t, "why", "127.0.0.1:40500", "-tables", emptyTCPTables(t), "-sysctl", dir, "-no-holders")
	if code != exitFree {
		t.Fatalf("exit = %d, want %d (stderr: %s)\n%s", code, exitFree, errb, out)
	}
	if !strings.Contains(out, "ephemeral range") {
		t.Errorf("missing the risk:\n%s", out)
	}
	if !strings.Contains(out, "could not be read") {
		t.Errorf("the unread reservation list is not disclosed:\n%s", out)
	}
	if strings.Contains(out, "does not exclude it") {
		t.Errorf("the report claims a reservation check that never ran:\n%s", out)
	}
}

// JSON carries the numbers with a measured switch that cannot be faked by a zero
// value, and the reserved list keeps "read, none" apart from "not there".
func TestWhyJSONCarriesPortPoolEvidence(t *testing.T) {
	t.Run("measured", func(t *testing.T) {
		dir := poolDir(t, "40000\t40999\n", strptr("40500,40600-40610\n"))
		code, out, errb := runCLI(t, "why", "127.0.0.1:40500", "-json",
			"-tables", emptyTCPTables(t), "-sysctl", dir, "-no-holders")
		if code != exitFree {
			t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitFree, errb)
		}
		var rep struct {
			Evidence struct {
				EphemeralRange struct {
					Measured bool   `json:"measured"`
					Low      *int   `json:"low"`
					High     *int   `json:"high"`
					Path     string `json:"path"`
					Error    string `json:"error"`
				} `json:"ephemeral_range"`
				ReservedPorts struct {
					Measured bool     `json:"measured"`
					Present  bool     `json:"present"`
					Ports    []string `json:"ports"`
					Path     string   `json:"path"`
				} `json:"reserved_ports"`
			} `json:"evidence"`
		}
		if err := json.Unmarshal([]byte(out), &rep); err != nil {
			t.Fatalf("not JSON: %v\n%s", err, out)
		}
		e := rep.Evidence.EphemeralRange
		if !e.Measured || e.Low == nil || e.High == nil || *e.Low != 40000 || *e.High != 40999 {
			t.Errorf("ephemeral_range = %+v, want measured 40000-40999", e)
		}
		if !strings.HasPrefix(e.Path, dir) {
			t.Errorf("path = %q, want the file that was read", e.Path)
		}
		r := rep.Evidence.ReservedPorts
		if !r.Measured || !r.Present {
			t.Errorf("reserved_ports = %+v, want measured and present", r)
		}
		if want := []string{"40500", "40600-40610"}; strings.Join(r.Ports, ",") != strings.Join(want, ",") {
			t.Errorf("ports = %v, want %v", r.Ports, want)
		}
	})

	t.Run("unreadable", func(t *testing.T) {
		dir := poolDir(t, "abc\n", nil)
		code, out, errb := runCLI(t, "why", "127.0.0.1:40500", "-json",
			"-tables", emptyTCPTables(t), "-sysctl", dir, "-no-holders")
		if code != exitFree {
			t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitFree, errb)
		}
		var rep struct {
			Evidence struct {
				EphemeralRange map[string]any `json:"ephemeral_range"`
				ReservedPorts  map[string]any `json:"reserved_ports"`
			} `json:"evidence"`
		}
		if err := json.Unmarshal([]byte(out), &rep); err != nil {
			t.Fatalf("not JSON: %v\n%s", err, out)
		}
		e := rep.Evidence.EphemeralRange
		if e["measured"] != false {
			t.Errorf("measured = %v, want false", e["measured"])
		}
		for _, key := range []string{"low", "high"} {
			if _, present := e[key]; present {
				t.Errorf("a failed read still carried %s: %v", key, e[key])
			}
		}
		if s, _ := e["error"].(string); strings.TrimSpace(s) == "" {
			t.Error("no error recorded for the failed read")
		}
		r := rep.Evidence.ReservedPorts
		if r["measured"] != false {
			t.Errorf("reserved measured = %v, want false for a missing file", r["measured"])
		}
		if r["present"] != false {
			t.Errorf("reserved present = %v, want false for a missing file", r["present"])
		}
	})
}

// Same table, same measurements, two runs: byte for byte identical. A report that
// changes between runs cannot be diffed, and every claim in it becomes unfalsifiable.
func TestWhyPortPoolOutputIsReproducible(t *testing.T) {
	dir := poolDir(t, "40000\t40999\n", strptr("\n"))
	first := ""
	for i := 0; i < 2; i++ {
		_, out, errb := runCLI(t, "why", "127.0.0.1:40500", "-json",
			"-tables", emptyTCPTables(t), "-sysctl", dir, "-no-holders")
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

// The live acceptance: the interval printed by the tool is the interval this
// kernel publishes, read here independently and compared. No fixture, no default.
func TestWhyPrintsTheRangeThisHostMeasured(t *testing.T) {
	path := "/proc/sys/net/ipv4/ip_local_port_range"
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("cannot read %s: %v", path, err)
	}
	fields := strings.Fields(string(raw))
	if len(fields) != 2 {
		t.Skipf("%s printed %q", path, raw)
	}
	low, errLow := strconv.Atoi(fields[0])
	high, errHigh := strconv.Atoi(fields[1])
	if errLow != nil || errHigh != nil || low >= high {
		t.Skipf("%s printed %q", path, raw)
	}
	if high-low < 4 {
		t.Skipf("range %d-%d is too narrow to pick a port inside", low, high)
	}
	port := low + (high-low)/2

	// A port this host has reserved would answer the reserved-port sentence instead, which is
	// the right answer but not the one this test is about.
	if reserved, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_reserved_ports"); err == nil {
		for _, field := range strings.Split(strings.TrimSpace(string(reserved)), ",") {
			if field == strconv.Itoa(port) {
				t.Skipf("port %d is reserved on this host", port)
			}
		}
	}

	code, out, errb := runCLI(t, "why", fmt.Sprintf("127.0.0.1:%d", port), "-tables", emptyTCPTables(t), "-no-holders")
	if code != exitFree {
		t.Fatalf("exit = %d, want %d (stderr: %s)\n%s", code, exitFree, errb, out)
	}
	want := fmt.Sprintf("%d-%d", low, high)
	if !strings.Contains(out, want) {
		t.Errorf("output does not print the range this host measured (%s):\n%s", want, out)
	}
	t.Logf("this host: %d-%d, queried %d", low, high, port)
}
