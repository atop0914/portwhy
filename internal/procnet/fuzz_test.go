package procnet

import (
	"strconv"
	"strings"
	"testing"
)

// FuzzParse asks the question every caller depends on: for arbitrary bytes, does
// the parser either understand the whole table or refuse it? The failure guarded
// against here is not a panic — it is a parser that returns "the rows I managed
// to read" and lets the layer above conclude that an unreadable port is free.
//
// The seeds are a captured table, the two shapes that produced bugs (a TIME_WAIT
// row with inode 0, and two rows glued by a lost newline), and rows at the
// scanner's limits. Anything the fuzzer finds lands in testdata/fuzz/FuzzParse/
// and becomes an ordinary regression test from then on.
func FuzzParse(f *testing.F) {
	f.Add("")
	f.Add(headerTCP + "\n")
	f.Add(tableListening)
	f.Add(tableTimeWait)
	f.Add(tableIPv6)
	f.Add(headerTCP + "\n" + testRowPlain("0100007F:1F90", "0A", 7) + testRowPlain("0100007F:1F91", "0A", 8) + "\n")

	// A line longer than the 1 MiB scanner budget must be an error, not a
	// truncation that happens to parse.
	f.Add(headerTCP + "\n   0: " + strings.Repeat("0", 1<<20) + "\n")

	f.Fuzz(func(t *testing.T, in string) {
		socks, err := Parse("tcp", TCP, V4, strings.NewReader(in))
		if err != nil {
			// Half a table plus an error is still half a table: the caller has to
			// choose between trusting the rows and trusting the error, and there
			// is no right choice.
			if socks != nil {
				t.Fatalf("Parse returned %d row(s) alongside %v", len(socks), err)
			}
			return
		}

		// Success means every line after the header was understood. Counting the
		// lines independently is the point: it catches a parser that accepts a
		// table while dropping the lines it did not like.
		lines := strings.Split(in, "\n")
		if len(lines) == 0 || !strings.HasPrefix(strings.TrimSpace(lines[0]), "sl") {
			t.Fatalf("accepted input with no header line: %q", firstLine(in))
		}
		want := 0
		for _, l := range lines[1:] {
			if strings.TrimSpace(l) != "" {
				want++
			}
		}
		if len(socks) != want {
			t.Fatalf("%d row(s) from %d non-blank line(s) after the header", len(socks), want)
		}

		for i, s := range socks {
			if !s.Local.IP.IsValid() || !s.Remote.IP.IsValid() {
				t.Fatalf("row %d has an invalid address: %+v", i, s)
			}
			if s.Table != "tcp" || s.Proto != TCP || s.Family != V4 {
				t.Fatalf("row %d lost its provenance: %+v", i, s)
			}
			// Whatever the parser accepted must be something the encoder can
			// write back, and writing it back must reproduce the same endpoint.
			text, err := FormatAddr(s.Local)
			if err != nil {
				t.Fatalf("row %d local %v cannot be formatted: %v", i, s.Local, err)
			}
			back, err := parseHexAddr(text, V4)
			if err != nil {
				t.Fatalf("FormatAddr produced %q, which the decoder rejects: %v", text, err)
			}
			if back.IP != s.Local.IP || back.Port != s.Local.Port {
				t.Fatalf("round trip of row %d changed the endpoint: %v → %q → %v", i, s.Local, text, back)
			}
		}
	})
}

// FuzzDecodeAddr is the same question one level down, where the input is a single
// column. It is separated because the address decoder is reachable from a fixture
// or a capture that never goes through Parse, and because "returned an address"
// and "returned an error" must be the only two outcomes.
func FuzzDecodeAddr(f *testing.F) {
	f.Add("0100007F:922F", false)
	f.Add("00000000:0000", false)
	f.Add("00000000000000000000000001000000:1F90", true)
	f.Add("0000000000000000FFFF00000100007F:1F90", true)
	f.Add("::1", false)
	f.Add("", false)
	f.Add("0100007F", false)
	f.Add("0100007F:ZZZZ", false)
	f.Add("0100007F:00000", false)

	f.Fuzz(func(t *testing.T, s string, v6 bool) {
		family := V4
		if v6 {
			family = V6
		}
		addr, err := parseHexAddr(s, family)
		if err != nil {
			// A failed decode must not carry half a result: a caller that ignores
			// the error would then act on an address nobody measured.
			if addr.IP.IsValid() || addr.Port != 0 {
				t.Fatalf("a failed decode of %q returned %+v", s, addr)
			}
			return
		}
		if family == V4 && !addr.IP.Is4() {
			t.Fatalf("decode of %q in the ipv4 table produced %v", s, addr.IP)
		}
		if family == V6 && addr.IP.Is4() {
			t.Fatalf("decode of %q in the ipv6 table produced a 4-byte address %v", s, addr.IP)
		}

		text, err := FormatAddr(addr)
		if err != nil {
			t.Fatalf("decoded %q to %v, which cannot be formatted: %v", s, addr, err)
		}
		back, err := parseHexAddr(text, family)
		if err != nil {
			t.Fatalf("FormatAddr produced %q, which the decoder rejects: %v", text, err)
		}
		if back.IP != addr.IP || back.Port != addr.Port {
			t.Fatalf("round trip of %q changed the endpoint: %v → %q → %v", s, addr, text, back)
		}
	})
}

// testRowPlain builds a row from an already-spelled local field, for seeds that
// are about the shape of the line rather than about an address.
func testRowPlain(local string, state string, inode int) string {
	return "   0: " + local + " 00000000:0000 " + state +
		" 00000000:00000000 00:00000000 00000000     0        0 " +
		strconv.Itoa(inode) + " 1 0000000000000000 100 0 0 10 0"
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
