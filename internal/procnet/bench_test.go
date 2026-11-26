package procnet

// Benchmarks for the three costs a `wait` round pays, plus the encoder every
// fixture now goes through. They are recorded in docs/design.md and are not a CI
// gate: a shared runner's noise is larger than the difference a regression of
// this size would make, so an absolute threshold there would be a false alarm
// generator. Run them by hand, on an idle machine, and write the median down.
//
// Nothing here caches between iterations on purpose. A cache would report the
// cost of reading the tables once and then describe every later round with the
// first round's instant — the same mistake as reusing a table across rounds.

import (
	"bytes"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// fourTables is one row per table, written so that the parser has real work to
// do. The addresses go through FormatAddr (never hand-copied hex): a fixture the
// parser cannot read benchmarks the error path, and reports a very fast number
// for doing nothing.
func fourTables(tb testing.TB) map[string]string {
	tb.Helper()
	row := func(port uint16, state string) string {
		a, err := FormatAddr(Addr{IP: netip.MustParseAddr("127.0.0.1"), Port: port})
		if err != nil {
			tb.Fatalf("FormatAddr: %v", err)
		}
		return "   0: " + a + " 00000000:0000 " + state +
			" 00000000:00000000 00:00000000 00000000     0        0 29841669 1 0000000000000000 100 0 0 10 0\n"
	}
	return map[string]string{
		"tcp":  headerTCP + "\n" + row(0x1F90, "0A"),
		"tcp6": headerTCP6 + "\n",
		"udp":  headerTCP + "\n" + row(0x1F91, "07"),
		"udp6": headerTCP6 + "\n",
	}
}

func writeTables(tb testing.TB, dir string) {
	tb.Helper()
	for name, body := range fourTables(tb) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			tb.Fatalf("write %s: %v", name, err)
		}
	}
}

// BenchmarkReadAll measures the four opens plus the four parses, which is where
// a round spends most of its time: the cost is the kernel generating the text,
// not our reader.
func BenchmarkReadAll(b *testing.B) {
	b.Run("fixture", func(b *testing.B) {
		dir := b.TempDir()
		writeTables(b, dir)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			tables := ReadAll(dir)
			for _, t := range tables {
				if t.Err != nil {
					b.Fatalf("%s: %v", t.Name, t.Err)
				}
			}
		}
	})

	b.Run("live", func(b *testing.B) {
		if _, err := os.Stat(DefaultDir); err != nil {
			b.Skipf("no kernel tables here: %v", err)
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = ReadAll(DefaultDir)
		}
	})
}

// BenchmarkParse is ReadAll without the syscalls: it prices the parser, which is
// the only part of the cost this project controls.
func BenchmarkParse(b *testing.B) {
	body := []byte(tableListening)
	b.SetBytes(int64(len(body)))
	for i := 0; i < b.N; i++ {
		if _, err := Parse("tcp", TCP, V4, bytes.NewReader(body)); err != nil {
			b.Fatalf("Parse: %v", err)
		}
	}
}

// BenchmarkFormatAddr is on the fixture path rather than the read path, but it
// is the function a wrong-byte-order bug hides in, so it gets a number.
func BenchmarkFormatAddr(b *testing.B) {
	a := Addr{IP: netip.MustParseAddr("::ffff:127.0.0.1"), Port: 8080}
	for i := 0; i < b.N; i++ {
		if _, err := FormatAddr(a); err != nil {
			b.Fatalf("FormatAddr: %v", err)
		}
	}
}
