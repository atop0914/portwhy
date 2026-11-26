//go:build linux

package sockid

// The holder walk is the part of a round that grows with the machine rather than
// with the socket count: it opens every process's fd directory. It is recorded in
// docs/design.md, not asserted in CI — see the note in procnet/bench_test.go.

import (
	"os"
	"testing"
)

// BenchmarkScan prices one full walk of the live /proc. It is deliberately not a
// fixture: a fixture would measure the directory reader, while the number that
// matters for the 50ms floor is what walking a real machine costs.
func BenchmarkScan(b *testing.B) {
	if _, err := os.Stat(DefaultRoot); err != nil {
		b.Skipf("no procfs here: %v", err)
	}
	for i := 0; i < b.N; i++ {
		if _, err := Scan(DefaultRoot); err != nil {
			b.Fatalf("Scan: %v", err)
		}
	}
}
