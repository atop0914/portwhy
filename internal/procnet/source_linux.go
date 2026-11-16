//go:build linux

package procnet

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Spec names one table and what it contains.
type Spec struct {
	Name   string
	Proto  Proto
	Family Family
}

// Specs is every table this package knows how to read, in reporting order.
//
// UDP is here because binding a UDP port is a separate namespace from TCP:
// "port 53 is free" is not true when a resolver holds UDP 53.
var Specs = []Spec{
	{Name: "tcp", Proto: TCP, Family: V4},
	{Name: "tcp6", Proto: TCP, Family: V6},
	{Name: "udp", Proto: UDP, Family: V4},
	{Name: "udp6", Proto: UDP, Family: V6},
}

// DefaultDir is where the kernel keeps them.
const DefaultDir = "/proc/net"

// ReadAll reads every table under dir.
//
// One Table is returned per spec, in spec order, whatever happened: the caller
// gets a per-table verdict instead of a single error that hides which tables it
// could see. Nothing here decides what a missing table means — that judgement
// belongs to the layer that knows what the user asked.
func ReadAll(dir string) []Table {
	out := make([]Table, 0, len(Specs))
	for _, spec := range Specs {
		out = append(out, read(dir, spec))
	}
	return out
}

func read(dir string, spec Spec) Table {
	t := Table{Name: spec.Name, Proto: spec.Proto, Family: spec.Family}
	path := filepath.Join(dir, spec.Name)
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			t.Err = fmt.Errorf("%w: %s", ErrTableMissing, path)
		} else {
			t.Err = fmt.Errorf("procnet: open %s: %w", path, err)
		}
		return t
	}
	// Read-only descriptor: a close error cannot change what was parsed.
	defer func() { _ = f.Close() }()

	socks, err := Parse(spec.Name, spec.Proto, spec.Family, f)
	if err != nil {
		t.Err = err
		return t
	}
	t.Sockets = socks
	return t
}
