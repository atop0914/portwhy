//go:build linux

package unixsock

import (
	"net"
	"path/filepath"
	"testing"
)

// A real socket file, made by a real listener. The kind has to come out as
// "socket": that is the word the report prints when it tells a user their file is
// the thing in the way.
func TestInspectRealSocketFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer func() { _ = ln.Close() }()

	p := Inspect(path)
	if !p.Measured || !p.Exists {
		t.Fatalf("a live socket file measured as %+v", p)
	}
	if p.Kind != "socket" || !p.IsSocket() {
		t.Errorf("kind = %q, IsSocket = %v, want socket", p.Kind, p.IsSocket())
	}
}

// The table lookup this package exists for: a live listener is in /proc/net/unix,
// with the flag that says it is listening.
func TestReadFindsARealListener(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer func() { _ = ln.Close() }()

	table := Read(DefaultDir)
	if !table.Bound() {
		t.Fatalf("reading %s/unix: %v", DefaultDir, table.Err)
	}
	found := false
	for _, s := range table.Sockets {
		if s.Name != path {
			continue
		}
		found = true
		if !s.Listening() {
			t.Errorf("live listener %q is in the table without the listening flag", path)
		}
		if s.Inode == 0 {
			t.Errorf("live listener %q has inode 0, so no process could be named for it", path)
		}
	}
	if !found {
		t.Fatalf("no row for the live listener %q in %s/unix", path, DefaultDir)
	}
}

// An abstract name is in the same table with the '@' spelling, and has no path.
func TestReadFindsARealAbstractName(t *testing.T) {
	ln, err := net.Listen("unix", "@portwhy-day7-test")
	if err != nil {
		t.Fatalf("listen abstract: %v", err)
	}
	defer func() { _ = ln.Close() }()

	table := Read(DefaultDir)
	if !table.Bound() {
		t.Fatalf("reading %s/unix: %v", DefaultDir, table.Err)
	}
	for _, s := range table.Sockets {
		if s.Name != "@portwhy-day7-test" {
			continue
		}
		if !s.Abstract() {
			t.Error("abstract name not reported as abstract")
		}
		return
	}
	t.Fatal("no row for the abstract listener")
}
