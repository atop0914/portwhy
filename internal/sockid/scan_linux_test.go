//go:build linux

package sockid

import (
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestScanFindsTheProcessHoldingARealSocket is the load-bearing test of this
// package: it opens a socket, takes its inode from the kernel, then asks the
// walker who holds that inode. The expected answer is this very test binary.
func TestScanFindsTheProcessHoldingARealSocket(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	// File() dups the descriptor; the original still owns the socket.
	f, err := ln.(*net.TCPListener).File()
	if err != nil {
		t.Fatalf("file: %v", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	ino := st.Sys().(*syscall.Stat_t).Ino

	idx, err := Scan(DefaultRoot)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if idx.ProcsRead == 0 {
		t.Fatal("walked zero processes; the fixture is not testing anything")
	}

	var found bool
	for _, h := range idx.Holders(ino) {
		if h.PID == os.Getpid() && h.FD > 2 {
			found = true
		}
	}
	if !found {
		t.Fatalf("inode %d not attributed to pid %d (holders: %v)", ino, os.Getpid(), idx.Holders(ino))
	}
}

// TestScanForgetsAClosedSocket is the reverse assertion: attribution must be
// about the present. If a closed listener kept its holder, every report would
// eventually point at processes that are not the problem.
func TestScanForgetsAClosedSocket(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f, err := ln.(*net.TCPListener).File()
	if err != nil {
		t.Fatalf("file: %v", err)
	}
	st, err := f.Stat()
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	ino := st.Sys().(*syscall.Stat_t).Ino
	_ = f.Close()
	_ = ln.Close()

	idx, err := Scan(DefaultRoot)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, h := range idx.Holders(ino) {
		if h.PID == os.Getpid() {
			t.Fatalf("closed socket inode %d still attributed to pid %d", ino, os.Getpid())
		}
	}
}

// TestScanAccountsForUnreadableEntries uses a synthetic tree so the bookkeeping
// can be checked deterministically: a real unreadable directory needs a second
// uid, which a test cannot rely on having.
func TestScanAccountsForUnreadableEntries(t *testing.T) {
	root := t.TempDir()
	mkdir(t, root, "100", "fd")
	write(t, filepath.Join(root, "100", "comm"), "faked\n")
	link(t, filepath.Join(root, "100", "fd", "3"), "socket:[111]")
	link(t, filepath.Join(root, "100", "fd", "1"), "pipe:[9]")
	// 200 has a regular file where fd should be: the walk must skip it, not
	// treat it as a process with no sockets.
	write(t, filepath.Join(root, "200"), "not a directory")
	// A non-numeric entry is not a process.
	write(t, filepath.Join(root, "loadavg"), "0.00 0.00 0.00")

	idx, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	holders := idx.Holders(111)
	if len(holders) != 1 {
		t.Fatalf("holders of 111 = %v, want exactly one", holders)
	}
	if h := holders[0]; h.PID != 100 || h.FD != 3 || h.Comm != "faked" {
		t.Errorf("holder = %+v, want pid 100 fd 3 comm faked", h)
	}
	if idx.ProcsRead != 1 {
		t.Errorf("ProcsRead = %d, want 1", idx.ProcsRead)
	}
	if idx.ProcsSkipped != 1 {
		t.Errorf("ProcsSkipped = %d, want 1", idx.ProcsSkipped)
	}
	if idx.ProcsDenied != 0 {
		t.Errorf("ProcsDenied = %d, want 0 in a synthetic tree", idx.ProcsDenied)
	}
}

func mkdir(t *testing.T, parts ...string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(parts...), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func link(t *testing.T, path, target string) {
	t.Helper()
	if err := os.Symlink(target, path); err != nil {
		t.Fatalf("symlink %s -> %s: %v", path, target, err)
	}
}
