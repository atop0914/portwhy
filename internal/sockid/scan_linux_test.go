//go:build linux

package sockid

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
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

// A forked worker inherits its parent's listener, so one inode has two holders.
// Reporting only one of them sends the user to kill the wrong process: the child
// dies and the port stays taken, because the parent still owns the socket.
func TestScanFindsBothTheParentAndTheInheritedChild(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

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

	// The child inherits the descriptor as fd 3 and holds it without ever
	// touching it. That is exactly what a preforking worker does.
	cmd := exec.Command("sleep", "30")
	cmd.ExtraFiles = []*os.File{f}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	var holders []Holder
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		idx, err := Scan(DefaultRoot)
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		holders = idx.Holders(ino)
		if len(holders) >= 2 {
			if idx.PPID[cmd.Process.Pid] != os.Getpid() {
				t.Fatalf("PPID of the child = %d, want %d (the process tree is the only evidence of who forked whom)",
					idx.PPID[cmd.Process.Pid], os.Getpid())
			}
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if len(holders) < 2 {
		t.Fatalf("inode %d reported %d holder(s) %v, want both this process and the child %d",
			ino, len(holders), holders, cmd.Process.Pid)
	}
	seen := make(map[int]bool, len(holders))
	for i, h := range holders {
		seen[h.PID] = true
		if i > 0 && holders[i-1].PID > h.PID {
			t.Errorf("holders are not in pid order: %v", holders)
		}
	}
	if !seen[os.Getpid()] || !seen[cmd.Process.Pid] {
		t.Errorf("holders = %v, want pid %d and pid %d", holders, os.Getpid(), cmd.Process.Pid)
	}
}

// Names sort as strings in a directory listing, so pid 100 comes before pid 50.
// The report must not inherit that: pid order is what a reader acts on.
func TestScanSortsHoldersByPidAndRecordsTheParent(t *testing.T) {
	root := t.TempDir()
	mkdir(t, root, "100", "fd")
	write(t, filepath.Join(root, "100", "comm"), "child\n")
	// The command name genuinely contains parentheses and spaces here.
	write(t, filepath.Join(root, "100", "stat"), "100 (my app (v2)) S 50 100 100 0 -1 4194560 1 0 0 0\n")
	link(t, filepath.Join(root, "100", "fd", "3"), "socket:[9001]")

	mkdir(t, root, "50", "fd")
	write(t, filepath.Join(root, "50", "comm"), "parent\n")
	write(t, filepath.Join(root, "50", "stat"), "50 (parent) S 1 50 50 0 -1 4194560 1 0 0 0\n")
	link(t, filepath.Join(root, "50", "fd", "4"), "socket:[9001]")

	idx, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	holders := idx.Holders(9001)
	if len(holders) != 2 {
		t.Fatalf("holders = %v, want two", holders)
	}
	if holders[0].PID != 50 || holders[1].PID != 100 {
		t.Errorf("order = %d,%d, want 50,100 (pid order, not name order)", holders[0].PID, holders[1].PID)
	}
	if idx.PPID[100] != 50 {
		t.Errorf("PPID[100] = %d, want 50", idx.PPID[100])
	}
}

func TestReadPPIDHandlesParenthesesInTheCommandName(t *testing.T) {
	root := t.TempDir()
	mkdir(t, root, "7")
	write(t, filepath.Join(root, "7", "stat"), "7 (my app (v2)) S 42 7 7 0 -1 4194560 1 0 0 0\n")

	got, ok := readPPID(root, 7)
	if !ok {
		t.Fatal("readPPID found no parent in a well-formed stat line")
	}
	if got != 42 {
		t.Errorf("ppid = %d, want 42 (fields must be counted from the last ')')", got)
	}

	if _, ok := readPPID(root, 8); ok {
		t.Error("readPPID invented a parent for a process with no stat file")
	}
	mkdir(t, root, "9")
	write(t, filepath.Join(root, "9", "stat"), "9 (broken)\n")
	if _, ok := readPPID(root, 9); ok {
		t.Error("readPPID invented a parent for a truncated stat line")
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
