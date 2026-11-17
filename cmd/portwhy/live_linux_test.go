//go:build linux

package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/atop0914/portwhy/internal/procnet"
)

// waitForRowState polls the live kernel until a TCP row for port is in state.
//
// Polling rather than sleeping a guessed interval: the transition to CLOSE_WAIT or
// FIN_WAIT2 depends on the peer's ACK arriving, and a fixed sleep would either be
// slow or flaky.
func waitForRowState(t *testing.T, port uint16, state procnet.State) procnet.Socket {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var last []procnet.Socket
	for {
		last = liveRows(port)
		for _, s := range last {
			if s.State == state {
				return s
			}
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("no %v row for port %d within 3s (rows seen: %v)", state, port, last)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// liveRows returns every TCP row whose local or remote end is the port.
func liveRows(port uint16) []procnet.Socket {
	var out []procnet.Socket
	for _, tbl := range procnet.ReadAll(procnet.DefaultDir) {
		if tbl.Proto != procnet.TCP {
			continue
		}
		for _, s := range tbl.Sockets {
			if s.Local.Port == port || s.Remote.Port == port {
				out = append(out, s)
			}
		}
	}
	return out
}

// A real CLOSE_WAIT: the peer closed and we never did. The port is still bound by
// that socket, and the report must say so — naming the state, and saying that
// whether it blocks a bind depends on socket options rather than guessing.
func TestWhyReportsRealCloseWait(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	target := fmt.Sprintf("127.0.0.1:%d", port)

	client, err := net.Dial("tcp", target)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	srv, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	// Drop the listener so the port is held by the connection alone: with a
	// LISTEN row present the answer would be "listening" and this state would
	// never be exercised.
	if err := ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("close client: %v", err)
	}
	defer srv.Close()

	waitForRowState(t, port, procnet.StateCloseWait)

	code, out, errb := runCLI(t, "why", target)
	if code != exitTaken {
		t.Fatalf("exit = %d, want %d (stderr: %s, stdout: %s)", code, exitTaken, errb, out)
	}
	if !strings.Contains(out, "CLOSE_WAIT") {
		t.Errorf("report does not name the state it saw:\n%s", out)
	}
	if !strings.Contains(out, "depends on socket options") {
		t.Errorf("report claims an outcome it did not verify:\n%s", out)
	}
	// The socket has an owner here: this very process. A report that left the
	// holder blank would be dropping evidence it had.
	if !strings.Contains(out, fmt.Sprintf("pid %d", os.Getpid())) {
		t.Errorf("holder %d not named for a socket this very process still holds:\n%s", os.Getpid(), out)
	}
}

// A real FIN_WAIT2: we closed first and the peer has not. The descriptor is gone,
// so the kernel reports inode 0 — which means no process can be named, and the
// report has to say that rather than leave an empty column.
func TestWhyReportsRealFinWait2(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	target := fmt.Sprintf("127.0.0.1:%d", port)

	client, err := net.Dial("tcp", target)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	srv, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if err := ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	// Only our end closes, so our end parks in FIN_WAIT2 with the port bound.
	if err := srv.Close(); err != nil {
		t.Fatalf("close server conn: %v", err)
	}

	row := waitForRowState(t, port, procnet.StateFinWait2)
	if row.Inode != 0 {
		t.Errorf("inode = %d, want 0: a socket with no descriptor left cannot be named", row.Inode)
	}

	code, out, errb := runCLI(t, "why", target)
	if code != exitTaken {
		t.Fatalf("exit = %d, want %d (stderr: %s, stdout: %s)", code, exitTaken, errb, out)
	}
	if !strings.Contains(out, "FIN_WAIT2") {
		t.Errorf("report does not name the state it saw:\n%s", out)
	}
	if !strings.Contains(out, "no open descriptor") {
		t.Errorf("report does not explain why no holder is named:\n%s", out)
	}
	if !strings.Contains(out, "no process can be named") {
		t.Errorf("report leaves the reader to guess why the owner is missing:\n%s", out)
	}
}

// The blind spot, proved rather than remembered: a socket that was bound and never
// listened holds the port (a second bind fails), and /proc/net/tcp has no row for
// it. This is why a "free" answer must carry its caveat, and the test fails if the
// kernel ever starts listing them — at which point the caveat can go.
func TestBindWithoutListenHoldsThePortButHasNoRow(t *testing.T) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	defer func() { _ = syscall.Close(fd) }()
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	name, err := syscall.Getsockname(fd)
	if err != nil {
		t.Fatalf("getsockname: %v", err)
	}
	port := uint16(name.(*syscall.SockaddrInet4).Port)

	// Premise check: the port really is held. Without this the test would pass on
	// a machine where the bind meant nothing.
	second, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	defer func() { _ = syscall.Close(second) }()
	if err := syscall.Bind(second, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}, Port: int(port)}); err == nil {
		t.Fatalf("a second bind on port %d succeeded; the port is not held, so nothing is being proved", port)
	}

	for _, s := range liveRows(port) {
		if s.Local.Port == port {
			t.Fatalf("the kernel now lists bound-but-not-listening sockets (row: %v); "+
				"the bind-without-listen caveat can be removed", s)
		}
	}

	code, out, errb := runCLI(t, "why", fmt.Sprintf("127.0.0.1:%d", port))
	if code != exitFree {
		t.Fatalf("exit = %d, want %d (stderr: %s, stdout: %s)", code, exitFree, errb, out)
	}
	if !strings.Contains(out, "bound without listen()") {
		t.Errorf("free answer does not disclose the blind spot it just fell into:\n%s", out)
	}
}
