//go:build linux

package procnet

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestReadAllSeesARealListener is the assertion that this parser is not merely
// consistent with its own fixture: a socket we just opened must appear in the
// kernel's table, at the address we asked for, in the state we expect.
func TestReadAllSeesARealListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	found := findSocket(t, DefaultDir, "tcp", func(s Socket) bool {
		return s.Local.Port == port && s.State == StateListen
	})
	if found == nil {
		t.Fatalf("listener on 127.0.0.1:%d is not in /proc/net/tcp", port)
	}
	if want := netip.MustParseAddr("127.0.0.1"); found.Local.IP != want {
		t.Errorf("local ip = %v, want %v", found.Local.IP, want)
	}
	if !found.Local.IP.Is4() {
		t.Errorf("local ip family = %v, want ipv4", found.Local.IP)
	}
	// Only a socket with an open file descriptor has an inode; this one must.
	if found.Inode == 0 {
		t.Error("listening socket has inode 0, so no holder could ever be named")
	}
}

// TestTimeWaitIsRealAndOwnerless pins the fact that makes naive port tools
// wrong: after a connection closes, the port stays reserved by a TIME_WAIT row
// that has inode 0. There is a reservation and there is no owner, and both
// halves of that sentence matter.
func TestTimeWaitIsRealAndOwnerless(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	served := make(chan struct{})
	go func() {
		defer close(served)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		// The server closes first, which is what puts *its* port in TIME_WAIT.
		_, _ = c.Write([]byte("x"))
		_ = c.Close()
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := c.Read(make([]byte, 1)); err != nil {
		t.Fatalf("read: %v", err)
	}
	<-served
	_ = c.Close()
	_ = ln.Close()

	deadline := time.Now().Add(3 * time.Second)
	for {
		tw := findSocket(t, DefaultDir, "tcp", func(s Socket) bool {
			return s.Local.Port == port && s.State == StateTimeWait
		})
		if tw != nil {
			if tw.Inode != 0 {
				t.Errorf("TIME_WAIT inode = %d, want 0 : a TIME_WAIT socket cannot name an owner", tw.Inode)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("port %d never entered TIME_WAIT; the test premise (server closes first) did not hold", port)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestReadAllReportsMissingTables checks the difference between "the kernel has
// no such table" and "the table is empty". Conflating them is how a tool ends up
// reporting a free port on a machine where it simply could not look.
func TestReadAllReportsMissingTables(t *testing.T) {
	for _, tb := range ReadAll(t.TempDir()) {
		if tb.Err == nil {
			t.Errorf("table %s: err = nil, want ErrTableMissing", tb.Name)
			continue
		}
		if !errors.Is(tb.Err, ErrTableMissing) {
			t.Errorf("table %s: err = %v, want ErrTableMissing", tb.Name, tb.Err)
		}
		if len(tb.Sockets) != 0 {
			t.Errorf("table %s: got %d sockets for an unreadable table", tb.Name, len(tb.Sockets))
		}
	}
}

func TestReadAllHeaderOnlyTableIsEmptyAndNotAnError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "tcp"), []byte(headerTCP+"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	var tcp *Table
	for _, tb := range ReadAll(dir) {
		if tb.Name == "tcp" {
			tb := tb
			tcp = &tb
		}
	}
	if tcp == nil {
		t.Fatal("no tcp table in ReadAll output")
	}
	if tcp.Err != nil {
		t.Fatalf("err = %v, want nil for a header-only table", tcp.Err)
	}
	if len(tcp.Sockets) != 0 {
		t.Fatalf("got %d sockets, want 0", len(tcp.Sockets))
	}
}

func findSocket(t *testing.T, dir, table string, match func(Socket) bool) *Socket {
	t.Helper()
	for _, tb := range ReadAll(dir) {
		if tb.Name != table {
			continue
		}
		if tb.Err != nil {
			t.Fatalf("table %s: %v", table, tb.Err)
		}
		for i := range tb.Sockets {
			if match(tb.Sockets[i]) {
				s := tb.Sockets[i]
				return &s
			}
		}
	}
	return nil
}
