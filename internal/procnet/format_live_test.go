//go:build linux

package procnet

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The kernel writes the column; FormatAddr has to spell it the same way. This
// comparison uses the kernel as the oracle rather than a table written by
// somebody who read the same man page: the address comes from the socket the
// test just opened, and the expected text is whatever /proc actually contains.
func TestFormatAddrMatchesTheKernel(t *testing.T) {
	t.Run("ipv4 listener", func(t *testing.T) {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer ln.Close()
		addr := ln.Addr().(*net.TCPAddr).AddrPort()
		compareWithKernel(t, "tcp", V4, addr)
	})

	t.Run("ipv6 listener", func(t *testing.T) {
		ln, err := net.Listen("tcp6", "[::1]:0")
		if err != nil {
			t.Skipf("no IPv6 on this host: %v", err)
		}
		defer ln.Close()
		addr := ln.Addr().(*net.TCPAddr).AddrPort()
		compareWithKernel(t, "tcp6", V6, addr)
	})

	// A v4 connection accepted on a v6 wildcard socket is spelled in tcp6 as
	// ::ffff:127.0.0.1. That row is the reason address comparison has to Unmap,
	// and FormatAddr has to be able to write it back. The network is "tcp", not
	// "tcp6": Go sets IPV6_V6ONLY=1 for the latter, so it would refuse the v4
	// connection before the table ever had a mapped row in it.
	t.Run("ipv4-mapped peer in tcp6", func(t *testing.T) {
		ln, err := net.Listen("tcp", "[::]:0")
		if err != nil {
			t.Skipf("no IPv6 on this host: %v", err)
		}
		defer ln.Close()
		port := ln.Addr().(*net.TCPAddr).Port

		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			// Hold the connection open until the test is done reading the table.
			var b [1]byte
			_, _ = c.Read(b[:])
		}()

		client, err := net.Dial("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer client.Close()

		// The client's socket lives in tcp, spelled as plain IPv4.
		compareWithKernel(t, "tcp", V4, client.LocalAddr().(*net.TCPAddr).AddrPort())

		// The server side of that connection lives in tcp6, spelled as a mapped
		// address: the same 127.0.0.1 the client used, plus ffff in the third word.
		accepted := netip.AddrPortFrom(
			netip.AddrFrom16([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff,
				127, 0, 0, 1}),
			uint16(port))
		compareWithKernel(t, "tcp6", V6, accepted)
	})
}

// compareWithKernel finds the row for addr's port in table and asserts that the
// kernel's local_address field is exactly what FormatAddr produces.
func compareWithKernel(t *testing.T, table string, family Family, addr netip.AddrPort) {
	t.Helper()
	socks, err := Parse(table, TCP, family, mustOpen(t, table))
	if err != nil {
		t.Fatalf("parse %s: %v", table, err)
	}

	var mine *Socket
	for i := range socks {
		s := socks[i]
		if s.Local.Port == addr.Port() && s.Local.IP == addr.Addr() {
			mine = &socks[i]
			break
		}
	}
	if mine == nil {
		t.Fatalf("%v is not in /proc/net/%s", addr, table)
	}

	want, err := FormatAddr(mine.Local)
	if err != nil {
		t.Fatalf("FormatAddr(%v): %v", mine.Local, err)
	}
	raw := rawLocalField(t, table, mine.Inode)
	if raw != want {
		t.Fatalf("kernel spells %v as %q in %s, FormatAddr says %q", mine.Local, raw, table, want)
	}
}

func mustOpen(t *testing.T, table string) *os.File {
	t.Helper()
	f, err := os.Open(filepath.Join(DefaultDir, table))
	if err != nil {
		t.Fatalf("open %s: %v", table, err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// rawLocalField returns the untouched local_address column of the row carrying
// inode, so the comparison is against the kernel's bytes and not a re-encoding.
func rawLocalField(t *testing.T, table string, inode uint64) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(DefaultDir, table))
	if err != nil {
		t.Fatalf("read %s: %v", table, err)
	}
	want := fmt.Sprintf("%d", inode)
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) > fieldInode && f[fieldInode] == want {
			return f[fieldLocal]
		}
	}
	t.Fatalf("no row with inode %d in %s", inode, table)
	return ""
}
