// Command mktables writes kernel socket table fixtures for the README rehearsal.
//
// Every address goes through procnet.FormatAddr, which is the encoder the parser
// is paired with. That is not tidiness: a hand-copied hex address is how a
// fixture ends up unparsable, and an unparsable fixture buys a green test and no
// coverage (this repository spent eight days on exactly that).
//
// The rows are declarations, not captures — the rehearsal wants a port to be
// listening, not the machine's actual state — so the caller says what each table
// should claim:
//
//	mktables -dir /tmp/t \
//	  -tcp 127.0.0.1:8080=0A -tcp 127.0.0.1:44433=06 \
//	  -udp 127.0.0.1:53535=07 -tcp6 "[::]:18080=0A" \
//	  -unix @demo=listen
//
// Tables with no rows are still written, with their header and nothing else: a
// missing table means "this kernel does not expose it" and would turn every
// answer into unknown, which is a different test.
package main

import (
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/atop0914/portwhy/internal/procnet"
)

// The column names are the kernel's, copied from a real capture. They are not
// hex addresses, so copying them cannot hide a byte-order mistake.
const (
	headerV4   = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode`
	headerV6   = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode`
	headerUnix = `Num       RefCount Protocol Flags    Type St Inode Path`
)

// rowList collects repeated flags for one table.
type rowList struct {
	name string
	rows []string
}

func (r *rowList) String() string { return strings.Join(r.rows, ",") }

func (r *rowList) Set(v string) error {
	r.rows = append(r.rows, v)
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "mktables: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	dir := flag.String("dir", "", "directory to write the tables into")
	tcp := &rowList{name: "tcp"}
	tcp6 := &rowList{name: "tcp6"}
	udp := &rowList{name: "udp"}
	udp6 := &rowList{name: "udp6"}
	unix := &rowList{name: "unix"}
	flag.Var(tcp, "tcp", "addr=state (e.g. 127.0.0.1:8080=0A)")
	flag.Var(tcp6, "tcp6", "addr=state")
	flag.Var(udp, "udp", "addr=state")
	flag.Var(udp6, "udp6", "addr=state")
	flag.Var(unix, "unix", "name=listen|bound (e.g. @demo=listen)")
	flag.Parse()

	if *dir == "" {
		return fmt.Errorf("-dir is required")
	}
	if err := os.MkdirAll(*dir, 0o755); err != nil {
		return err
	}

	for _, t := range []*rowList{tcp, tcp6, udp, udp6} {
		header := headerV4
		if strings.HasSuffix(t.name, "6") {
			header = headerV6
		}
		body := header + "\n"
		for _, spec := range t.rows {
			line, err := socketRow(spec, t.name)
			if err != nil {
				return fmt.Errorf("-%s %s: %w", t.name, spec, err)
			}
			body += line + "\n"
		}
		if err := os.WriteFile(filepath.Join(*dir, t.name), []byte(body), 0o644); err != nil {
			return err
		}
	}

	body := headerUnix + "\n"
	for _, spec := range unix.rows {
		line, err := unixRow(spec)
		if err != nil {
			return fmt.Errorf("-unix %s: %w", spec, err)
		}
		body += line + "\n"
	}
	return os.WriteFile(filepath.Join(*dir, "unix"), []byte(body), 0o644)
}

// socketRow renders one /proc/net/{tcp,udp} row: "addr=state", where state is the
// hex code the kernel prints (0A listening, 06 TIME_WAIT, 07 the code that means
// "unhashed" in TCP and "bound, not connected" in UDP).
//
// The peer column is spelled by width: 8 hex digits in a v4 table, 32 in a v6 one.
// A v6 row with a v4-width peer is the mistake that kept one fixture unreadable
// for eight days here — the parser rejects the row, the table reports an error,
// and every assertion downstream compares unknown with unknown.
func socketRow(spec, table string) (string, error) {
	addrPart, statePart, ok := strings.Cut(spec, "=")
	if !ok {
		return "", fmt.Errorf("want addr=state, got %q", spec)
	}
	ap, err := netip.ParseAddrPort(addrPart)
	if err != nil {
		return "", fmt.Errorf("address: %w", err)
	}
	local, err := procnet.FormatAddr(procnet.Addr{IP: ap.Addr(), Port: ap.Port()})
	if err != nil {
		return "", err
	}
	if strings.HasSuffix(table, "6") != ap.Addr().Is6() {
		return "", fmt.Errorf("%s row on %s: the address family does not match the table", ap.Addr(), table)
	}
	state := strings.ToUpper(strings.TrimSpace(statePart))
	if len(state) != 2 {
		return "", fmt.Errorf("state %q is not two hex digits", statePart)
	}
	peer := "00000000:0000"
	if strings.HasSuffix(table, "6") {
		peer = strings.Repeat("0", 32) + ":0000"
	}
	// The inode is derived from the port so that two fixtures on one port collide
	// loudly instead of sharing a holder by accident.
	inode := 4000000 + int(ap.Port())
	return fmt.Sprintf("   0: %s %s %s 00000000:00000000 00:00000000 00000000"+
		"     0        0 %d 1 0000000000000000 100 0 0 10 0", local, peer, state, inode), nil
}

// unixRow renders one /proc/net/unix row. "listen" sets SO_ACCEPTCON (flags
// 0x00010000), which is the only column that distinguishes a listening unix
// socket: the state column is the socket type, not a state.
func unixRow(spec string) (string, error) {
	name, kind, ok := strings.Cut(spec, "=")
	if !ok {
		return "", fmt.Errorf("want name=listen|bound, got %q", spec)
	}
	var flags string
	switch kind {
	case "listen":
		flags = "00010000"
	case "bound":
		flags = "00000000"
	default:
		return "", fmt.Errorf("kind %q is not listen or bound", kind)
	}
	// The inode only has to be stable within one fixture set.
	return fmt.Sprintf("0000000000000000: 00000002 00000000 %s 0001 01 4700000 %s", flags, name), nil
}
