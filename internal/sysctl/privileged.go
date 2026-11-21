package sysctl

import (
	"fmt"
	"strconv"
	"strings"
)

// privilegedPortStartRel is the tunable that decides which ports a bind() may
// use without CAP_NET_BIND_SERVICE. It exists so that this tool does not have to
// write 1024 into a sentence: 1024 is the traditional value, and a report that
// states a tradition as a measurement is the failure mode this project is built
// to avoid. On a host with net.ipv4.ip_unprivileged_port_start = 0 there is no
// privileged port at all, and a tool that guessed would warn about port 80 on
// every container.
const privilegedPortStartRel = "net/ipv4/ip_unprivileged_port_start"

// PrivilegedStartState says whether the boundary was really read.
//
// Three states, because they lead to three different sentences: a measured
// value can be compared against the queried port, a missing file means the
// kernel does not offer the tunable (Linux before 4.11), and a file that could
// not be read or understood is a hole. None of them may be answered with 1024.
type PrivilegedStartState uint8

const (
	// PrivilegedStartUnmeasured is the zero value: nobody asked, or the read or
	// parse failed (see PrivilegedPortStart.Err for which).
	PrivilegedStartUnmeasured PrivilegedStartState = iota
	// PrivilegedStartMeasured means the file held one port number.
	PrivilegedStartMeasured
	// PrivilegedStartAbsent means the tunable file is not there: a kernel
	// without it, or a directory handed in with -sysctl that is not procfs.
	PrivilegedStartAbsent
)

// PrivilegedPortStart is one reading of net.ipv4.ip_unprivileged_port_start:
// the lowest port a non-root process may bind.
type PrivilegedPortStart struct {
	State PrivilegedStartState
	// Port is only meaningful when State is PrivilegedStartMeasured.
	Port uint16
	// Raw is the file's text exactly as the kernel printed it.
	Raw string
	// Path is the file this came from, so a report can cite it.
	Path string
	// Err is why no value was obtained; non-empty means State is Unmeasured.
	Err string
}

// Known reports whether a value was really read.
func (p PrivilegedPortStart) Known() bool {
	return p.State == PrivilegedStartMeasured && p.Err == ""
}

// Absent reports whether the tunable file was missing, which is a different
// sentence from a failed read and must stay one.
func (p PrivilegedPortStart) Absent() bool {
	return p.State == PrivilegedStartAbsent && p.Err == ""
}

// NeedsRoot reports whether binding port requires capability on this host,
// according to the measured boundary.
//
// Port 0 is excluded on purpose: it is not a port the user named, it is "pick
// one for me", and the kernel picks from the ephemeral range where no
// capability is needed. An unmeasured boundary answers false — "I did not look"
// must not become "yes, this one needs root".
func (p PrivilegedPortStart) NeedsRoot(port uint16) bool {
	return p.Known() && port != 0 && port < p.Port
}

// Describe is the sentence a report cites: the value and the file it came from,
// or the reason there is no value.
func (p PrivilegedPortStart) Describe() string {
	switch {
	case p.Known():
		return fmt.Sprintf("net.ipv4.ip_unprivileged_port_start = %d, read from %s", p.Port, p.Path)
	case p.Absent():
		return fmt.Sprintf("%s does not exist, so the privileged-port boundary could not be read "+
			"(a kernel without the tunable, or a directory that is not procfs)", p.Path)
	}
	if p.Err != "" {
		return fmt.Sprintf("net.ipv4.ip_unprivileged_port_start is unreadable (%s): %s", p.Path, p.Err)
	}
	return "net.ipv4.ip_unprivileged_port_start was not measured"
}

// parsePortStart turns the file's text into a port number.
//
// Only a bare decimal number is a measurement. The kernel prints one, so
// anything else means we are not reading what we think we are reading, and a
// guess here becomes a sentence about capabilities that nobody verified.
func parsePortStart(raw string) (uint16, error) {
	text := strings.TrimSpace(raw)
	if text == "" {
		return 0, fmt.Errorf("%q is not a port number 0-65535", text)
	}
	// Fields catches the shapes ParseUint would reject anyway; the split is
	// stated so "1024 1024" reports itself as two numbers rather than as a bad
	// digit.
	if fields := strings.Fields(text); len(fields) != 1 {
		return 0, fmt.Errorf("%q is %d fields, not one port number", text, len(fields))
	}
	v, err := strconv.ParseUint(text, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("%q is not a port number 0-65535", text)
	}
	return uint16(v), nil
}
