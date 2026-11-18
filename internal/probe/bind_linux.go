//go:build linux

package probe

import (
	"errors"
	"fmt"
	"net/netip"
	"syscall"
	"time"
)

// Bind asks the kernel for one address, once.
//
// The socket is created, the option (if any) is set, bind() is called, and the
// descriptor is closed. listen() is never called: a bound socket that never
// listens accepts nothing, so the probe cannot alter the traffic of a service
// it is asked about. The window in which this process holds the address is one
// syscall long.
func Bind(ap netip.AddrPort, mode Mode) Attempt {
	res := Attempt{Mode: mode, At: time.Now().UTC()}

	switch mode {
	case ModePlain, ModeReuseAddr:
	default:
		res.Outcome = OutcomeNotRun
		res.Err = fmt.Sprintf("unknown probe mode %q", string(mode))
		return res
	}

	sa, family, err := sockaddr(ap)
	if err != nil {
		res.Outcome = OutcomeNotRun
		res.Err = err.Error()
		return res
	}

	fd, err := syscall.Socket(family, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, syscall.IPPROTO_TCP)
	if err != nil {
		res.Outcome = OutcomeNotRun
		res.Err = "socket: " + err.Error()
		return res
	}

	if mode == ModeReuseAddr {
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
			_ = syscall.Close(fd)
			res.Outcome = OutcomeNotRun
			res.Err = "setsockopt SO_REUSEADDR: " + err.Error()
			return res
		}
	}

	bindErr := syscall.Bind(fd, sa)
	// The descriptor must not outlive the attempt: leaving it open would hold
	// the very address the report is about.
	closeErr := syscall.Close(fd)

	if bindErr != nil {
		var errno syscall.Errno
		if errors.As(bindErr, &errno) {
			res.Outcome = classify(errno)
			res.Errno = errnoName(errno)
			res.Message = errno.Error()
		} else {
			res.Outcome = OutcomeFailed
			res.Message = bindErr.Error()
		}
	} else {
		res.Outcome = OutcomeBound
	}
	if closeErr != nil {
		res.Err = "close: " + closeErr.Error()
	}
	return res
}

// Both makes the two attempts this version knows how to make, plain first.
//
// Two rather than one because a single attempt cannot distinguish "a process
// holds this" from "a closed connection reserves this": only the difference
// between the attempts can, and that difference is the whole point of offering
// the option.
func Both(ap netip.AddrPort) []Attempt {
	return []Attempt{Bind(ap, ModePlain), Bind(ap, ModeReuseAddr)}
}

// sockaddr expresses the target in the form bind() takes.
//
// Three inputs are refused rather than approximated: port 0 (the kernel would
// pick a free port, which answers a different question), a scoped IPv6 address
// (resolving a zone name to an index needs a dependency this project does not
// take), and an invalid address.
func sockaddr(ap netip.AddrPort) (syscall.Sockaddr, int, error) {
	ip := ap.Addr().Unmap()
	if !ip.IsValid() {
		return nil, 0, errors.New("probe: invalid address")
	}
	if ip.Zone() != "" {
		return nil, 0, fmt.Errorf("probe: scoped address %s is not supported", ip)
	}
	if ap.Port() == 0 {
		return nil, 0, errors.New("probe: port 0 asks for any free port, which says nothing about the port asked about")
	}
	if ip.Is4() {
		return &syscall.SockaddrInet4{Port: int(ap.Port()), Addr: ip.As4()}, syscall.AF_INET, nil
	}
	return &syscall.SockaddrInet6{Port: int(ap.Port()), Addr: ip.As16()}, syscall.AF_INET6, nil
}

func classify(errno syscall.Errno) Outcome {
	switch errno {
	case syscall.EADDRINUSE:
		return OutcomeAddrInUse
	case syscall.EACCES, syscall.EPERM:
		return OutcomeNotPermitted
	case syscall.EADDRNOTAVAIL:
		return OutcomeAddrNotAvailable
	}
	return OutcomeFailed
}

// errnoName spells the errno the way the manual and every search result do.
// syscall.Errno.Error() gives the sentence ("address already in use"), which is
// right for a human and useless for a grep.
func errnoName(errno syscall.Errno) string {
	switch errno {
	case syscall.EADDRINUSE:
		return "EADDRINUSE"
	case syscall.EACCES:
		return "EACCES"
	case syscall.EPERM:
		return "EPERM"
	case syscall.EADDRNOTAVAIL:
		return "EADDRNOTAVAIL"
	case syscall.EINVAL:
		return "EINVAL"
	case syscall.EAFNOSUPPORT:
		return "EAFNOSUPPORT"
	case syscall.ENODEV:
		return "ENODEV"
	case syscall.EMFILE:
		return "EMFILE"
	case syscall.ENFILE:
		return "ENFILE"
	case syscall.ENOMEM:
		return "ENOMEM"
	}
	return fmt.Sprintf("errno(%d)", int(errno))
}
