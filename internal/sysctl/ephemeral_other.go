//go:build !linux

package sysctl

import (
	"errors"
	"path/filepath"
	"runtime"
)

// ErrPortRangeUnsupported is returned on every non-Linux platform.
//
// The alternative — reporting the range Linux usually has — would let the tool
// tell a macOS user that their port sits in a kernel pool that does not exist
// there. An explicit refusal is the only honest answer.
var ErrPortRangeUnsupported = errors.New("sysctl: net.ipv4.ip_local_port_range is a Linux tunable")

// ErrReservedPortsUnsupported is the same refusal for the reservation list.
var ErrReservedPortsUnsupported = errors.New("sysctl: net.ipv4.ip_local_reserved_ports is a Linux tunable")

// ReadPortRange refuses, with the platform in the reason.
func ReadPortRange(dir string) PortRange {
	return PortRange{
		Path: filepath.Join(dir, portRangeRel),
		Err:  ErrPortRangeUnsupported.Error() + " (this build runs on " + runtime.GOOS + ")",
	}
}

// ReadReservedPorts refuses, with the platform in the reason. It is not reported
// as Absent: a missing tunable would let a reader conclude the kernel has the
// feature and nothing is reserved.
func ReadReservedPorts(dir string) ReservedPorts {
	return ReservedPorts{
		Path: filepath.Join(dir, reservedPortsRel),
		Err:  ErrReservedPortsUnsupported.Error() + " (this build runs on " + runtime.GOOS + ")",
	}
}
