//go:build !linux

package sysctl

import (
	"path/filepath"
	"runtime"
)

// ReadPrivilegedPortStart refuses on every non-Linux platform.
//
// The alternative — reporting 1024, which is the traditional boundary — would
// let this tool state a capability rule for a machine it never looked at. It is
// the same refusal the other tunables make, for the same reason.
func ReadPrivilegedPortStart(dir string) PrivilegedPortStart {
	return PrivilegedPortStart{
		Path: filepath.Join(dir, privilegedPortStartRel),
		Err:  "net.ipv4.ip_unprivileged_port_start is a Linux tunable (this build runs on " + runtime.GOOS + ")",
	}
}
