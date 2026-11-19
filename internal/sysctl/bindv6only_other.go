//go:build !linux

package sysctl

import (
	"errors"
	"path/filepath"
	"runtime"
)

// ErrUnsupported is returned on every non-Linux platform.
//
// The alternative — reporting the value 0, which is what Linux usually has —
// would let this tool claim a [::] listener occupies IPv4 on a machine it never
// looked at. A missing measurement is the honest answer; a default is not.
var ErrUnsupported = errors.New("sysctl: net.ipv6.bindv6only is a Linux tunable")

// ReadBindV6Only refuses, explicitly, and carries the platform in the reason so
// the report can say which build it was.
func ReadBindV6Only(dir string) BindV6Only {
	return BindV6Only{
		Path: filepath.Join(dir, bindV6OnlyRel),
		Err:  ErrUnsupported.Error() + " (this build runs on " + runtime.GOOS + ")",
	}
}
