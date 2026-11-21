//go:build linux

package sysctl

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// ReadPrivilegedPortStart reads net.ipv4.ip_unprivileged_port_start from dir
// (usually /proc/sys).
//
// A missing file is its own state, not a failed read: kernels before 4.11 do not
// publish the tunable, and "this kernel has no such knob" is a different
// sentence from "the file was there and I could not read it". Neither may be
// answered with 1024.
func ReadPrivilegedPortStart(dir string) PrivilegedPortStart {
	path := filepath.Join(dir, privilegedPortStartRel)
	p := PrivilegedPortStart{Path: path}

	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			p.State = PrivilegedStartAbsent
			return p
		}
		p.Err = err.Error()
		return p
	}
	p.Raw = string(raw)

	port, err := parsePortStart(p.Raw)
	if err != nil {
		p.Err = err.Error()
		return p
	}
	p.Port, p.State = port, PrivilegedStartMeasured
	return p
}
