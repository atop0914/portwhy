//go:build linux

package sysctl

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// ReadPortRange reads net.ipv4.ip_local_port_range from dir (usually /proc/sys).
//
// Every failure is reported as "no range" with its reason, never as the
// interval Linux usually has: a report that says "your port is inside
// 32768-60999" on a host whose range was never read is a wrong answer wearing
// the clothes of a measured one.
func ReadPortRange(dir string) PortRange {
	path := filepath.Join(dir, portRangeRel)
	p := PortRange{Path: path}

	raw, err := os.ReadFile(path)
	if err != nil {
		p.Err = err.Error()
		return p
	}
	p.Raw = string(raw)

	low, high, err := parsePortRange(p.Raw)
	if err != nil {
		p.Err = err.Error()
		return p
	}
	p.Low, p.High, p.State = low, high, PortRangeMeasured
	return p
}

// ReadReservedPorts reads net.ipv4.ip_local_reserved_ports from dir.
//
// A missing file is its own state, not a failed read: the kernel may simply not
// offer the tunable, and that is a different sentence from "the file was there
// and I could not parse it".
func ReadReservedPorts(dir string) ReservedPorts {
	path := filepath.Join(dir, reservedPortsRel)
	r := ReservedPorts{Path: path}

	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			r.State = ReservedAbsent
			return r
		}
		r.Err = err.Error()
		return r
	}
	r.Raw = string(raw)

	intervals, err := parseReservedPorts(r.Raw)
	if err != nil {
		r.Err = err.Error()
		return r
	}
	r.Intervals, r.State = intervals, ReservedMeasured
	return r
}
