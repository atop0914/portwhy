//go:build linux

package sysctl

import (
	"os"
	"path/filepath"
)

// ReadBindV6Only reads net.ipv6.bindv6only from dir (usually /proc/sys).
//
// Every failure is reported as an unreadable value with its reason, never as a
// fallback to 0: on this host the difference between "dual-stack" and "I could
// not look" is the difference between a confident wrong answer and an honest
// one.
func ReadBindV6Only(dir string) BindV6Only {
	path := filepath.Join(dir, bindV6OnlyRel)
	b := BindV6Only{Path: path}

	raw, err := os.ReadFile(path)
	if err != nil {
		b.Err = err.Error()
		return b
	}
	b.Raw = string(raw)

	state, err := parse(b.Raw)
	if err != nil {
		b.Err = err.Error()
		return b
	}
	b.State = state
	return b
}
