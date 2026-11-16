//go:build !linux

package procnet

import (
	"errors"
	"runtime"
)

// ErrUnsupported is returned on every non-Linux platform.
//
// The alternative — returning an empty table — would be read by every caller as
// "nothing holds this port", which on macOS and Windows is simply false. A tool
// that cannot see must say so; this project's whole value is that its "free"
// means something.
var ErrUnsupported = errors.New("procnet: socket tables are only available on Linux")

// Spec names one table and what it contains.
type Spec struct {
	Name   string
	Proto  Proto
	Family Family
}

// Specs mirrors the Linux set so callers compile everywhere.
var Specs = []Spec{
	{Name: "tcp", Proto: TCP, Family: V4},
	{Name: "tcp6", Proto: TCP, Family: V6},
	{Name: "udp", Proto: UDP, Family: V4},
	{Name: "udp6", Proto: UDP, Family: V6},
}

// DefaultDir exists so callers do not need a build tag to name it.
const DefaultDir = "/proc/net"

// ReadAll returns one failed table per spec on platforms without /proc/net.
func ReadAll(dir string) []Table {
	out := make([]Table, 0, len(Specs))
	for _, spec := range Specs {
		out = append(out, Table{
			Name:   spec.Name,
			Proto:  spec.Proto,
			Family: spec.Family,
			Err:    errors.Join(ErrUnsupported, errors.New(runtime.GOOS)),
		})
	}
	return out
}
