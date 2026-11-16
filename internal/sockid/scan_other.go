//go:build !linux

package sockid

import (
	"errors"
	"fmt"
	"runtime"
)

// ErrUnsupported is returned wherever /proc does not exist. Reporting an empty
// index instead would be read by every caller as "no process holds this port".
var ErrUnsupported = errors.New("sockid: process descriptors are only enumerable on Linux")

// Scan always fails off Linux, and says why.
func Scan(root string) (*Index, error) {
	return nil, fmt.Errorf("%w (host is %s)", ErrUnsupported, runtime.GOOS)
}
