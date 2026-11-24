//go:build !linux

package probe

import (
	"errors"
	"runtime"
	"time"

	"net/netip"
)

// ErrUnsupported is returned on every non-Linux platform.
//
// The alternative — pretending the bind would have succeeded — would turn this
// package into the one thing it must not be: a source of confident answers
// about a machine it cannot question. A caller that ignores the error gets
// OutcomeNotRun, which every consumer treats as "not evidence".
var ErrUnsupported = errors.New("probe: bind probes are only implemented on Linux")

// Bind refuses, explicitly. See ErrUnsupported.
func Bind(ap netip.AddrPort, mode Mode) Attempt {
	return Attempt{
		Mode:    mode,
		At:      time.Now().UTC(),
		Outcome: OutcomeNotRun,
		Err:     errors.Join(ErrUnsupported, errors.New(runtime.GOOS)).Error(),
	}
}

// Both refuses both attempts for the same reason.
func Both(ap netip.AddrPort) []Attempt {
	return []Attempt{Bind(ap, ModePlain), Bind(ap, ModeReuseAddr)}
}

// BindUDP refuses for the same reason. A platform without this probe must say
// so; a caller that ignores it gets OutcomeNotRun, which is not evidence.
func BindUDP(ap netip.AddrPort) Attempt {
	return Attempt{
		Mode:    ModePlain,
		At:      time.Now().UTC(),
		Outcome: OutcomeNotRun,
		Err:     errors.Join(ErrUnsupported, errors.New(runtime.GOOS)).Error(),
	}
}
