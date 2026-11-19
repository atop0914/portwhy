// Package sysctl reads the kernel tunables this tool needs.
//
// It exists as its own package for one reason: the value it reads decides an
// answer, and a value that could not be read must never be replaced by the
// value Linux usually has. A default is not a measurement, and this project's
// value rests on the difference.
//
// The only tunable here today is net.ipv6.bindv6only: whether a socket created
// for IPv6 also serves IPv4. It is a property of the machine, not of a socket,
// which is exactly why /proc/net cannot answer it.
package sysctl

import (
	"fmt"
	"strings"
)

// DefaultDir is where Linux keeps its tunables.
const DefaultDir = "/proc/sys"

// bindV6OnlyRel is the tunable, relative to DefaultDir.
const bindV6OnlyRel = "net/ipv6/bindv6only"

// BindV6OnlyState is the measured value of net.ipv6.bindv6only.
//
// The zero value is "nobody asked", not "0". A zero value that claimed
// dual-stack would turn every caller that forgot to measure into a confident
// report that a [::] listener is shadowing IPv4.
type BindV6OnlyState uint8

const (
	// BindV6OnlyUnmeasured means no value was obtained: either the caller never
	// asked, or the read failed (see BindV6Only.Err for which).
	BindV6OnlyUnmeasured BindV6OnlyState = iota
	// BindV6OnlyDualStack is the value 0. A socket created for IPv6 accepts
	// IPv4-mapped addresses, so a wildcard [::] listener also holds the IPv4
	// wildcard — unless that particular socket set IPV6_V6ONLY for itself.
	BindV6OnlyDualStack
	// BindV6OnlyIPv6Only is the value 1. [::] is IPv6 only; an IPv4 address on
	// the same port is untouched.
	BindV6OnlyIPv6Only
)

// BindV6Only is one reading of the tunable, with the evidence for it.
type BindV6Only struct {
	State BindV6OnlyState
	// Raw is the file's text, trimmed, exactly as the kernel printed it.
	Raw string
	// Path is the file this came from, so a report can cite it instead of
	// asking the reader to trust it.
	Path string
	// Err is why no value was obtained. Non-empty means State is Unmeasured.
	Err string
}

// Known reports whether a value was really read.
func (b BindV6Only) Known() bool {
	return b.Err == "" && b.State != BindV6OnlyUnmeasured
}

// DualStack reports whether the measured value is 0, the setting under which a
// [::] wildcard also occupies IPv4.
func (b BindV6Only) DualStack() bool {
	return b.Known() && b.State == BindV6OnlyDualStack
}

// Value returns the number the kernel printed, and false when nothing was
// measured. It is the number a report prints when it says "measured".
func (b BindV6Only) Value() (int, bool) {
	switch b.State {
	case BindV6OnlyDualStack:
		return 0, b.Known()
	case BindV6OnlyIPv6Only:
		return 1, b.Known()
	}
	return 0, false
}

// String is the one-line form used in reports: the value when it was measured,
// the reason when it was not.
func (b BindV6Only) String() string {
	if v, ok := b.Value(); ok {
		return fmt.Sprintf("%d", v)
	}
	if b.Err != "" {
		return "unreadable (" + b.Err + ")"
	}
	return "not measured"
}

// Describe is the sentence a report cites: value and source, or the reason
// there is no value. Both halves matter — a number without a source is a claim,
// and a missing number without a reason is a shrug.
func (b BindV6Only) Describe() string {
	if v, ok := b.Value(); ok {
		return fmt.Sprintf("net.ipv6.bindv6only = %d, read from %s", v, b.Path)
	}
	if b.Err != "" {
		return fmt.Sprintf("net.ipv6.bindv6only is unreadable (%s): %s", b.Path, b.Err)
	}
	return "net.ipv6.bindv6only was not measured"
}

// parse turns the file's text into a state. Only "0" and "1" are values: the
// kernel prints nothing else, so anything else means we are not reading what we
// think we are, and guessing would be the one thing this package must not do.
func parse(raw string) (BindV6OnlyState, error) {
	switch strings.TrimSpace(raw) {
	case "0":
		return BindV6OnlyDualStack, nil
	case "1":
		return BindV6OnlyIPv6Only, nil
	}
	return BindV6OnlyUnmeasured, fmt.Errorf("%q is not 0 or 1", strings.TrimSpace(raw))
}
