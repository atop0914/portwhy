package sysctl

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// The two tunables that decide whether a port is one the kernel may hand out on
// its own. They are read for a different reason than bindv6only: not to settle
// an answer about who holds the port, but to say that this port was never a
// good place for a long-lived listener in the first place.
const (
	portRangeRel     = "net/ipv4/ip_local_port_range"
	reservedPortsRel = "net/ipv4/ip_local_reserved_ports"
)

// PortRangeState says whether the ephemeral range was really read.
//
// The zero value has to mean "not measured", because 0 is a legal port number
// and a zero-valued range of 0-0 would otherwise read as a measurement that
// every port fails. Replacements for a missing value are this package's whole
// reason for existing: 32768-60999 is what Linux usually has, and printing it
// for a host nobody looked at would be the most confidently wrong answer this
// tool can produce.
type PortRangeState uint8

const (
	// PortRangeUnmeasured means no range was obtained: either nobody asked, or
	// the read/parse failed (see PortRange.Err).
	PortRangeUnmeasured PortRangeState = iota
	// PortRangeMeasured means the file was read and held two port numbers in
	// order.
	PortRangeMeasured
)

// PortRange is one reading of net.ipv4.ip_local_port_range: the interval the
// kernel draws outbound connection source ports from.
type PortRange struct {
	State PortRangeState
	// Low and High are only meaningful when State is PortRangeMeasured.
	Low, High uint16
	// Raw is the file's text, exactly as the kernel printed it.
	Raw string
	// Path is the file this came from, so a report can cite it.
	Path string
	// Err is why no range was obtained; non-empty means State is Unmeasured.
	Err string
}

// Known reports whether a range was really read.
func (p PortRange) Known() bool {
	return p.State == PortRangeMeasured && p.Err == ""
}

// Contains reports whether the port falls inside the measured interval. An
// unmeasured range contains nothing: "I did not look" must not turn into "yes,
// it is in there".
func (p PortRange) Contains(port uint16) bool {
	return p.Known() && port >= p.Low && port <= p.High
}

// Describe is the sentence a report cites: the range and the file it came from,
// or the reason there is no range.
func (p PortRange) Describe() string {
	if p.Known() {
		return fmt.Sprintf("net.ipv4.ip_local_port_range = %d-%d, read from %s", p.Low, p.High, p.Path)
	}
	if p.Err != "" {
		return fmt.Sprintf("net.ipv4.ip_local_port_range is unreadable (%s): %s", p.Path, p.Err)
	}
	return "net.ipv4.ip_local_port_range was not measured"
}

// PortInterval is one inclusive range of ports, as ip_local_reserved_ports
// spells them.
type PortInterval struct {
	Low, High uint16
}

// String prints the interval in the kernel's own syntax.
func (i PortInterval) String() string {
	if i.Low == i.High {
		return strconv.Itoa(int(i.Low))
	}
	return fmt.Sprintf("%d-%d", i.Low, i.High)
}

// ReservedState separates the three ways the reserved-ports file can speak. They
// are not interchangeable: an empty file is a measurement ("nothing is
// reserved"), a malformed file is a failed read, and a missing file means the
// kernel does not offer the tunable at all. Folding any two of them together
// would turn "I could not look" into "nothing is reserved".
type ReservedState uint8

const (
	// ReservedUnmeasured is the zero value: nobody asked, or the read failed.
	ReservedUnmeasured ReservedState = iota
	// ReservedMeasured means the file was read. Intervals may still be empty —
	// that is the kernel saying nothing has been excluded.
	ReservedMeasured
	// ReservedAbsent means the tunable file is not there. On a real kernel that
	// is a kernel without the feature (Linux before 2.6.36); on a directory
	// handed in with -sysctl it is simply a directory without that file, which
	// is why the wording covers both and claims neither.
	ReservedAbsent
)

// ReservedPorts is one reading of net.ipv4.ip_local_reserved_ports: the ports
// carved out of the ephemeral range so the kernel never hands them out.
type ReservedPorts struct {
	State ReservedState
	// Intervals are the reserved ports, sorted and with touching ranges merged,
	// so that two runs over the same file print the same thing.
	Intervals []PortInterval
	Raw       string
	Path      string
	Err       string
}

// Known reports whether the file was read and understood. An empty file is
// known: it is the measurement "none".
func (r ReservedPorts) Known() bool {
	return r.State == ReservedMeasured && r.Err == ""
}

// Absent reports whether the tunable file was missing.
func (r ReservedPorts) Absent() bool {
	return r.State == ReservedAbsent && r.Err == ""
}

// Empty reports whether the file was read and excluded no port at all.
func (r ReservedPorts) Empty() bool {
	return r.Known() && len(r.Intervals) == 0
}

// Contains reports whether the port is reserved. Only a measurement can say
// yes; an unread or absent file says nothing about any port.
func (r ReservedPorts) Contains(port uint16) bool {
	for _, iv := range r.Intervals {
		if port >= iv.Low && port <= iv.High {
			return true
		}
	}
	return false
}

// Describe is the sentence a report cites for the reservation question.
func (r ReservedPorts) Describe() string {
	switch {
	case r.Empty():
		return fmt.Sprintf("net.ipv4.ip_local_reserved_ports is empty in %s: no port is excluded from the "+
			"ephemeral pool", r.Path)
	case r.Known():
		return fmt.Sprintf("net.ipv4.ip_local_reserved_ports = %s, read from %s",
			strings.TrimSpace(r.Raw), r.Path)
	case r.Absent():
		return fmt.Sprintf("%s does not exist, so no reservation could be read (a kernel without the "+
			"tunable, or a directory that is not procfs)", r.Path)
	}
	if r.Err != "" {
		return fmt.Sprintf("net.ipv4.ip_local_reserved_ports is unreadable (%s): %s", r.Path, r.Err)
	}
	return "net.ipv4.ip_local_reserved_ports was not measured"
}

// parsePortRange turns the file's text into an interval.
//
// Every malformed shape ends in an error rather than in a guess: two fields,
// decimal, 0..65535, low not above high. A range that half-parsed would be
// worse than none, because the answer it produces ("your port is inside
// 32768-60999") is exactly the folklore this tool is meant to replace.
func parsePortRange(raw string) (low, high uint16, err error) {
	fields := strings.Fields(raw)
	if len(fields) != 2 {
		return 0, 0, fmt.Errorf("%q is not two port numbers", strings.TrimSpace(raw))
	}
	low, err = parsePort(fields[0])
	if err != nil {
		return 0, 0, err
	}
	high, err = parsePort(fields[1])
	if err != nil {
		return 0, 0, err
	}
	if low > high {
		return 0, 0, fmt.Errorf("%q starts at %d and ends at %d", strings.TrimSpace(raw), low, high)
	}
	return low, high, nil
}

// parsePort accepts only a decimal port number. ParseUint with a 16-bit size
// rejects negatives, "0x1234", empty strings and anything above 65535 in one
// step, which is the entire validation this needs.
func parsePort(s string) (uint16, error) {
	v, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("%q is not a port number 0-65535", s)
	}
	return uint16(v), nil
}

// parseReservedPorts turns the file's text into intervals.
//
// An empty file is not an error: it is the kernel reporting that nothing is
// reserved, which is a measured value and has to be usable as one.
func parseReservedPorts(raw string) ([]PortInterval, error) {
	text := strings.TrimSpace(raw)
	if text == "" {
		return nil, nil
	}
	items := strings.Split(text, ",")
	out := make([]PortInterval, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			// "50000,,50100": the kernel does not print this, so a value that
			// does is not a reservation list and must not be half-read.
			return nil, fmt.Errorf("%q has an empty entry", text)
		}
		iv, err := parseInterval(item)
		if err != nil {
			return nil, err
		}
		out = append(out, iv)
	}
	return normalise(out), nil
}

// parseInterval reads "50000" or "50100-50200".
func parseInterval(item string) (PortInterval, error) {
	lowText, highText, ranged := strings.Cut(item, "-")
	if !ranged {
		port, err := parsePort(item)
		if err != nil {
			return PortInterval{}, err
		}
		return PortInterval{Low: port, High: port}, nil
	}
	low, err := parsePort(strings.TrimSpace(lowText))
	if err != nil {
		return PortInterval{}, fmt.Errorf("%q: %w", item, err)
	}
	high, err := parsePort(strings.TrimSpace(highText))
	if err != nil {
		return PortInterval{}, fmt.Errorf("%q: %w", item, err)
	}
	if low > high {
		return PortInterval{}, fmt.Errorf("%q ends before it starts", item)
	}
	return PortInterval{Low: low, High: high}, nil
}

// normalise sorts and merges, so that "50100-50200,50000" and
// "50000,50100-50200" print the same and a report stays diffable.
func normalise(in []PortInterval) []PortInterval {
	if len(in) == 0 {
		return nil
	}
	sort.Slice(in, func(i, j int) bool {
		if in[i].Low != in[j].Low {
			return in[i].Low < in[j].Low
		}
		return in[i].High < in[j].High
	})
	out := []PortInterval{in[0]}
	for _, iv := range in[1:] {
		last := &out[len(out)-1]
		// int() keeps 65535+1 from wrapping to 0: a range ending at the last
		// port must not merge with a range starting at 0.
		if int(iv.Low) <= int(last.High)+1 {
			if iv.High > last.High {
				last.High = iv.High
			}
			continue
		}
		out = append(out, iv)
	}
	return out
}
