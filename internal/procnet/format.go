package procnet

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// FormatAddr renders an endpoint the way a socket table spells it:
// "AABBCCDD:PORT" for IPv4, 32 hex chars plus the port for IPv6, uppercase, and
// little-endian — per 32-bit word for IPv6, not for the whole address.
//
// It exists so that a fixture is written by the same code that reads it. Hand
// copied hex is how a test ends up asserting against a layout the kernel never
// produced: the fixture parses, the assertion passes, and both are wrong
// together. The endianness itself is pinned by FormatAddr's own test against
// values taken from a real capture, not from this function.
//
// The port is always four hex digits; port 0 is legitimate (that is how the peer
// of a listener is spelled) and is not an error.
func FormatAddr(a Addr) (string, error) {
	if !a.IP.IsValid() {
		// A zero netip.Addr has no family. Guessing IPv4 would spell "00000000"
		// for an address nobody supplied.
		return "", errors.New("procnet: cannot format an address with no family")
	}
	var b []byte
	if a.IP.Is4() {
		v := a.IP.As4()
		reverse(v[:])
		b = v[:]
	} else {
		v := a.IP.As16()
		for i := 0; i < len(v); i += 4 {
			reverse(v[i : i+4])
		}
		b = v[:]
	}
	return strings.ToUpper(hex.EncodeToString(b)) + fmt.Sprintf(":%04X", a.Port), nil
}
