package sysctl

import (
	"fmt"
	"strings"
	"testing"
)

// The zero value is the one every caller gets by forgetting, so it must not be
// an answer. If it were 0 (dual-stack), a caller that never measured would
// report that a [::] listener shadows IPv4 — a confident claim about a machine
// nobody looked at.
func TestZeroValueIsNotAMeasurement(t *testing.T) {
	var b BindV6Only
	if b.Known() {
		t.Fatal("zero value claims to be measured")
	}
	if b.DualStack() {
		t.Fatal("zero value claims dual-stack")
	}
	if v, ok := b.Value(); ok {
		t.Fatalf("zero value yields value %d, want none", v)
	}
	if !strings.Contains(b.Describe(), "not measured") {
		t.Errorf("Describe() = %q, want it to say nothing was measured", b.Describe())
	}
}

func TestParseOnlyAcceptsTheTwoValuesTheKernelPrints(t *testing.T) {
	cases := []struct {
		raw   string
		want  BindV6OnlyState
		known bool
	}{
		{"0\n", BindV6OnlyDualStack, true},
		{"1\n", BindV6OnlyIPv6Only, true},
		{" 1 ", BindV6OnlyIPv6Only, true},
		{"2\n", BindV6OnlyUnmeasured, false},
		{"01\n", BindV6OnlyUnmeasured, false},
		{"true\n", BindV6OnlyUnmeasured, false},
		{"", BindV6OnlyUnmeasured, false},
		{"\n", BindV6OnlyUnmeasured, false},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%q", c.raw), func(t *testing.T) {
			got, err := parse(c.raw)
			if (err == nil) != c.known {
				t.Fatalf("parse(%q) err = %v, want known=%v", c.raw, err, c.known)
			}
			if got != c.want {
				t.Errorf("parse(%q) = %v, want %v", c.raw, got, c.want)
			}
		})
	}
}

// A value with no source and a missing value with no reason are both
// unfalsifiable, so Describe always carries one of the two.
func TestDescribeNamesValueAndSourceOrTheReason(t *testing.T) {
	measured := BindV6Only{State: BindV6OnlyDualStack, Raw: "0\n", Path: "/proc/sys/net/ipv6/bindv6only"}
	text := measured.Describe()
	if !strings.Contains(text, "= 0") || !strings.Contains(text, measured.Path) {
		t.Errorf("Describe() = %q, want the value and the path", text)
	}

	broken := BindV6Only{Path: "/proc/sys/net/ipv6/bindv6only", Err: "permission denied"}
	text = broken.Describe()
	if !strings.Contains(text, "unreadable") || !strings.Contains(text, "permission denied") {
		t.Errorf("Describe() = %q, want the reason for the missing value", text)
	}
	if broken.Known() {
		t.Error("an unreadable value reports itself as known")
	}
}
