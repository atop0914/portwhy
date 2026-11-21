package netns

import (
	"strings"
	"testing"
)

// The kernel prints "net:[<inode>]" and nothing else. Every other shape is not a
// namespace this tool understands, and a half-parsed link would put an inode in
// a report that nobody can look up.
func TestParseLinkAcceptsTheKernelShape(t *testing.T) {
	cases := map[string]uint64{
		"net:[4026531840]": 4026531840,
		"net:[4026532488]": 4026532488,
		" net:[1] ":        1,
		"net:[4294967295]": 4294967295,
	}
	for target, want := range cases {
		got, err := parseLink(target)
		if err != nil {
			t.Errorf("parseLink(%q): %v", target, err)
			continue
		}
		if got != want {
			t.Errorf("parseLink(%q) = %d, want %d", target, got, want)
		}
	}
}

func TestParseLinkRejectsEverythingElse(t *testing.T) {
	for name, target := range map[string]string{
		"empty":        "",
		"other kind":   "pid:[4026531836]",
		"mnt":          "mnt:[4026531841]",
		"no brackets":  "net:4026531840",
		"unclosed":     "net:[4026531840",
		"unopened":     "net:4026531840]",
		"not a number": "net:[abc]",
		"inode zero":   "net:[0]",
		"negative":     "net:[-1]",
		"trailing":     "net:[1]extra",
	} {
		t.Run(name, func(t *testing.T) {
			got, err := parseLink(target)
			if err == nil {
				t.Fatalf("accepted %q as %d", target, got)
			}
			if got != 0 {
				t.Errorf("a rejected input still produced %d", got)
			}
		})
	}
}

// The scope phrase, in each of the four states it can be in. None of them may
// mention "initial" or "the host": this tool reads exactly one namespace, and
// naming another one would be the inference its own rules forbid.
func TestDescribeNeverClaimsToSeeAnotherNamespace(t *testing.T) {
	cases := map[string]Identity{
		"unread": {Path: "/proc/self/ns/net", Err: "permission denied"},
		"same": {Inode: 4026532488, Self: "net:[4026532488]", PIDOne: "net:[4026532488]",
			Same: PIDOneSame, Path: "/proc/self/ns/net"},
		"different": {Inode: 4026532488, Self: "net:[4026532488]", PIDOne: "net:[4026532223]",
			Same: PIDOneDifferent, Path: "/proc/self/ns/net"},
		"no comparison": {Inode: 4026532488, Self: "net:[4026532488]",
			SameErr: "open /proc/1/ns/net: permission denied", Path: "/proc/self/ns/net"},
		"never asked": {},
	}
	for name, id := range cases {
		t.Run(name, func(t *testing.T) {
			desc := id.Describe()
			if strings.TrimSpace(desc) == "" {
				t.Fatal("describe said nothing at all")
			}
			for _, forbidden := range []string{"initial", "host"} {
				if strings.Contains(desc, forbidden) {
					t.Errorf("describe claims more than it measured (%q): %q", forbidden, desc)
				}
			}
			if id.Known() && !strings.Contains(desc, id.Self) {
				t.Errorf("describe does not print the link it read: %q", desc)
			}
		})
	}
}

// The two halves of a partial read stay distinguishable: a namespace with no
// comparison is still a namespace, and the missing half is stated as missing.
func TestDescribeStatesTheComparisonItCouldNotMake(t *testing.T) {
	id := Identity{Inode: 4026532488, Self: "net:[4026532488]", Path: "/proc/self/ns/net",
		SameErr: "open /proc/1/ns/net: no such file or directory"}
	desc := id.Describe()
	if !strings.Contains(desc, "net:[4026532488]") {
		t.Errorf("describe drops the inode it did read: %q", desc)
	}
	if !strings.Contains(desc, "could not be read") {
		t.Errorf("describe does not disclose the failed comparison: %q", desc)
	}
	if strings.Contains(desc, "the same one") {
		t.Errorf("describe assumed equality it never measured: %q", desc)
	}
}

func TestKnownRequiresAnInode(t *testing.T) {
	for name, id := range map[string]Identity{
		"never asked": {},
		"failed":      {Path: "/proc/self/ns/net", Err: "permission denied"},
		"inode only":  {Inode: 42, Self: "net:[42]"},
	} {
		t.Run(name, func(t *testing.T) {
			if id.Known() != (id.Inode != 0 && id.Err == "") {
				t.Errorf("Known() = %v for %+v", id.Known(), id)
			}
		})
	}
}
