//go:build linux

package netns

import (
	"os"
	"path/filepath"
	"testing"
)

// procTree lays out the two links the way procfs does, so a test can state which
// namespaces exist without touching the ones it runs in. The links are real
// symlinks on a real filesystem: the reader under test is exercised end to end,
// not handed a struct.
func procTree(t *testing.T, self, pidOne *string) string {
	t.Helper()
	dir := t.TempDir()
	for rel, target := range map[string]*string{"self/ns/net": self, "1/ns/net": pidOne} {
		if target == nil {
			continue
		}
		full := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.Symlink(*target, full); err != nil {
			t.Fatalf("symlink %s: %v", rel, err)
		}
	}
	return dir
}

func link(s string) *string { return &s }

func TestReadReportsThisProcessNamespace(t *testing.T) {
	dir := procTree(t, link("net:[4026532488]"), link("net:[4026532488]"))
	id := Read(dir)
	if !id.Known() {
		t.Fatalf("not known: %s", id.Describe())
	}
	if id.Inode != 4026532488 {
		t.Errorf("inode = %d, want 4026532488", id.Inode)
	}
	if id.Self != "net:[4026532488]" {
		t.Errorf("self = %q, want the link target as printed", id.Self)
	}
	if id.Same != PIDOneSame {
		t.Errorf("same = %v, want the same one", id.Same)
	}
	if want := filepath.Join(dir, "self", "ns", "net"); id.Path != want {
		t.Errorf("path = %q, want %q", id.Path, want)
	}
}

// A different namespace is a fact worth printing, not a failure: it is the case
// where pid 1's view of the machine is not this process's view.
func TestReadNoticesADifferentNamespaceFromPIDOne(t *testing.T) {
	dir := procTree(t, link("net:[4026532488]"), link("net:[4026532223]"))
	id := Read(dir)
	if id.Same != PIDOneDifferent {
		t.Fatalf("same = %v, want different", id.Same)
	}
	if id.PIDOne != "net:[4026532223]" {
		t.Errorf("pid one = %q, want the link that was read", id.PIDOne)
	}
	if id.SameErr != "" {
		t.Errorf("sameErr = %q, want empty: the comparison was made", id.SameErr)
	}
}

// Half the evidence is still worth printing: the namespace was read, and the
// comparison was not. Neither half may be invented.
func TestReadWithoutPIDOneKeepsTheNamespaceAndDropsTheComparison(t *testing.T) {
	dir := procTree(t, link("net:[4026532488]"), nil)
	id := Read(dir)
	if !id.Known() {
		t.Fatalf("a readable self link was reported as unknown: %s", id.Describe())
	}
	if id.Same != PIDOneUnknown {
		t.Errorf("same = %v, want unknown", id.Same)
	}
	if id.SameErr == "" {
		t.Error("no reason recorded for the missing comparison")
	}
	if id.PIDOne != "" {
		t.Errorf("pid one = %q, want empty", id.PIDOne)
	}
}

// The reverse assertion for the whole package: no link means no inode. A zero
// inode must not turn into a plausible-looking namespace.
func TestReadWithoutASelfLinkReportsNothing(t *testing.T) {
	dir := procTree(t, nil, link("net:[4026532488]"))
	id := Read(dir)
	if id.Known() {
		t.Fatalf("reported a namespace from nothing: %+v", id)
	}
	if id.Inode != 0 || id.Self != "" {
		t.Errorf("invented an identity: %+v", id)
	}
	if id.Err == "" {
		t.Error("no reason recorded for the failed read")
	}
	if id.Same != PIDOneUnknown {
		t.Errorf("same = %v, want unknown", id.Same)
	}
}

// A link that is not a namespace link is not a namespace. Readlink succeeding is
// not the same as having read what we think we read.
func TestReadRejectsALinkItDoesNotUnderstand(t *testing.T) {
	for name, target := range map[string]string{
		"other kind":   "pid:[4026531836]",
		"not a number": "net:[abc]",
		"inode zero":   "net:[0]",
	} {
		t.Run(name, func(t *testing.T) {
			id := Read(procTree(t, link(target), link("net:[4026532488]")))
			if id.Known() {
				t.Fatalf("accepted %q as a namespace", target)
			}
			if id.Inode != 0 {
				t.Errorf("inode = %d, want 0", id.Inode)
			}
		})
	}
}

// readlink on something that is not a symlink fails; that failure has to be
// reported, not swallowed into "unknown but fine".
func TestReadReportsANonSymlink(t *testing.T) {
	dir := t.TempDir()
	full := filepath.Join(dir, "self", "ns", "net")
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(full, []byte("not a link"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	id := Read(dir)
	if id.Known() {
		t.Fatalf("a regular file was read as a namespace: %+v", id)
	}
	if id.Err == "" {
		t.Error("no reason recorded")
	}
}

// The live cross-check: the inode the reader reports is the inode an independent
// readlink of this host's own link names. No fixture, and no assertion about
// which namespace it is — the point is agreement.
func TestReadMatchesThisHost(t *testing.T) {
	target, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Skipf("cannot readlink /proc/self/ns/net: %v", err)
	}
	want, err := parseLink(target)
	if err != nil {
		t.Skipf("this host's link is %q: %v", target, err)
	}

	id := Read(DefaultRoot)
	if !id.Known() {
		t.Fatalf("reader failed on a link this test just read: %s", id.Describe())
	}
	if id.Inode != want {
		t.Errorf("inode = %d, want %d (from %q)", id.Inode, want, target)
	}
	// When pid 1's link is readable here too, so is the comparison — "unknown"
	// with both links present would mean the second read failed silently. It is
	// checked independently, because a run as a non-root user may legitimately
	// not have that access.
	if _, err := os.Readlink("/proc/1/ns/net"); err == nil && id.Same == PIDOneUnknown {
		t.Errorf("no comparison with pid 1 although /proc/1/ns/net was readable: %s", id.SameErr)
	}
	t.Logf("this process: %s", id.Describe())
}
