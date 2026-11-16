package sockid

import "testing"

func TestParseSockLink(t *testing.T) {
	cases := []struct {
		target string
		want   uint64
		ok     bool
	}{
		{"socket:[29841669]", 29841669, true},
		{"socket:[0]", 0, false},          // inode 0 is not a file anyone can hold
		{"socket:[notanumber]", 0, false}, // malformed: skipped, not guessed
		{"pipe:[12345]", 0, false},
		{"/dev/null", 0, false},
		{"anon_inode:[eventfd]", 0, false},
		{"socket:[1]extra", 0, false},
	}
	for _, c := range cases {
		got, ok := ParseSockLink(c.target)
		if ok != c.ok || got != c.want {
			t.Errorf("ParseSockLink(%q) = (%d, %v), want (%d, %v)", c.target, got, ok, c.want, c.ok)
		}
	}
}

func TestHoldersOfInodeZeroIsAlwaysEmpty(t *testing.T) {
	// Even a corrupt index must not invent an owner for inode 0: TIME_WAIT rows
	// carry it, and naming a process there would be a fabricated accusation.
	idx := &Index{ByInode: map[uint64][]Holder{0: {{PID: 42, Comm: "x", FD: 3}}}}
	if got := idx.Holders(0); got != nil {
		t.Errorf("Holders(0) = %v, want nil", got)
	}
}

func TestCompleteTracksDeniedProcesses(t *testing.T) {
	if (&Index{}).Complete() != true {
		t.Error("index with no denials should be complete")
	}
	if (&Index{ProcsDenied: 1}).Complete() != false {
		t.Error("index with a denial must not claim completeness")
	}
	var nilIdx *Index
	if nilIdx.Complete() {
		t.Error("nil index must not claim completeness")
	}
	if nilIdx.Holders(123) != nil {
		t.Error("nil index must return no holders")
	}
}
