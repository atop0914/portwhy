package verdict

import "testing"

func owners(pids ...int) []Owner {
	out := make([]Owner, 0, len(pids))
	for _, p := range pids {
		out = append(out, Owner{PID: p, Comm: "svc", FD: 3})
	}
	return out
}

func rolesOf(owners []Owner) map[int]Role {
	out := make(map[int]Role, len(owners))
	for _, o := range owners {
		out[o.PID] = o.Role
	}
	return out
}

func TestSingleHolderIsSole(t *testing.T) {
	got := prepareOwners(owners(42), map[int]int{42: 1})
	if len(got) != 1 || got[0].Role != RoleSole {
		t.Fatalf("roles = %v, want one sole holder", rolesOf(got))
	}
}

// The parent forked the child after opening the listener, so the parent had the
// descriptor first. That is the whole inference, and it is why the parent is the
// one to talk to: killing the child leaves the socket up.
func TestAncestorIsCreatorAndDescendantIsInherited(t *testing.T) {
	got := prepareOwners(owners(200, 100), map[int]int{200: 100, 100: 1})
	roles := rolesOf(got)
	if roles[100] != RoleCreator {
		t.Errorf("pid 100 = %q, want creator", roles[100])
	}
	if roles[200] != RoleInherited {
		t.Errorf("pid 200 = %q, want inherited", roles[200])
	}
	// Pid order, not read order: ReadDir sorts names as strings, so this is the
	// assertion that catches "100 before 50" leaking into reports.
	if got[0].PID != 100 || got[1].PID != 200 {
		t.Errorf("order = %d,%d, want ascending pids", got[0].PID, got[1].PID)
	}
}

func TestGrandchildIsStillInheritedFromTheRootHolder(t *testing.T) {
	got := prepareOwners(owners(300, 100, 200), map[int]int{300: 200, 200: 100, 100: 1})
	roles := rolesOf(got)
	if roles[100] != RoleCreator {
		t.Errorf("pid 100 = %q, want creator", roles[100])
	}
	for _, pid := range []int{200, 300} {
		if roles[pid] != RoleInherited {
			t.Errorf("pid %d = %q, want inherited", pid, roles[pid])
		}
	}
}

// Two unrelated processes holding one socket means the descriptor was passed, not
// forked. Which of them opened it is not in /proc, so no role is claimed.
func TestUnrelatedHoldersAreSharedNotInvented(t *testing.T) {
	got := prepareOwners(owners(100, 200), map[int]int{100: 1, 200: 1})
	for pid, role := range rolesOf(got) {
		if role != RoleShared {
			t.Errorf("pid %d = %q, want shared", pid, role)
		}
	}
}

// A missing process tree downgrades the answer instead of guessing a lineage.
func TestMissingProcessTreeDowngradesToShared(t *testing.T) {
	got := prepareOwners(owners(100, 200), nil)
	for pid, role := range rolesOf(got) {
		if role != RoleShared {
			t.Errorf("pid %d = %q, want shared without a process tree", pid, role)
		}
	}
}

// One process can hold the same socket on several descriptors (dup). It is still
// one holder, and "creator" would be a claim about a relationship with itself.
func TestDuplicateDescriptorsOfOneProcessAreSole(t *testing.T) {
	got := prepareOwners([]Owner{{PID: 7, FD: 3}, {PID: 7, FD: 9}}, map[int]int{7: 1})
	if len(got) != 2 {
		t.Fatalf("owners = %d, want both descriptors listed", len(got))
	}
	for _, o := range got {
		if o.Role != RoleSole {
			t.Errorf("fd %d = %q, want sole", o.FD, o.Role)
		}
	}
}

// The parent walk must return, and return the same thing twice. /proc cannot
// produce a cycle, but the map can come from a fixture, and a hang on a host whose
// /proc cannot be trusted is the worst moment to hang: that is when this runs.
func TestCyclicProcessTreeTerminatesDeterministically(t *testing.T) {
	tree := map[int]int{1: 2, 2: 1, 3: 2}
	first := rolesOf(prepareOwners(owners(1, 2, 3), tree))
	second := rolesOf(prepareOwners(owners(3, 1, 2), tree))
	if len(first) != 3 {
		t.Fatalf("roles = %v, want three holders", first)
	}
	for pid, role := range first {
		if second[pid] != role {
			t.Errorf("pid %d = %q, then %q: input order changed the answer", pid, role, second[pid])
		}
	}
}

// prepareOwners must not reorder the evidence it was given: the slice comes from
// the /proc index, and the next question asked of that index would see the damage.
func TestPrepareOwnersDoesNotTouchItsInput(t *testing.T) {
	in := owners(300, 100, 200)
	before := make([]int, len(in))
	for i, o := range in {
		before[i] = o.PID
	}

	_ = prepareOwners(in, map[int]int{300: 200, 200: 100, 100: 1})

	for i, pid := range before {
		if in[i].PID != pid {
			t.Fatalf("input reordered at %d: %d, want %d", i, in[i].PID, pid)
		}
	}
	if in[0].Role != "" {
		t.Error("input was annotated; roles belong to the copy")
	}
}
