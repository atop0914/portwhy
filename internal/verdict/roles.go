package verdict

import "sort"

// Role is what the process tree proves about how a process came to hold a socket.
//
// The kernel records no creator: /proc/net names an inode, and every process with
// that inode open is equally a holder. What the process tree does give is
// descent — a shared socket is inherited across fork(), so a holder that is an
// ancestor of every other holder must have had it first. That is a conclusion
// from evidence, and it stops where the evidence stops: when the holders are not
// in one chain (the descriptor was passed over a unix socket, as socket activation
// does), no role is assigned and every holder is reported as shared.
type Role string

const (
	// RoleSole means one process holds the socket. There is nothing to choose.
	RoleSole Role = "sole"
	// RoleCreator means the holder is an ancestor of every other holder, so it
	// had the socket before them. This is the process to talk to.
	RoleCreator Role = "creator"
	// RoleInherited means the holder descends from the creator: it was forked
	// with the descriptor already open. Killing it alone leaves the socket up.
	RoleInherited Role = "inherited"
	// RoleShared means several holders and none is an ancestor of the others.
	// Either the descriptor was passed between unrelated processes, or the
	// process tree was not readable; which of the two cannot be told here, so no
	// claim is made about who opened it.
	RoleShared Role = "shared"
)

func (r Role) String() string { return string(r) }

// prepareOwners returns a sorted copy of owners with roles assigned.
//
// The copy is not politeness: the slice comes from the /proc index, and a
// judgement that reordered the evidence it was handed would corrupt the next
// question asked of the same index.
func prepareOwners(owners []Owner, ppid map[int]int) []Owner {
	if len(owners) == 0 {
		return nil
	}
	out := make([]Owner, len(owners))
	copy(out, owners)
	assignRoles(out, ppid)
	// Pid order, then descriptor: a report whose rows swap places between runs
	// cannot be diffed, and the first pid is the first thing a reader acts on.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].PID != out[j].PID {
			return out[i].PID < out[j].PID
		}
		return out[i].FD < out[j].FD
	})
	return out
}

// assignRoles writes a role on every element of a slice the caller owns.
func assignRoles(owners []Owner, ppid map[int]int) {
	distinct := distinctPIDs(owners)
	if len(distinct) == 1 {
		for i := range owners {
			owners[i].Role = RoleSole
		}
		return
	}

	creator := -1
	for _, candidate := range distinct {
		if ancestorOfAll(candidate, distinct, ppid) {
			creator = candidate
			break
		}
	}
	for i := range owners {
		switch {
		case creator == -1:
			owners[i].Role = RoleShared
		case owners[i].PID == creator:
			owners[i].Role = RoleCreator
		default:
			owners[i].Role = RoleInherited
		}
	}
}

func distinctPIDs(owners []Owner) []int {
	seen := make(map[int]bool, len(owners))
	out := make([]int, 0, len(owners))
	for _, o := range owners {
		if seen[o.PID] {
			continue
		}
		seen[o.PID] = true
		out = append(out, o.PID)
	}
	// Sorted so the search below does not depend on the order /proc happened to
	// hand the holders over in: the same tree must give the same roles.
	sort.Ints(out)
	return out
}

// ancestorOfAll reports whether candidate is an ancestor of every other pid.
//
// At most one holder can answer true: two processes cannot both be ancestors of
// each other in a tree.
func ancestorOfAll(candidate int, pids []int, ppid map[int]int) bool {
	if ppid == nil {
		return false
	}
	for _, pid := range pids {
		if pid == candidate {
			continue
		}
		if !isAncestor(candidate, pid, ppid) {
			return false
		}
	}
	return true
}

// isAncestor walks up from descendant towards the root.
//
// The walk stops at the first parent it cannot see — a process that exited, or one
// we were not allowed to read — and reports "not an ancestor" rather than guessing
// past the hole. Visited pids guard the loop: /proc cannot produce a cycle, but
// this map can also come from a fixture, and a hang in a diagnostic tool is the
// worst failure mode it has.
func isAncestor(ancestor, descendant int, ppid map[int]int) bool {
	visited := make(map[int]bool, len(ppid)+1)
	for {
		if visited[descendant] {
			return false
		}
		visited[descendant] = true
		parent, ok := ppid[descendant]
		if !ok || parent <= 0 {
			return false
		}
		if parent == ancestor {
			return true
		}
		descendant = parent
	}
}
