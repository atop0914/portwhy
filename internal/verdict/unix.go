package verdict

import (
	"fmt"
	"sort"
	"strings"

	"github.com/atop0914/portwhy/internal/unixsock"
)

// Unix reason codes.
//
// They all start with "unix-" so that a code in a log or a JSON field says which
// vocabulary it belongs to without a lookup. The judgement and the CLI sentences
// are tied together by a test that walks these values.
//
// They are separate from the port codes because the failures are different
// things. "The port is taken" is a statement about sockets; "the socket file is
// still there" is a statement about a filesystem entry that outlived its
// process, and telling a user to look for a process there would send them after
// something that does not exist.
const (
	// ReasonUnixHolder means a socket in the kernel table carries this name, so
	// bind() fails with EADDRINUSE.
	ReasonUnixHolder = "unix-socket-bound"
	// ReasonUnixStaleSocket is the failure no port has: the socket file exists,
	// no socket in the table carries the name, and bind() still fails until the
	// file is removed. Verified on a live kernel by killing a listener and
	// binding again.
	ReasonUnixStaleSocket = "unix-stale-socket-file"
	// ReasonUnixNonSocketPath is the same failure with a different entry: the
	// path is a regular file, a directory or a pipe. bind() fails just the same,
	// and the fix is the same, but calling it a stale socket would be a false
	// description of what the user is looking at.
	ReasonUnixNonSocketPath = "unix-path-not-a-socket"
	// ReasonUnixNameReleased is the mirror of the stale file: the table still has
	// a row, the name is gone from the filesystem, and a new bind succeeds. The
	// old socket is unreachable rather than holding anything. Verified on a live
	// kernel: unlink() while the listener stays open, then bind again.
	ReasonUnixNameReleased = "unix-name-released"
	// ReasonUnixAbsent is the free answer for a filesystem name: no row, and no
	// entry at the path.
	ReasonUnixAbsent = "unix-name-absent"
	// ReasonUnixAbstractAbsent is the free answer for an abstract name. It is a
	// different sentence because there is no file to check: the name lives only
	// in the kernel, and the report must not imply it looked at a path.
	ReasonUnixAbstractAbsent = "unix-abstract-absent"
	// ReasonUnixTableUnreadable is a hole in the evidence, never a free name.
	ReasonUnixTableUnreadable = "unix-table-unreadable"
	// ReasonUnixPathUnreadable is the other hole: the kernel table was fine but
	// the filesystem question could not be answered, so "no file there" was
	// never established.
	ReasonUnixPathUnreadable = "unix-path-unreadable"
)

// UnixQuery is the question: one unix socket name.
type UnixQuery struct {
	// Name is what the user typed, exactly: a filesystem path, or an abstract
	// name including its leading '@'. It is compared byte for byte against the
	// kernel's column, because that is how the kernel compares names.
	Name string
	// Abstract is whether this name lives in the abstract namespace. It cannot be
	// inferred at judgement time: an '@' at the start of a path is a legal
	// filename character, and the two namespaces are independent (verified:
	// binding "@x" and "/x" both succeed).
	Abstract bool
}

// UnixHolder is one socket in the table that carries the queried name.
type UnixHolder struct {
	Socket unixsock.Socket
	Owners []Owner
}

// UnixEnv is everything ExplainUnix needs from outside, injected so the
// judgement stays a function of its inputs.
type UnixEnv struct {
	// Path is what the filesystem said. It is ignored for abstract names, which
	// have no filesystem entry at all.
	Path unixsock.PathState
	// Lookup returns the holders of one inode. Nil means the walk was not
	// attempted, which is disclosed rather than read as "no owner".
	Lookup func(inode uint64) []Owner
	// ProcsRead and ProcsDenied describe how complete the holder lookup was.
	ProcsRead   int
	ProcsDenied int
	// PPID maps pid to parent pid, for the same reason as in the port judgement:
	// a shared socket is inherited across fork(), so an ancestor must precede.
	PPID map[int]int
}

// UnixVerdict is the answer plus the evidence it rests on.
type UnixVerdict struct {
	Query   UnixQuery
	Kind    Kind
	Holders []UnixHolder
	Reasons []Reason
	// Path is the filesystem measurement this answer was allowed to use,
	// recorded whether or not it changed anything: a report that says "the file
	// is gone" has to be able to show what it looked at.
	Path unixsock.PathState
	// TableRead is false when the kernel table could not be read; Err says why.
	TableRead   bool
	TableErr    string
	ProcsRead   int
	ProcsDenied int
}

// ExplainUnix classifies one unix socket name.
//
// The order of the checks is the honesty of the result. An unreadable table is
// settled first, because no later branch may turn a blind spot into "free". After
// that the filesystem question comes before the "nothing found" answer for the
// same reason: "no socket carries this name" and "nothing is in the way" are
// different statements, and only the second one is a free name.
func ExplainUnix(q UnixQuery, table unixsock.Table, env UnixEnv) UnixVerdict {
	v := UnixVerdict{
		Query:       q,
		Path:        env.Path,
		TableRead:   table.Err == nil,
		ProcsRead:   env.ProcsRead,
		ProcsDenied: env.ProcsDenied,
	}

	if table.Err != nil {
		v.TableErr = table.Err.Error()
		v.Kind = KindUnknown
		v.Reasons = append(v.Reasons, Reason{
			Code:   ReasonUnixTableUnreadable,
			Detail: table.Err.Error(),
		})
		return v
	}

	// Names are matched exactly. A suffix or prefix match here would make
	// "/run/app.sock" collide with "/run/app.sock.old" — a name that is a
	// different socket, not a variant of this one.
	for _, s := range table.Sockets {
		if s.Name != q.Name {
			continue
		}
		h := UnixHolder{Socket: s}
		if env.Lookup != nil {
			h.Owners = prepareOwners(env.Lookup(s.Inode), env.PPID)
		}
		v.Holders = append(v.Holders, h)
	}
	// Stable order so two runs over the same table produce the same report.
	sort.SliceStable(v.Holders, func(i, j int) bool {
		if v.Holders[i].Socket.Listening() != v.Holders[j].Socket.Listening() {
			return v.Holders[i].Socket.Listening()
		}
		return v.Holders[i].Socket.Inode < v.Holders[j].Socket.Inode
	})

	if q.Abstract {
		return explainUnixAbstract(v, env)
	}
	return explainUnixPath(v, env)
}

// explainUnixAbstract answers for the abstract namespace.
//
// There is no file to check and no file to remove, so the only evidence is the
// table. That also means a stale name cannot outlive its socket: the name lives
// in the kernel and goes away with the socket.
func explainUnixAbstract(v UnixVerdict, env UnixEnv) UnixVerdict {
	if len(v.Holders) > 0 {
		v.Kind = KindBound
		v.Reasons = append(v.Reasons, Reason{
			Code:   ReasonUnixHolder,
			Detail: fmt.Sprintf("%d row(s) in the unix table carry this name", len(v.Holders)),
		})
		v = unixOwnerCaveat(v, env)
		return v
	}
	v.Kind = KindFree
	v.Reasons = append(v.Reasons, Reason{
		Code: ReasonUnixAbstractAbsent,
		// No detail: the one measurement this answer rests on is the sentence
		// itself, and repeating it here would read as two findings.
	})
	return v
}

// explainUnixPath answers for a filesystem name.
//
// Two independent facts decide it, and they can disagree in both directions:
// the kernel may have a row while the name is gone (unlinked, still bound), and
// it may have no row while a file is in the way (the stale socket). Both were
// verified by binding for real, which is why neither is folded into the other.
func explainUnixPath(v UnixVerdict, env UnixEnv) UnixVerdict {
	path := v.Path

	switch {
	case !path.Measured:
		// Nobody looked, so "no file there" was never established.
		v.Kind = KindUnknown
		v.Reasons = append(v.Reasons, Reason{
			Code:   ReasonUnixPathUnreadable,
			Detail: "the path was not checked",
		})
		return v
	case path.Err != "":
		v.Kind = KindUnknown
		v.Reasons = append(v.Reasons, Reason{
			Code:   ReasonUnixPathUnreadable,
			Detail: path.Err,
		})
		return v
	}

	hasRow := len(v.Holders) > 0
	switch {
	case hasRow && path.Exists:
		v.Kind = KindBound
		v.Reasons = append(v.Reasons, Reason{
			Code:   ReasonUnixHolder,
			Detail: fmt.Sprintf("%d row(s) in the unix table; %s", len(v.Holders), path.Describe()),
		})
		return unixOwnerCaveat(v, env)

	case hasRow && !path.Exists:
		// The row is real and the name is not: unlink() removed the directory
		// entry while the socket stayed bound, so a new bind() succeeds and the
		// old listener is unreachable rather than in the way.
		v.Kind = KindFree
		v.Reasons = append(v.Reasons, Reason{
			Code: ReasonUnixNameReleased,
			Detail: fmt.Sprintf("inode %d still cites this name in the unix table; the path itself does not exist",
				v.Holders[0].Socket.Inode),
		})
		return v

	case !hasRow && path.Exists && path.IsSocket():
		// The case this package exists for. A real bind was verified to fail
		// while this is true, and removing the file was verified to fix it.
		v.Kind = KindStalePath
		v.Reasons = append(v.Reasons, Reason{
			Code:   ReasonUnixStaleSocket,
			Detail: "the path is a socket file; no row in the unix table carries this name",
		})
		return v

	case !hasRow && path.Exists:
		v.Kind = KindStalePath
		v.Reasons = append(v.Reasons, Reason{
			Code:   ReasonUnixNonSocketPath,
			Detail: "the path exists and is a " + path.Kind,
		})
		return v
	}

	v.Kind = KindFree
	v.Reasons = append(v.Reasons, Reason{
		Code:   ReasonUnixAbsent,
		Detail: "no row in the unix table carries this name; nothing exists at the path",
	})
	return v
}

// unixOwnerCaveat states the hole in a "who holds it" answer: there is a socket,
// and the process behind it could not be named. It is a caveat on a finding, not
// on a free answer, and the two are different sentences.
//
// A nil Lookup is "the walk was not attempted" (-no-holders), not "it came back
// empty": blaming unreadable processes there would describe a search nobody made.
func unixOwnerCaveat(v UnixVerdict, env UnixEnv) UnixVerdict {
	unnamed := false
	for _, h := range v.Holders {
		if len(h.Owners) == 0 && h.Socket.Inode != 0 {
			unnamed = true
		}
	}
	if unnamed && env.Lookup != nil && v.ProcsDenied > 0 {
		v.Reasons = append(v.Reasons, Reason{
			Code:   ReasonProcsDenied,
			Detail: fmt.Sprintf("%d process(es) not readable", v.ProcsDenied),
		})
	}
	return v
}

// UnixNameOf turns a command-line target into a query.
//
// "unix:/path" is accepted because that is how people write it when a command
// has more than one target space; a bare "@name" is abstract because the kernel
// spells abstract names that way. Everything else is a path.
func UnixNameOf(target string) UnixQuery {
	name := target
	if rest, ok := strings.CutPrefix(target, "unix:"); ok {
		name = rest
	}
	return UnixQuery{Name: name, Abstract: strings.HasPrefix(name, "@")}
}

// AllUnixReasonCodes is every code this file can produce, for the registry test
// that keeps each one from being printed as a bare identifier.
func AllUnixReasonCodes() []string {
	return []string{
		ReasonUnixHolder,
		ReasonUnixStaleSocket,
		ReasonUnixNonSocketPath,
		ReasonUnixNameReleased,
		ReasonUnixAbsent,
		ReasonUnixAbstractAbsent,
		ReasonUnixTableUnreadable,
		ReasonUnixPathUnreadable,
	}
}
