package verdict

import (
	"errors"
	"testing"

	"github.com/atop0914/portwhy/internal/unixsock"
)

func unixSock(name string, listening bool) unixsock.Socket {
	flags := uint32(0)
	if listening {
		flags = 0x00010000
	}
	return unixsock.Socket{
		Name:  name,
		Type:  unixsock.TypeStream,
		State: unixsock.StateUnconnected,
		Flags: flags,
		Inode: 4242,
	}
}

func unixTable(socks ...unixsock.Socket) unixsock.Table {
	return unixsock.Table{Name: "unix", Sockets: socks}
}

func path(socket bool) unixsock.PathState {
	kind := "regular file"
	if socket {
		kind = "socket"
	}
	return unixsock.PathState{Measured: true, Exists: true, Kind: kind}
}

func askUnix(name string, table unixsock.Table, env UnixEnv) UnixVerdict {
	return ExplainUnix(UnixNameOf(name), table, env)
}

// hasUnixReason is the unix counterpart of hasReason, kept separate because the
// two verdict types are separate: a port finding and a name finding are not
// interchangeable, and neither are their reasons.
func hasUnixReason(v UnixVerdict, code string) bool {
	for _, r := range v.Reasons {
		if r.Code == code {
			return true
		}
	}
	return false
}

// A live socket with that name: bind() fails, and the report has to name it.
func TestUnixHolderIsBound(t *testing.T) {
	v := askUnix("/run/app.sock", unixTable(unixSock("/run/app.sock", true)), UnixEnv{Path: path(true)})
	if v.Kind != KindBound {
		t.Fatalf("kind = %v, want bound", v.Kind)
	}
	if !hasUnixReason(v, ReasonUnixHolder) {
		t.Error("missing socket-bound-to-name reason")
	}
	if len(v.Holders) != 1 || !v.Holders[0].Socket.Listening() {
		t.Errorf("holders = %+v, want one listening socket", v.Holders)
	}
}

// The case no port has: the socket file outlived its process. The table has no
// row, the file is still there, and bind() still fails — verified on a live
// kernel by closing a listener without unlinking and binding again.
func TestUnixStaleSocketFileIsNotFree(t *testing.T) {
	v := askUnix("/run/app.sock", unixTable(), UnixEnv{Path: path(true)})
	if v.Kind != KindStalePath {
		t.Fatalf("kind = %v, want stale-path", v.Kind)
	}
	if !hasUnixReason(v, ReasonUnixStaleSocket) {
		t.Error("missing socket-file-without-holder reason")
	}
	if hasUnixReason(v, ReasonUnixHolder) {
		t.Error("a stale file is reported as a holder")
	}
}

// A regular file in the way fails bind() just the same, but the sentence has to
// differ: telling a user their "socket file" is stale when they are looking at a
// config file is the kind of wrong that erodes trust.
func TestUnixNonSocketPathHasItsOwnReason(t *testing.T) {
	v := askUnix("/run/app.sock", unixTable(), UnixEnv{Path: path(false)})
	if v.Kind != KindStalePath {
		t.Fatalf("kind = %v, want stale-path", v.Kind)
	}
	if !hasUnixReason(v, ReasonUnixNonSocketPath) {
		t.Error("missing path-exists-not-a-socket reason")
	}
	if hasUnixReason(v, ReasonUnixStaleSocket) {
		t.Error("a regular file is described as a stale socket file")
	}
}

// The mirror case: the name was unlinked while the socket stayed open. The table
// still has the row, the path is gone, and a new bind() succeeds — so the answer
// is free, with the orphaned socket named rather than treated as a blocker.
func TestUnixUnlinkedNameIsFreeEvenThoughARowRemains(t *testing.T) {
	v := askUnix("/run/app.sock", unixTable(unixSock("/run/app.sock", true)),
		UnixEnv{Path: unixsock.PathState{Measured: true}})
	if v.Kind != KindFree {
		t.Fatalf("kind = %v, want free (the name is gone, so bind() succeeds)", v.Kind)
	}
	if !hasUnixReason(v, ReasonUnixNameReleased) {
		t.Error("missing name-released reason")
	}
	if hasUnixReason(v, ReasonUnixHolder) {
		t.Error("a socket that no longer occupies the name is reported as a holder")
	}
}

// Nothing anywhere: the only case that is free with no condition attached.
func TestUnixAbsentIsFree(t *testing.T) {
	v := askUnix("/run/app.sock", unixTable(), UnixEnv{Path: unixsock.PathState{Measured: true}})
	if v.Kind != KindFree {
		t.Fatalf("kind = %v, want free", v.Kind)
	}
	if !hasUnixReason(v, ReasonUnixAbsent) {
		t.Error("missing name-in-neither-table-nor-filesystem reason")
	}
}

// "Nobody looked" is not "nothing is there". The zero PathState reaches this
// branch whenever a caller forgets to measure, and the answer has to be unknown.
func TestUnixUnmeasuredPathIsUnknownNotFree(t *testing.T) {
	v := askUnix("/run/app.sock", unixTable(), UnixEnv{})
	if v.Kind != KindUnknown {
		t.Fatalf("kind = %v, want unknown", v.Kind)
	}
	if !hasUnixReason(v, ReasonUnixPathUnreadable) {
		t.Error("missing unix-path-unreadable reason")
	}
}

// A failed stat is a hole, not an absence: a permission problem must never be
// read as "the name is free".
func TestUnixFailedStatIsUnknownNotFree(t *testing.T) {
	v := askUnix("/run/app.sock", unixTable(),
		UnixEnv{Path: unixsock.PathState{Measured: true, Err: "permission denied"}})
	if v.Kind != KindUnknown {
		t.Fatalf("kind = %v, want unknown", v.Kind)
	}
}

// An unreadable table defeats everything else: no row was seen, so a missing file
// cannot make the name free.
func TestUnixUnreadableTableIsUnknownNotFree(t *testing.T) {
	table := unixsock.Table{Name: "unix", Err: errors.New("open /proc/net/unix: permission denied")}
	v := askUnix("/run/app.sock", table, UnixEnv{Path: unixsock.PathState{Measured: true}})
	if v.Kind != KindUnknown {
		t.Fatalf("kind = %v, want unknown", v.Kind)
	}
	if !hasUnixReason(v, ReasonUnixTableUnreadable) {
		t.Error("missing unix-table-unreadable reason")
	}
	if v.TableRead {
		t.Error("TableRead is true for a table that could not be read")
	}
}

// Abstract names live only in the kernel: no row means free, and the report must
// not claim it looked at a path.
func TestUnixAbstractName(t *testing.T) {
	v := askUnix("@svc", unixTable(unixSock("@svc", true)), UnixEnv{})
	if v.Kind != KindBound {
		t.Fatalf("kind = %v, want bound", v.Kind)
	}

	// A path state handed in for an abstract name must be ignored: there is no
	// file, so a file cannot be what holds it.
	v = askUnix("@svc", unixTable(), UnixEnv{Path: path(true)})
	if v.Kind != KindFree {
		t.Fatalf("kind = %v, want free", v.Kind)
	}
	if !hasUnixReason(v, ReasonUnixAbstractAbsent) {
		t.Error("missing abstract-name-not-in-table reason")
	}
	if hasUnixReason(v, ReasonUnixStaleSocket) || hasUnixReason(v, ReasonUnixNonSocketPath) {
		t.Error("an abstract name was judged against a filesystem entry")
	}
}

// The two namespaces are independent: "@name" and "/name" are different sockets.
// Verified on a live kernel — both binds succeed.
func TestUnixAbstractAndPathDoNotCollide(t *testing.T) {
	table := unixTable(unixSock("@svc", true))
	v := askUnix("/svc", table, UnixEnv{Path: unixsock.PathState{Measured: true}})
	if v.Kind != KindFree {
		t.Fatalf("kind = %v, want free: /svc is not @svc", v.Kind)
	}
	// And the reverse direction.
	v = askUnix("@svc", unixTable(unixSock("/svc", true)), UnixEnv{})
	if v.Kind != KindFree {
		t.Fatalf("kind = %v, want free: @svc is not /svc", v.Kind)
	}
}

// Names are matched exactly. A prefix rule would make "/run/app.sock" collide
// with "/run/app.sock.old", which is a different socket and a different process.
func TestUnixNamesMatchExactly(t *testing.T) {
	table := unixTable(unixSock("/run/app.sock.old", true))
	if v := askUnix("/run/app.sock", table, UnixEnv{Path: unixsock.PathState{Measured: true}}); v.Kind != KindFree {
		t.Fatalf("kind = %v, want free: a longer name is not this name", v.Kind)
	}
	table = unixTable(unixSock("/run/app.sock", true))
	if v := askUnix("/run/app", table, UnixEnv{Path: unixsock.PathState{Measured: true}}); v.Kind != KindFree {
		t.Fatalf("kind = %v, want free: a shorter name is not this name", v.Kind)
	}
}

// Who holds it is the next question, so the owners come with the answer — and an
// unreadable process is stated rather than leaving the field silently empty.
func TestUnixHolderOwnersAndTheDeniedCaveat(t *testing.T) {
	table := unixTable(unixSock("/run/app.sock", true))
	env := UnixEnv{
		Path: path(true),
		Lookup: func(inode uint64) []Owner {
			return []Owner{{PID: 1234, Comm: "app", FD: 7}}
		},
		ProcsRead: 10, ProcsDenied: 2,
	}
	v := askUnix("/run/app.sock", table, env)
	if len(v.Holders) != 1 || len(v.Holders[0].Owners) != 1 {
		t.Fatalf("holders = %+v, want one with one owner", v.Holders)
	}
	if v.Holders[0].Owners[0].PID != 1234 {
		t.Errorf("owner pid = %d, want 1234", v.Holders[0].Owners[0].PID)
	}
	// Two processes were unreadable, but this holder has a name, so the caveat
	// would be about a different process than the one being reported.
	if hasUnixReason(v, ReasonProcsDenied) {
		t.Error("procs-denied stated next to a holder that has a name")
	}

	env.Lookup = nil
	env.ProcsDenied = 2
	v = askUnix("/run/app.sock", table, env)
	if hasUnixReason(v, ReasonProcsDenied) {
		t.Error("procs-denied stated when the holder walk was never attempted")
	}
}

// The target parser is the boundary where a name becomes a question: "unix:" is a
// prefix people type, "@" is the kernel's spelling of the abstract namespace, and
// everything else is a path.
func TestUnixNameOf(t *testing.T) {
	cases := []struct {
		in       string
		name     string
		abstract bool
	}{
		{"/run/app.sock", "/run/app.sock", false},
		{"unix:/run/app.sock", "/run/app.sock", false},
		{"@svc", "@svc", true},
		{"unix:@svc", "@svc", true},
		// '@' is a legal filename character, but the kernel's own spelling wins:
		// a path that starts with @ cannot be expressed here, and pretending it
		// could would break abstract names, which are far more common.
		{"@/tmp/odd", "@/tmp/odd", true},
	}
	for _, c := range cases {
		q := UnixNameOf(c.in)
		if q.Name != c.name || q.Abstract != c.abstract {
			t.Errorf("UnixNameOf(%q) = %+v, want name=%q abstract=%v", c.in, q, c.name, c.abstract)
		}
	}
}
