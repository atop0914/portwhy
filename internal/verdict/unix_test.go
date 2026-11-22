package verdict

import (
	"errors"
	"strings"
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
// A name is compared byte for byte, the way the kernel compares it. Prefix
// matching is the tempting bug here — "/run/app.sock" and "/run/app.sock.old"
// are two different sockets, and so are "/run/app" and "/run/app.sock".
//
// Every case keeps a socket file at the queried path, because that is what makes
// a wrong match visible: with no file there, both a matched and an unmatched row
// end in "free" and the assertion would pass for the wrong reason. With the file
// present, an unmatched row must say stale-socket-file, while a wrongly matched
// row would claim bound.
func TestUnixNamesMatchExactly(t *testing.T) {
	cases := []struct {
		name  string
		table string
		query string
	}{
		{"a longer name is not this name", "/run/app.sock.old", "/run/app.sock"},
		{"a shorter name is not this name", "/run/app.sock", "/run/app"},
		{"a sibling directory is not this name", "/run/other/app.sock", "/run/app.sock"},
		{"the same suffix is not this name", "/run/app.sock", "/tmp/app.sock"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := askUnix(c.query, unixTable(unixSock(c.table, true)), UnixEnv{Path: path(true)})
			if v.Kind != KindStalePath {
				t.Fatalf("kind = %v, want stale-path: the row for %q does not hold %q", v.Kind, c.table, c.query)
			}
			if len(v.Holders) != 0 {
				t.Errorf("holders = %+v, want none: %q was read as %q", v.Holders, c.table, c.query)
			}
			if hasUnixReason(v, ReasonUnixHolder) {
				t.Error("a foreign row was reported as holding this name")
			}
		})
	}

	// The same table, queried with the name it actually carries, must still be
	// bound — otherwise the cases above could pass because matching broke
	// entirely rather than because it is exact.
	v := askUnix("/run/app.sock", unixTable(unixSock("/run/app.sock", true)), UnixEnv{Path: path(true)})
	if v.Kind != KindBound {
		t.Fatalf("kind = %v, want bound for the row's own name", v.Kind)
	}
}

// The report prints the path fact on its own "path:" line, so a reason detail
// must not restate it. The same fact said twice does not read as emphasis, it
// reads as two findings — the mistake this test was written after seeing in real
// output, where a free answer said "nothing exists at the path" both in the
// sentence and in its parenthetical.
//
// It also pins the details that do belong there: a count is a measurement the
// sentence does not carry, and dropping every detail would satisfy the rule by
// saying nothing.
func TestUnixReasonDetailsDoNotRestateThePath(t *testing.T) {
	regular := unixsock.PathState{Measured: true, Exists: true, Kind: "regular file"}
	absent := unixsock.PathState{Measured: true}

	cases := []struct {
		name     string
		v        UnixVerdict
		detail   string
		code     string
		noDetail bool
	}{
		{
			name:   "bound",
			v:      askUnix("/run/app.sock", unixTable(unixSock("/run/app.sock", true)), UnixEnv{Path: path(true)}),
			code:   ReasonUnixHolder,
			detail: "1 row(s) in the unix table",
		},
		{
			name:   "stale socket file",
			v:      askUnix("/run/app.sock", unixTable(), UnixEnv{Path: path(true)}),
			code:   ReasonUnixStaleSocket,
			detail: "0 row(s) in the unix table",
		},
		{
			name:   "not a socket",
			v:      askUnix("/run/app.sock", unixTable(), UnixEnv{Path: regular}),
			code:   ReasonUnixNonSocketPath,
			detail: "0 row(s) in the unix table",
		},
		{
			name:   "name released",
			v:      askUnix("/run/app.sock", unixTable(unixSock("/run/app.sock", true)), UnixEnv{Path: absent}),
			code:   ReasonUnixNameReleased,
			detail: "inode 4242 still cites this name",
		},
		{
			name:     "absent",
			v:        askUnix("/run/app.sock", unixTable(), UnixEnv{Path: absent}),
			code:     ReasonUnixAbsent,
			noDetail: true,
		},
		{
			// The abstract namespace has no path line, but it has the same rule:
			// the count is the measurement and the sentence carries the rest.
			name:   "abstract bound",
			v:      askUnix("@app", unixTable(unixSock("@app", true)), UnixEnv{}),
			code:   ReasonUnixHolder,
			detail: "1 row(s) in the unix table",
		},
		{
			name:     "abstract absent",
			v:        askUnix("@app", unixTable(), UnixEnv{}),
			code:     ReasonUnixAbstractAbsent,
			noDetail: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var found *Reason
			for i := range c.v.Reasons {
				if c.v.Reasons[i].Code == c.code {
					found = &c.v.Reasons[i]
				}
			}
			if found == nil {
				t.Fatalf("missing reason %s", c.code)
			}
			switch {
			case c.noDetail && found.Detail != "":
				t.Errorf("detail = %q, want none: the sentence and the path line already say it", found.Detail)
			case !c.noDetail && found.Detail != c.detail:
				t.Errorf("detail = %q, want %q", found.Detail, c.detail)
			}
			// The rule itself, applied to every reason on this answer, not just
			// the one above: a new code must not reintroduce the duplication.
			for _, r := range c.v.Reasons {
				for _, banned := range []string{"path", "exist"} {
					if strings.Contains(r.Detail, banned) {
						t.Errorf("%s detail = %q, restates the path line", r.Code, r.Detail)
					}
				}
			}
		})
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
