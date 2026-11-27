# Changelog

Everything here is in v1.0.0. There was no earlier release: the project was built
day by day and published once, so the entries below are capabilities rather than
diffs — what the tool can now answer, and the boundary of each answer.

The boundary lines are not modesty. Every one of them was measured on a real
kernel, and several replaced a claim this tool used to make and no longer does.

## v1.0.0 — 2026-11-27

### Five diagnoses instead of "the port is in use"

`portwhy why <host:port>` reads `/proc/net/tcp` and `/proc/net/tcp6`, resolves each
matching socket's inode to the processes holding it, and classifies the answer as
`free`, `listening`, `time-wait-only`, `occupied-non-listening` or `unknown`.
Exit codes are the interface: 0 free, 1 taken, 2 usage, 3 unknown. Unknown is a
separate number because it is a separate answer.

*Boundary:* `unknown` is not a softer `taken`. It means evidence was missing, and
the report says which table could not be read.

### Every state, every holder

All twelve TCP states the kernel names are covered, each with what it does to a
`bind()` rather than just its label. A port held by several sockets lists all of
them, and each holder carries what the process tree can prove: `creator` (it was
there first), `inherited` (it was forked with the descriptor open), `shared` (the
descriptor was passed — `/proc` cannot say who opened it). `--all` lists every row
that mentions the port with a machine-readable reason it did not take part.

*Boundary:* `shared` is never promoted to `creator`. `st=07` (CLOSE) is disclosed
but never counted as a holder — the kernel has already unhashed it, so killing
that process would not free the port.

### The probe, and the one direction it may move

`--probe` makes the bind attempt for real: a plain `bind()` and one with
`SO_REUSEADDR`, each carrying the instant it was taken. It exists for the socket
that was bound and never called `listen()` — it holds the port, a second bind gets
`EADDRINUSE`, and no table lists it at all.

*Boundary:* the probe may only make an answer more conservative (`free` →
`unknown`), never more optimistic. A successful bind is not a table, so it never
produces `free`; all it can remove is the caveat it just falsified. `SO_REUSEPORT`
is never used — it would join someone's listening group and could steal a
connection. When the tables and the probe disagree, the answer is `unknown`: the
two describe different instants and this version will not pick a side.

### The IPv6 wildcard, and the tunable behind it

`net.ipv6.bindv6only` is read and reported with its measured value. A `[::]`
listener only shadows IPv4 when that value says so, and a per-socket
`IPV6_V6ONLY` can make any single listener an exception.

*Boundary:* the tunable is a machine default, not a socket property, and no kernel
column reports the per-socket option. A bind that succeeds where the default said
it would be shadowed produces `ipv6-wildcard-turned-out-ipv6-only` and stays
`unknown` — not `free`, and not "the table is stale", which would be an invented
mechanism. Addresses are compared after `Unmap()` on both sides, so a
`::ffff:a.b.c.d` row counts as IPv4 and `[::1]` never covers `127.0.0.1`.

### The port that fails one time in fifty

A listener inside `net.ipv4.ip_local_port_range` is reported as a risk with the
range and the overlap, and `ip_local_reserved_ports` is read as a separate
question.

*Boundary:* a pool risk never changes the diagnosis or the exit code — a `free`
port in the ephemeral range is still `free`. An unreadable range file adds no
numbers to the output instead of assuming 32768–60999, and the empty reserved-ports
file (measured: nothing reserved), the malformed one (unreadable) and the missing
one (this kernel does not provide it) stay three different answers.

### Namespace and privilege, stated rather than assumed

Every answer carries the network namespace it describes, whether that is the one
pid 1 runs in, and how many processes the holder lookup could not read. Binding a
port below `ip_unprivileged_port_start` is reported as `EACCES`, a third thing
that is neither `taken` nor `free`.

*Boundary:* there is no "initial namespace" field. Inside a container pid 1 is the
container's init, so equality with it proves nothing about the host, and a field
that cannot be filled is a field a reader will believe. An unreadable
`ip_unprivileged_port_start` prints no boundary at all rather than 1024.

### UDP and unix names

`-proto udp` reads `/proc/net/udp`, and `-proto both` answers twice, once per
namespace, with the exit code taken from the TCP answer and said out loud in the
report. `portwhy unix <path|@name>` handles both the filesystem and abstract
namespaces, where the two failures look nothing like a port: a name in the way with
nobody behind it (a stale socket file — only `rm` fixes it) and a name that is free
while the table still shows a socket (`unix-name-released`).

*Boundary:* UDP has no listening state, so the answer is `bound`, never
`listening`, and `-proto udp --probe` is a usage error rather than a silent
no-op — a TCP experiment is not a UDP answer. Whether a unix socket listens is read
from `SO_ACCEPTCON`, not from the state column. `@name` is never compared with the
filesystem, and `unix` has no ephemeral pool, no privilege boundary and no probe;
passing `-sysctl` there is a usage error, because a shared flag set would make
"not supported" look like "your version is old".

### A machine-readable output that admits what it does not know

`-json` emits a documented shape with `schema_version` (the contract) separate from
`version` (the program, deliberately kept out of `evidence`). The holder query is
`{attempted, procs_read, procs_denied, error}` with the counts `null` until the walk
finishes, unreadable tables are `{name, present, error}` entries, and `-batch` reads
NDJSON targets from stdin and answers each with its own exit code.

*Boundary:* a count that was never taken is `null`, not `0`. A batch reads the
tables once, before the first line, so all its answers describe one instant and can
be compared. Exit codes are ordered by what a monitor needs to see first:
`usage(2) > unknown(3) > taken(1) > free(0)`. `-batch` refuses `-probe` (N targets
would be N real binds) and refuses `unix` (two questions, two documents), and it
says why in both cases. An empty batch is a usage error.

### Waiting, and what a deadline may not say

`portwhy wait <host:port>` polls until a plain `bind()` is accepted or the deadline
passes, re-reading the tables every round, and reports how long it waited and how
the state changed.

*Boundary:* the only source of success is an accepted bind, so a timeout can never
exit 0. `SO_REUSEADDR` is not used — it is accepted on `TIME_WAIT`, and that success
would be a lie about the plain bind the user is about to run. `EACCES` and
`EADDRNOTAVAIL` stop the wait immediately: a capability limit and "that address is
not on this machine" do not change with time. Blind rounds are counted into the
conclusion, and a successful bind still wins over an unreadable table while the
report says how many rounds it could not read. `-interval` has a 50ms floor and no
default; `-proto both` is rejected, because two namespaces and one deadline cannot
share a timeline.

### Hardening: fuzzing, property tests, and a column bound

`FuzzParse` and `FuzzDecodeAddr` cover the two parsers, `FormatAddr` has a
round-trip property, and every failing input is committed as a corpus file so an
ordinary `go test` replays it forever.

*Boundary:* a green fuzz run proves nothing about what it did not try, which is why
`make fuzz` is not part of CI — the corpus is the evidence. A line with more than
20 fields is rejected: the kernel adds columns one at a time, so a line's worth of
extra columns means two lines were concatenated, and accepting it would hand a
`free` to the port whose row was dropped. Test fixtures are generated by
`FormatAddr`; a hand-written one with the wrong address width made a `tcp6` table
unparseable for eight days while its test compared unknown with unknown.

### The documents are checked, and so are the commands in them

`internal/docs` verifies that every relative link resolves, every repository path
in inline code exists, and the README reaches the design and the schema. It fails
closed: an unreadable README or an empty `docs/` is an error, not a clean report.
The JSON schema document is compared against the Go types field by field, in both
directions. `make readme` executes all 26 commands the README prints and asserts
their exit codes, and the benchmarks that the design document quotes are
`go test -bench`, so anyone can re-run them.

*Boundary:* the gate's own report carries counts (`Links`, `Paths`), because "no
problems" and "nothing scanned" are the same sentence otherwise. The rehearsal
injects tables and tunables and binds its own sockets; it never reads the host's
state, and it does not grep prose — wording may improve without turning CI red.

### One release, one spelling

A binary learns its version from `-ldflags` (what `make build` injects) or from
module build info (what `go install module@v1.0.0` leaves). Both paths now produce
the same string, and how much of a commit is printed is decided in one place.
`make release-check` asserts the whole chain — the tag is at HEAD, this file starts
at that tag, and a binary built there prints it.

*Boundary:* a field that cannot be established stays empty rather than becoming
`unknown` or `0`; an unbuilt binary says `dev` and does not borrow an identity from
the checkout it grew up in.

## Not in this release

No `--kill`, no sysctl advice (the internet still recommends `tcp_tw_recycle`,
removed in Linux 4.12), and no test that holds the target port by really listening
on it — that would change the state being measured. Zero third-party dependencies
is a gate in CI, not a preference: a diagnostic tool gets run on broken hosts, where
a module download is not available. Linux only; the whole answer comes from `/proc`,
and the other platforms compile but refuse at runtime instead of returning an empty
result that reads as `free`.
