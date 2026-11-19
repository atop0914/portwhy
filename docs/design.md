# Design and capability boundary

This document exists before the rest of the code because the boundary is the
product. A diagnostic tool is trusted for the answers it refuses to give as much
as for the ones it gives.

## 1. The question

`bind()` returned `EADDRINUSE`. Which of these is true?

1. A process is listening on that exact address.
2. A process is listening on a wildcard that covers that address
   (`0.0.0.0`, or `[::]` depending on `net.ipv6.bindv6only` — which this version
   measures instead of guessing).
3. Nothing is listening, and the address is reserved by a `TIME_WAIT` row left
   by a closed connection.
4. A socket holds the address in a non-listening state (`ESTABLISHED`,
   `FIN_WAIT1`, `CLOSE_WAIT`), and whether that blocks the bind depends on
   socket options.

The four have different fixes. `ss -ltnp` shows raw rows and leaves the
classification to the reader, which is why the same question gets asked again
every week.

## 2. What each judgement rests on

| kind | evidence | what would make it wrong |
|---|---|---|
| `free` | every relevant table was read successfully and no row occupies the address | a socket in an unread table; a namespace we cannot see; a bind that fails for a reason other than the address being held (`EACCES` below 1024, `EADDRNOTAVAIL`) |
| `listening` | a row in `LISTEN` whose local address covers the query | nothing: the row is the state |
| `time-wait-only` | rows in `TIME_WAIT` and nothing else | a non-`TIME_WAIT` row in an unread table |
| `occupied-non-listening` | rows in another bound state | whether the bind actually fails: it may not, if `SO_REUSEADDR`/`SO_REUSEPORT` is set. Without a probe this version reports the occupation and says the consequence is unverified; with `--probe` the consequence is measured, and a successful bind becomes a conflict rather than a quiet contradiction |
| `unknown` | a table that should exist could not be read, or an IPv6 wildcard may be shadowing IPv4 and `bindv6only` could not be read | nothing: `unknown` is the honest floor |

The `free` row carries the risk. It is the only kind that tells a user "go
ahead", so every hole in the evidence must collapse it into `unknown` first.

### The state table

Each of the twelve TCP states carries three things: the kernel's own spelling, what
it means for a later `bind()`, and one clause saying why. `portwhy states` prints
it; `internal/procnet/state.go` is it. It is a table rather than a chain of
comparisons because "what does this state do to my bind" is the question, and a
table can be read against `man 7 tcp` in one pass.

| effect | states | what a `bind()` does |
|---|---|---|
| `blocks` | `LISTEN` | fails with `EADDRINUSE`; `SO_REUSEPORT` can share the port, but only between sockets that both asked for it |
| `options-decide` | the other ten bound states | the port is held; whether the bind fails depends on `SO_REUSEADDR` and on whether the holder set it too |
| `teardown` | `CLOSE` | already released by the kernel: it does not explain an `EADDRINUSE` now |
| `unknown` | any code this build does not know | nothing can be claimed, so the answer becomes `unknown` |

Two consequences are deliberate. An unrecognised state code degrades the whole
answer to `unknown` instead of being counted as occupation: a state the tool cannot
describe is a hole in the evidence, and `UNKNOWN(0x..)` in the output is the tool
saying so. And `CLOSE` is not a holder — the row is disclosed in the reasons and
left out of the holders list, because naming a process for a socket the kernel has
released sends the reader off to kill something that is already gone.

### The probe, and the one direction it may move

The probe is the only evidence that can contradict the tables, so the direction it
is allowed to move the answer is fixed in code, not in prose: **it may make the
answer more cautious, never more optimistic.**

| tables said | plain bind | outcome | why |
|---|---|---|---|
| `free` | refused `EADDRINUSE` | `unknown` | the tables cannot see a socket bound without `listen()`; one `bind()` can |
| `free` | accepted | `free`, caveat removed | the blind spot was tested at that instant and did not materialise |
| `free` | `EACCES` / `EADDRNOTAVAIL` / not run | `unknown` | the probe did not answer; a non-answer is not a free port |
| `listening`, `time-wait-only`, `occupied` | refused `EADDRINUSE` | unchanged | corroboration, and nothing more |
| `time-wait-only` | refused, `SO_REUSEADDR` accepted | unchanged | the option is the fix, and it is named as tried, not recommended |
| `listening`, `time-wait-only`, `occupied` | accepted | `unknown` | the tables were read first, so the two describe different instants |

Nothing enters the `free` column from any row that was not already `free`. That is
what keeps the probe from becoming a second opinion that can be talked into a
reassuring answer.

### The IPv6 wildcard: one tunable, three answers

Day 1 answered this shape with `unknown` and said why: whether `[::]` also holds an
IPv4 address is `net.ipv6.bindv6only`, `/proc/net` does not report it, and an
unverified `free` is the one answer this tool must never give. The fix was not to
model the question better but to measure the input, the same way the probe is an
input: `internal/sysctl` reads the file, `Env.V6Only` carries the value, and the
judgement stays a pure function.

| measured | what it means here | kind |
|---|---|---|
| `0` | a `[::]` socket is dual-stack by default, so the wildcard holds the IPv4 address too | `listening`, row added with owners, plus the per-socket limit |
| `1` | `[::]` is IPv6 only; the IPv4 address is untouched | the base classification stands, and the value is printed |
| unreadable | nothing was measured | `unknown` — unless an IPv4 listener already settles it, in which case the listener wins |

Three details are deliberate:

- **The value is always printed with its source file.** A number a verdict rests
  on has to be checkable, and "bindv6only" without a value is the folklore this
  tool replaces.
- **`unknown` outranks `free` but not a known listener.** If an IPv4 listener is
  in the table, the question about a tunable does not matter: a listener blocks
  regardless. Downgrading that to `unknown` would trade a fact for a gap.
- **The per-socket limit travels with the shadow claim.** `bindv6only` is the
  default for new sockets; a program can call `setsockopt(IPV6_V6ONLY, 1)` for
  itself and the kernel exposes no column for it. So the shadow is reported as
  "true unless that socket opted out", and `--probe` is named as the way to settle
  it. A refused plain bind removes the limit; a successful one replaces the whole
  claim with the opt-out diagnosis (`ipv6-wildcard-turned-out-ipv6-only`) rather
  than blaming a stale table, because both observations describe the same instant.

Address comparison follows `bind()` rather than the string form: both sides are
`Unmap()`ed first, so a `tcp6` row holding `::ffff:127.0.0.1` is compared as the
IPv4 address it is, and a specific `[::1]` never covers `127.0.0.1` in any setting.
Getting the first one wrong answers `free` about a port that is plainly taken;
getting the second one wrong invents a conflict that does not exist.

## 3. Capability boundary

### What the data sources can prove

- `/proc/net/tcp`, `tcp6`, `udp`, `udp6`: which local addresses and ports are
  reserved in **this network namespace**, in which state, and (for sockets that
  have a file descriptor) the inode that names them. Proven by test: a listener
  opened in the test binary is found at the address it asked for, in `LISTEN`
  (`internal/procnet/live_test.go`).
- `/proc/<pid>/fd/*` symlinks: which process holds which socket inode, and how
  many processes we were not allowed to look inside. Proven by test: the inode of
  a real listener is attributed back to the test process, and a closed socket
  stops being attributed (`internal/sockid/scan_linux_test.go`).
- The `bind()` consequence of every state, from one table that is asserted against
  the kernel's own twelve state codes rather than sampled
  (`internal/procnet/state_test.go`).
- Which of several holders had a shared socket first, as far as the process tree
  can say: a shared socket arrives through `fork()`, so a holder that is an
  ancestor of the others must precede them. Proven with a real forked child
  (`internal/sockid/scan_linux_test.go`, `cmd/portwhy/main_rows_linux_test.go`).

### What they cannot prove

- **Other network namespaces.** A port held on the host is invisible inside a
  container, and vice versa. A `free` answer is therefore always "free *here*".
  This tool does not claim otherwise anywhere in its output.
- **The age of a socket.** The kernel does not expose when a `TIME_WAIT` row was
  created, so "released in 43 s" would be a fabrication. Refused.
- **Whether `[::]` occupies IPv4, in general.** The machine-wide default is
  readable and now read, so this tool can answer it for an ordinary listener. What
  remains unknowable is the per-socket case: `setsockopt(IPV6_V6ONLY)` is not in
  any table. The report states that limit next to the claim, and `--probe` is the
  only thing that settles it.
- **Why a specific `bind()` failed.** `EACCES` (privileged port), `EADDRNOTAVAIL`
  (address not on any interface) and `EADDRINUSE` are three different errors that
  arrive as the same failure to a user. Tables can only classify the address; with
  `--probe` the errno is read directly, and every errno that is not `EADDRINUSE`
  is treated as "the probe did not answer", never as "so the port is free".
- **Whether the holder is the one you care about.** A forked worker inherits its
  parent's listener; both are reported, and choosing between them is the user's
  job.
- **A socket that was bound and never listened.** It holds the port — a second
  `bind()` fails with `EADDRINUSE` — and it has no row in any `/proc/net` table,
  because those tables iterate only the connection and listener hashes. This is
  measured, not assumed (`cmd/portwhy/live_linux_test.go`), and it is why every
  `free` answer carries the `bind-without-listen-not-listed` caveat. Only a bind
  attempt can close it: with `--probe`, a refused plain bind collapses `free` into
  `unknown` and the caveat becomes the diagnosis (`cmd/portwhy/probe_linux_test.go`).
- **Who opened a shared socket when the descriptor was passed.** A role is derived
  from the process tree, which proves descent and nothing else. When several
  holders are unrelated (systemd socket activation hands the listener to a service
  that is not its child), the report says `shared` and stops there.

### Deliberately not done

- No `--kill`. A port diagnostic is the wrong place to hide a destructive action.
- No listening on the port to "test" it. That changes the state it is measuring.
- No sysctl advice. `tcp_tw_recycle` was removed in Linux 4.12 and suggestions
  to set it outlive the feature; this tool does not repeat folklore.
- No support for macOS or Windows. The binary compiles there and refuses at
  runtime, because an empty report would be read as "free".

## 4. Layers and the invariant

```
internal/procnet   files → []Socket          (pure over an io.Reader)
internal/sysctl    tunables → measured value (0, 1, or unreadable)
internal/sockid    inodes → holders          (the only /proc/<pid> walker)
internal/probe     address → []Attempt       (real bind(); never listen())
internal/verdict   []Socket + evidence → Kind (pure; evidence is an argument)
cmd/portwhy        rendering, exit codes
```

The invariant worth defending: **`internal/verdict` never touches the system.**
Every conclusion is a function of rows and attempts it was given. That is what
makes the false-positive and false-negative cases testable without a socket, and
it is why the exit-code contract can be argued about without a machine. The probe
is deliberately on the other side of that line: it produces evidence, the verdict
consumes it, and `Explain` never runs one.

The second invariant: **a missing table is not an unreadable table.** A kernel
without IPv6 has no `tcp6`; that hides nothing about an IPv4 question and must
not degrade the answer. A `tcp` table that exists but returns a permission error
is a hole, and must degrade `free` to `unknown`.

## 5. The assertions that must never regress

Each of these is a test today, and each is a way the tool could become harmful:

- A listener on `127.0.0.1:8080` must not be reported for `10.1.2.3:8080`.
- A listener on `8080` must not be reported for `8081`.
- A UDP socket on `8080` must not block a TCP `8080`.
- A `TIME_WAIT` row must not be reported as a listener: the fixes differ.
- A `TIME_WAIT` row must never be given an owner.
- An unreadable table must produce exit 3, never exit 0.
- A `[::]` listener on the port must produce `unknown`, never `free`, when
  `bindv6only` could not be read. With `bindv6only=1` the same row must not be a
  holder at all; with `0` it must be one — and in both cases the measured value and
  its source file must be printed.
- A specific `[::1]` listener must never be reported for `127.0.0.1`, whatever
  `bindv6only` says.
- A successful bind on a port whose only evidence was a shadow must replace that
  claim with the per-socket opt-out diagnosis. Two contradictory sentences in one
  report are worse than a gap.
- The zero value of the measured tunable must never read as `0`: a caller that
  forgot to measure has to land on `unknown`.
- An IPv4-mapped target (`[::ffff:127.0.0.1]:8080`) must be compared as IPv4,
  or the answer is `free` for a port that is plainly taken.
- An unrecognised state code must produce `unknown`, never `occupied` and never
  `free`: the tool cannot describe the row, so it cannot judge it.
- A row the kernel has already released must be disclosed and must not appear in
  the holders list. Naming a process there is an accusation against a socket that
  no longer exists.
- `--all` must not change the kind or the exit code. It is compared byte for byte
  on the `kind` field, over a matrix of neighbour shapes
  (`cmd/portwhy/main_rows_linux_test.go`).
- A `free` answer without the `bind-without-listen-not-listed` caveat is a
  regression: that is the one blind spot the tables have, and the one answer it can
  invalidate.
- A refused bind on a port no table lists must turn `free` into `unknown`, and the
  caveat must stop being printed as a limits line once it is the diagnosis.
- A successful plain bind must not promote anything to `free` — it may only
  subtract the caveat it just disproved.
- A probe that could not run (`EACCES`, `EADDRNOTAVAIL`, `socket()` or `close()`
  failure) must never leave `free` standing.
- `SO_REUSEADDR` must not be recommended unless the option attempt actually
  succeeded: one attempt is not the two-attempt diagnosis, and the refusal must be
  reported as "the option does not help here".
- A probe result must carry the instant it was taken, in text and in JSON, and no
  output may offer a guarantee.

## 6. What the probe does, and what is still later

The probe binds twice — plain, then `SO_REUSEADDR` — and reports the errno and the
instant of each attempt. Two rather than four, on purpose:

- `SO_REUSEPORT` is not attempted. Joining an existing listener's group can steal
  a connection for the duration of the probe, and that is a side effect this
  version is not willing to cause silently.
- An IPv6-only attempt is not made. Whether `[::]` shadows IPv4 is answered by
  reading `net.ipv6.bindv6only`, and a fourth attempt would only measure the one
  case the tunable cannot describe (a socket that opted out) — which the shadow
  claim already names as its limit and which any plain bind on the IPv4 address
  settles for free.

What the two attempts settle today: whether a `TIME_WAIT` row blocks a plain bind
here, whether the option unblocks it, and which errno a bind really returns. Since
Day 4 they also settle the per-socket IPv6 question, asymmetrically: a bind that
succeeds proves the wildcard opted out, while a bind refused with `EADDRINUSE`
proves only that something holds the address — not that the wildcard does. What
they do not settle: anything about a `bind()` that happens after the probe — which
is why the report prints the instant instead of a verdict about the future.

Two rules for this work, decided before it was written so they were not decided
under pressure:

- The probe is **opt-in** (`--probe`). Without it the report is byte-identical to
  the table-only version, and the exit-code contract does not change.
- A probe result is labelled with the moment it was taken. Between the probe and
  the user's own `bind()`, the state can change; the report must not present a
  probe as a guarantee.
