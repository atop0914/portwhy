# Design and capability boundary

This document exists before the rest of the code because the boundary is the
product. A diagnostic tool is trusted for the answers it refuses to give as much
as for the ones it gives.

## 1. The question

`bind()` returned `EADDRINUSE`. Which of these is true?

1. A process is listening on that exact address.
2. A process is listening on a wildcard that covers that address
   (`0.0.0.0`, or `[::]` depending on `net.ipv6.bindv6only`).
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
| `occupied-non-listening` | rows in another bound state | whether the bind actually fails: it may not, if `SO_REUSEADDR`/`SO_REUSEPORT` is set. This version reports the occupation and says the consequence is unverified |
| `unknown` | a table that should exist could not be read, or an IPv6 wildcard may be shadowing IPv4 | nothing: `unknown` is the honest floor |

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
- **Whether `[::]` occupies IPv4.** It depends on `net.ipv6.bindv6only`, which
  `/proc/net` does not report. Until a probe settles it, a `[::]` listener on
  the queried port turns `free` into `unknown` — it never silently shadows, and
  it never silently allows.
- **Why a specific `bind()` failed.** `EACCES` (privileged port), `EADDRNOTAVAIL`
  (address not on any interface) and `EADDRINUSE` are three different errors that
  arrive as the same failure to a user. Only a probe can distinguish them; this
  version classifies the address, not the error.
- **Whether the holder is the one you care about.** A forked worker inherits its
  parent's listener; both are reported, and choosing between them is the user's
  job.
- **A socket that was bound and never listened.** It holds the port — a second
  `bind()` fails with `EADDRINUSE` — and it has no row in any `/proc/net` table,
  because those tables iterate only the connection and listener hashes. This is
  measured, not assumed (`cmd/portwhy/live_linux_test.go`), and it is why every
  `free` answer carries the `bind-without-listen-not-listed` caveat. Only a probe
  can close it.
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
internal/sockid    inodes → holders          (the only /proc/<pid> walker)
internal/verdict   []Socket + query → Kind   (pure; injected holder lookup)
cmd/portwhy        rendering, exit codes
```

The invariant worth defending: **`internal/verdict` never touches the system.**
Every conclusion is a function of rows it was given. That is what makes the
false-positive and false-negative cases testable without a socket, and it is why
the exit-code contract can be argued about without a machine.

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
- A `[::]` listener on the port must produce `unknown`, never `free`.
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

## 6. What changes later

The probe (a later capability) will `bind()` four ways — plain, `SO_REUSEADDR`,
`SO_REUSEPORT`, and IPv6-only — and report what the kernel actually did. That
turns three current uncertainties into facts: whether a `TIME_WAIT` row blocks
this program, whether `[::]` shadows IPv4 here, and which errno the bind really
returns. It also closes the blind spot the tables have by construction: a port that
looks free but is held by a socket that was bound without `listen()`.

Two rules for that work, decided now so they are not decided under pressure:

- The probe is **opt-in** (`--probe`), because `SO_REUSEPORT` can join an
  existing listener's group and steal a connection for the duration of the probe.
- A probe result is labelled with the moment it was taken. Between the probe and
  the user's own `bind()`, the state can change; the report must not present a
  probe as a guarantee.
