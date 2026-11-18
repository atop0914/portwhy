# portwhy

Explain why a port cannot be bound — from the kernel's own tables, with the
names of the processes holding it, and with "I could not tell" as a distinct
answer.

```
$ portwhy why 127.0.0.1:8080
127.0.0.1:8080/tcp — a listening socket holds it

holders
  LISTEN         127.0.0.1:8080         pid 892 (python3) fd 3 [sole] inode 29866188

why
  - bind() to an address a listener holds fails with EADDRINUSE

limits
  - no bind was attempted: this verdict comes from kernel state only
  - holder lookup walked 3 process(es), 0 not readable
```

When a listener is shared, every holder is listed with what the process tree proves
about it: `creator` (it was there first — talk to this one), `inherited` (it was
forked with the descriptor open — killing it leaves the port taken), or `shared`
(the descriptor was passed, so /proc cannot say who opened it).

`--all` lists every row that mentions the port, each with a machine-readable reason
it did or did not take part (`matched`, `released`, `other-port`, `other-proto`,
`other-family`, `other-address`, `wildcard-shadowed`). It changes nothing else: the
verdict and the exit code are computed before a single row is added.

## The one thing no table can show

`/proc/net/tcp` lists sockets that are connected or listening. A socket that was
bound and never called `listen()` holds the port — a second `bind()` gets
`EADDRINUSE` — and appears in no table at all. `--probe` makes the attempt for
real, twice:

```
$ portwhy why 127.0.0.1:43569 --probe
127.0.0.1:43569/tcp — cannot be determined from what was readable

why
  - no row in the read tables matches this address
  - a plain bind was refused while no row covers the address: something bound this
    port without listen(), and no table lists it (a plain bind returned EADDRINUSE
    at 2026-11-18T12:41:42Z)

probe
  plain      at 2026-11-18T12:41:42Z  EADDRINUSE (address already in use)
  reuseaddr  at 2026-11-18T12:41:42Z  EADDRINUSE (address already in use)
  what these attempts found at those instants only; anyone may take or release
  the port afterwards, so none of it is a promise. listen() was never called and
  every socket was closed immediately.
```

The exit code moved from 0 to 3, and that is the point: `free` was a claim the
tables could not support, and one `bind()` disproved it.

The same two attempts answer what a `TIME_WAIT` row raises, and the difference
between them is the diagnosis:

```
$ portwhy why 127.0.0.1:44433 --probe
127.0.0.1:44433/tcp — only TIME_WAIT rows hold it

holders
  TIME_WAIT      127.0.0.1:44433        no open descriptor           inode 0

why
  - the reservation belongs to a closed connection, not to a running process
  - SO_REUSEADDR is what unblocks it — both attempts were made, and only the
    option one was accepted (plain refused with EADDRINUSE, SO_REUSEADDR bound at
    2026-11-18T12:41:56Z)

probe
  plain      at 2026-11-18T12:41:56Z  EADDRINUSE (address already in use)
  reuseaddr  at 2026-11-18T12:41:56Z  bind succeeded, socket closed immediately
```

Three properties make that safe to run against a service you care about:

- **Opt-in.** Without `--probe` the report and the exit code are exactly what they
  were before the flag existed.
- **It never listens.** A bound socket that never listens accepts nothing, and the
  descriptor is closed by the same function that opened it. `SO_REUSEPORT` is not
  set: joining an existing listener's group could steal a connection.
- **It can only make the answer more cautious, never more optimistic.** A probe
  may turn `free` into `unknown`; it may never turn anything into `free`, because
  that word means every table was read and nothing holds the address. The one
  thing a successful bind subtracts is the `bind-without-listen` caveat it has
  just disproved at that instant.

## Why another one

`ss` and `lsof` list sockets. They do not answer the question people actually
have, which is *which of the four different things* is wrong:

| what you see | what it means | what fixes it |
|---|---|---|
| a listener on the same address | a process is serving there | stop it, or use another port |
| only `TIME_WAIT` rows | a closed connection still reserves the port | a socket option, or wait out 2×MSL |
| a listener on `0.0.0.0` while you asked for one interface | the wildcard covers you | same as the first row |
| a listener on `[::]` while you asked for IPv4 | maybe: it depends on `net.ipv6.bindv6only` | verified, not assumed |

The fourth row is why this tool exists. Most advice on the internet collapses all
of these into "kill the process or set `SO_REUSEADDR`", and part of that advice is
wrong on modern systems: Go sets `SO_REUSEADDR` on listeners by default, so a
`TIME_WAIT` row often does not block a Go server at all. A tool that repeats the
folklore is worse than no tool.

Two things follow from that, and they are the design:

1. **The answer is a classification, not a port listing.** `free`, `listening`,
   `time-wait-only`, `occupied-non-listening`, `unknown` are different
   diagnoses with different fixes.
2. **Absence of evidence is reported as such.** If a socket table could not be
   read, or a process could not be inspected, the result is `unknown` (exit 3),
   never `free`. `free` is a claim, and this tool only makes claims it can
   support.

## Install

```
go install github.com/atop0914/portwhy/cmd/portwhy@latest
```

Zero third-party dependencies, no cgo. Linux only: the whole answer comes from
`/proc`.

## Usage

```
portwhy why <host:port> [flags]
portwhy states
portwhy version
```

| flag | meaning |
|---|---|
| `-proto tcp\|udp` | which protocol to check (default `tcp`) |
| `-json` | machine-readable report on stdout |
| `-all` | also list every row that mentions the port, with why it did or did not take part (the verdict does not change) |
| `-probe` | attempt a real `bind()` twice — plain, then `SO_REUSEADDR` — and report what the kernel answered. Never calls `listen()`. tcp only |
| `-no-holders` | skip the `/proc/<pid>/fd` walk: kernel state only |
| `-tables DIR` | read the socket tables from DIR instead of `/proc/net` |
| `-proc ROOT` | use ROOT instead of `/proc` when naming the holder |

`:8080` means every interface (`0.0.0.0:8080`). `[::1]:8080` is IPv6.

`portwhy states` prints the twelve TCP states with what each one does to a
`bind()`, so the rule behind a verdict can be read instead of inferred.

### Exit codes

These are the contract, and the third one is the reason the contract exists:

| code | meaning |
|---|---|
| 0 | free — every relevant table was read and nothing occupies it |
| 1 | taken — a listener, a `TIME_WAIT` reservation, or another socket holds it |
| 2 | usage or internal error |
| 3 | unknown — the evidence needed was missing. **This is not "free".** |

A script that treats every non-zero code as "taken" will do the wrong thing on
3. That is intentional: it is the code saying it did not get to look.

With `--probe`, a 0 can become a 3: the tables said nothing held the address and
a `bind()` proved otherwise. The other direction never happens — no flag turns a
3 into a 0.

## What it does not do

Written down because the boundary is the product:

- **It does not attempt the bind unless you ask.** Without `--probe` every report
  says so, because a verdict from tables alone is a different kind of claim from
  one that was tested. With `--probe` it makes two attempts and prints the errno
  and the instant of each.
- **It does not probe UDP.** UDP has no listener to be refused by and no
  `TIME_WAIT` to wait out, so a TCP-style probe would be a different experiment
  reported as the answer to this one. `-proto udp` with `--probe` is rejected.
- **It does not see other network namespaces.** Inside a container, a port held
  on the host is invisible. The report describes the namespace it ran in; it
  never claims a port is free on the machine.
- **It does not estimate how long a `TIME_WAIT` will last.** The kernel does not
  expose the age of a socket, so any "12 seconds left" would be invented.
- **It does not name the holder of a `TIME_WAIT` row.** Those rows carry inode 0
  — there is no file descriptor behind them, so there is no process to name.
  The report says exactly that instead of showing an empty owner column. The same
  holds for a socket you closed that is still waiting out its timeout.
- **It cannot see a socket that was bound without `listen()` by reading tables.**
  That socket holds the port (a second `bind()` fails with `EADDRINUSE`) and
  appears in no `/proc/net` table, because those tables only iterate the connection
  and listener hashes. So a `free` answer always carries that caveat. `--probe` is
  what closes the gap, and it closes it only for the instant it ran.
- **It does not resolve `net.ipv6.bindv6only` yet.** A `[::]` listener on the queried
  port still forces `unknown`, even with `--probe`: a successful IPv4 `bind()` shows
  that IPv4 was free, but this version has no model for the shadow question, so it
  does not upgrade the answer. Measuring the flag is the next capability.
- **It refuses addresses it cannot express.** A scoped IPv6 address (`[fe80::1%eth0]`)
  is rejected rather than approximated, because resolving a zone name to an index
  needs a dependency this project does not take.
- **It does not kill anything.** No `--force`, no `--kill`, on purpose: a port
  diagnostic is the wrong place to hide a destructive action.
- **It does not run on macOS or Windows.** `portwhy` exits with an explicit
  "socket tables are only available on Linux" rather than printing an empty
  report. The binary compiles on those platforms so that cross-compilation and
  `go vet` keep working; it refuses at runtime.

## How it works

```
/proc/net/tcp{,6}, /proc/net/udp{,6}   → internal/procnet   rows, addresses, states
/proc/<pid>/fd/* → "socket:[inode]"    → internal/sockid    who holds which inode
bind() twice, never listen()           → internal/probe     what the kernel does now
                        ↓
                  internal/verdict      classification, pure function
                        ↓
                  cmd/portwhy           text / JSON, exit codes
```

Only `internal/procnet`, `internal/sockid` and `internal/probe` touch the system;
`internal/verdict` is a pure function over rows and injected evidence, which is
why the four causes above — and every way the probe can contradict them — can be
tested without opening a socket. See [docs/design.md](docs/design.md) for the
decisions behind that split and the cases this version deliberately refuses to
answer.
