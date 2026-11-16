# portwhy

Explain why a port cannot be bound — from the kernel's own tables, with the
names of the processes holding it, and with "I could not tell" as a distinct
answer.

```
$ portwhy why 127.0.0.1:8080
127.0.0.1:8080/tcp — a listening socket holds it

holders
  LISTEN         127.0.0.1:8080         pid 892 (python3) fd 3       inode 29866188

why
  - bind() to an address a listener holds fails with EADDRINUSE

limits
  - no bind was attempted: this verdict comes from kernel state only
  - holder lookup walked 3 process(es), 0 not readable
```

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
portwhy version
```

| flag | meaning |
|---|---|
| `-proto tcp\|udp` | which protocol to check (default `tcp`) |
| `-json` | machine-readable report on stdout |
| `-no-holders` | skip the `/proc/<pid>/fd` walk: kernel state only |
| `-tables DIR` | read the socket tables from DIR instead of `/proc/net` |
| `-proc ROOT` | use ROOT instead of `/proc` when naming the holder |

`:8080` means every interface (`0.0.0.0:8080`). `[::1]:8080` is IPv6.

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

## What it does not do

Written down because the boundary is the product:

- **It does not attempt the bind.** This version decides from kernel state only,
  and says so in every report. An empirical probe (`bind()` with and without
  `SO_REUSEADDR`, reporting what actually happened instead of what should have)
  is the next capability, and until it exists nothing here claims to have
  tested a bind.
- **It does not see other network namespaces.** Inside a container, a port held
  on the host is invisible. The report describes the namespace it ran in; it
  never claims a port is free on the machine.
- **It does not estimate how long a `TIME_WAIT` will last.** The kernel does not
  expose the age of a socket, so any "12 seconds left" would be invented.
- **It does not name the holder of a `TIME_WAIT` row.** Those rows carry inode 0
  — there is no file descriptor behind them, so there is no process to name.
  The report says exactly that instead of showing an empty owner column.
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
                        ↓
                  internal/verdict      classification, pure function
                        ↓
                  cmd/portwhy           text / JSON, exit codes
```

Only `internal/procnet` and `internal/sockid` touch the system; `internal/verdict`
is a pure function over rows, which is why the four causes above can be tested
without opening a socket. See [docs/design.md](docs/design.md) for the decisions
behind that split and the cases this version deliberately refuses to answer.
