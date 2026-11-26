# portwhy

Explain why a port cannot be bound — from the kernel's own tables, with the
names of the processes holding it, and with "I could not tell" as a distinct
answer.

The same question is answered for a unix socket name, where the two failures look
nothing like a port: a name can be in the way with nobody behind it, and a name
can be free while the table still shows a socket.

```
$ portwhy why 127.0.0.1:8080
127.0.0.1:8080/tcp — a listening socket holds it
scope: net:[4026532486], this process's network namespace, the same one pid 1 runs in
  the tables read here cover one network namespace; a holder in another one cannot be ruled out

holders
  LISTEN         127.0.0.1:8080         pid 892 (python3) fd 3 [sole] inode 29866188

why
  - bind() to an address a listener holds fails with EADDRINUSE

limits
  - no bind was attempted: this verdict comes from kernel state only
  - holder lookup walked 3 process(es), 0 not readable
```

The `scope` pair is not decoration: "nothing holds this port" is only ever true of
one network namespace. The tool reads exactly one and says which, instead of
letting a container's answer read as the machine's.

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
scope: net:[4026532486], this process's network namespace, the same one pid 1 runs in
  the tables read here cover one network namespace; a holder in another one cannot be ruled out

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
scope: net:[4026532486], this process's network namespace, the same one pid 1 runs in
  the tables read here cover one network namespace; a holder in another one cannot be ruled out

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

## The one question one tunable answers

`[::]:8080` on its own decides nothing: whether it also holds `127.0.0.1:8080`
is `net.ipv6.bindv6only`, and no socket table reports it. This version reads the
tunable and prints what it found:

```
$ portwhy why 127.0.0.1:18080
127.0.0.1:18080/tcp — a listening socket holds it
scope: net:[4026532486], this process's network namespace, the same one pid 1 runs in
  the tables read here cover one network namespace; a holder in another one cannot be ruled out

holders
  LISTEN         [::]:18080             pid 170 (server) fd 4 [sole]     inode 42451711

why
  - the IPv6 wildcard listener holds this IPv4 address too: this host runs with
    bindv6only=0, so a [::] socket is dual-stack ([::]:18080;
    net.ipv6.bindv6only = 0, read from /proc/sys/net/ipv6/bindv6only)

limits
  - bindv6only is the default for new sockets, not a property of an existing one:
    a listener that set IPV6_V6ONLY for itself would leave IPv4 free, and only
    -probe can tell which
```

On a host with `bindv6only=1` the same row is not a holder at all, and the answer
returns to `free` — quoting `= 1` and the file it came from, so the number can be
checked instead of trusted. When the tunable cannot be read (no IPv6, a hidden
mount, a file that does not contain `0` or `1`), the answer stays `unknown`: a
default is not a measurement.

The `limits` line above is not decoration. That particular blind spot — a socket
that opted out of dual-stack for itself — is real, and `--probe` is what settles
it:

```
$ portwhy why 127.0.0.1:18082 --probe     # [::] bound as tcp6, so V6ONLY for that socket
127.0.0.1:18082/tcp — cannot be determined from what was readable
scope: net:[4026532486], this process's network namespace, the same one pid 1 runs in
  the tables read here cover one network namespace; a holder in another one cannot be ruled out

why
  - the wildcard looked dual-stack but a bind succeeded: that listener is
    IPv6-only for itself, an option the kernel reports nowhere, so this version
    does not promote the answer to free (a plain bind succeeded at
    2026-11-19T12:41:45Z although [::]:18082 is listening on this port)
```

Exit 3, not 0: the port is bindable at that instant, and "bindable now" is not
what `free` means here.

## The port that fails one time in fifty

A fixed port that binds every day, then one morning answers `EADDRINUSE` and
works again after a restart, is usually not being held by anything. It sits
inside `net.ipv4.ip_local_port_range`, the pool the kernel draws *outbound*
connection source ports from — so every so often one of the machine's own
connections takes the port first.

```
$ portwhy why 127.0.0.1:46883
127.0.0.1:46883/tcp — nothing in the kernel tables occupies it
scope: net:[4026532486], this process's network namespace, the same one pid 1 runs in
  the tables read here cover one network namespace; a holder in another one cannot be ruled out

why
  - no row in the read tables matches this address
  - this port is inside the kernel's ephemeral range: an outbound connection may
    take it as its source port, which is why a fixed listener here fails only
    sometimes — a port a long-lived service depends on belongs outside that range
    (46883 is inside 32768-60999 read from /proc/sys/net/ipv4/ip_local_port_range;
    net.ipv4.ip_local_reserved_ports does not exclude it)
```

The exit code is still 0 and the kind is still `free`. That is deliberate: this
port is bindable right now, and turning "occasionally taken" into `taken` would
be the false positive that kills a diagnostic tool. The risk is printed as a
reason, not as a verdict, and the interval is printed with the file it came
from.

The mechanism is not folklore. While a connection from that port is open, a
`bind()` to it really does fail:

```
outbound connection established from 127.0.0.1:46883
while that connection is open, bind() to port 46883 returned: address already in use
```

and once the connection closes, the port is left in `TIME_WAIT` — which is why
"restart and it works" is the usual experience. A host that has excluded the
port from the pool says so instead:

```
  - this port is excluded from the ephemeral range: the kernel will not take it
    as an outbound source port, so the occasional EADDRINUSE from the pool cannot
    come from here (46883 is listed in /proc/sys/net/ipv4/ip_local_reserved_ports;
    the ephemeral range this host measured is 32768-60999
    (/proc/sys/net/ipv4/ip_local_port_range))
```

Both of those intervals are measurements. When the range cannot be read — a
hidden mount, a file holding `abc`, a range that ends before it starts — the tool
says so and prints no interval at all:

```
limits
  - the ephemeral range could not be read, so whether the kernel may take this
    port for an outbound connection was not measured — the range Linux usually
    has is not a measurement of this host
    (net.ipv4.ip_local_port_range is unreadable
    (/proc/sys/net/ipv4/ip_local_port_range): "abc" is not two port numbers)
```

`32768-60999` appears nowhere in that output, on purpose: those numbers are the
most common range, not this host's range, and a report that prints them for a
host it never read is exactly the confident wrong answer this tool exists to
replace.

## The port that is bound and never listens

A UDP socket never listens. `bind()` takes the port, `connect()` remembers a
peer, and there is nothing in between — but the port is held all the same, and a
second plain `bind()` fails exactly as it does over TCP:

```
$ portwhy why -proto udp 127.0.0.1:53535
127.0.0.1:53535/udp — a bound socket holds it (udp has no listening state)
scope: net:[4026532486], this process's network namespace, the same one pid 1 runs in
  the tables read here cover one network namespace; a holder in another one cannot be ruled out

holders
  CLOSE          127.0.0.1:53535        pid 1232 (hold) fd 4 [sole]  inode 46961390

why
  - a UDP socket is bound to this address and keeps the port to itself: a second
    plain bind() fails with EADDRINUSE, and the fix is to find that process — or,
    if both sides agree to it, to share the port with SO_REUSEADDR
```

`CLOSE` there does not mean what it means in TCP. `/proc/net/udp` and
`/proc/net/tcp` share one state column, and `0x07` reads in opposite directions:
in TCP it is `CLOSE`, a socket the kernel has already unhashed and which blocks
nothing; in UDP it is "bound and not connected", the ordinary state of a bound
UDP socket — and it blocks a plain `bind()`. Reading that column with TCP's
vocabulary turns a held port into a free one, so the state table is interpreted
per protocol instead of shared. The same mistake used to hide a second case: a
UDP `[::]` wildcard shadowing IPv4 was unfindable, because the shadow check
looked for `LISTEN` and a UDP socket is never in it.

`SO_REUSEADDR` does what it says for UDP: two sockets that both set it can hold
the same address, which is why the report says "a second *plain* bind fails"
rather than "the address is taken". The verdict is about the bind you are about
to make, not about a count of holders.

TCP and UDP are separate namespaces, so `-proto both` gives two answers rather
than one merged kind:

```
$ portwhy why -proto both 127.0.0.1:53535
127.0.0.1:53535/tcp — nothing in the kernel tables occupies it
...
127.0.0.1:53535/udp — a bound socket holds it (udp has no listening state)
...
exit code: 0, from the tcp answer; the udp answer alone would exit 1
```

A merged answer would tell the UDP user "free" and the TCP user "taken", so the
two are printed and the one the exit code came from is named in the report.

## Waiting, and what a deadline may not say

The answer to "why can't I bind" is usually followed by "then tell me when I can".
The usual script is `while ! nc -z host 8080; do sleep 1; done`, which asks whether
a connection is accepted — a different question, and the wrong one on a port held
by a UDP socket or by a socket bound without `listen()`.

`portwhy wait` asks the only question that matters: it makes a plain `bind()` over
and over until the kernel accepts one, and says how the interval went.

```
$ portwhy wait 127.0.0.1:8080 -timeout 300ms -interval 50ms
portwhy wait 127.0.0.1:8080/tcp
  timeout 300ms, interval 50ms; the only thing that ends this is a plain bind() the kernel accepts

timeline
  t+0.001s   round 1    listening
  t+0.302s   round 7    listening

result
  not bindable at the deadline: the last round still answered "listening"
    a listening socket holds it — 7 attempt(s), none accepted, 302ms waited

still held by, as of the last round
  LISTEN         127.0.0.1:8080         pid 85 (python3) fd 3 [sole] inode 53482830

limits
  - holder lookup walked 3 process(es), 0 not readable

note
  every round is a real bind(): listen() is never called and the socket is closed at
  once. A refused bind changes nothing; the one that is accepted holds the address for
  the length of a single syscall. Each round is true of its own instant — the port can
  be taken again the moment the attempt returns.
```

The exit code is 1, and the report never uses the word "success" for that. When the
holder lets go, the same command ends differently:

```
$ portwhy wait 127.0.0.1:8080 -timeout 5s
timeline
  t+0.002s   round 1    listening
  t+0.206s   round 3    free (changed from listening)

result
  bindable: a plain bind() was accepted at t+0.206s, after 3 attempt(s) in 206ms
```

Four decisions are worth stating, because each one is a way the command could have
been more convenient and less honest:

- **A deadline is not a port.** A timeout exits 1 (or 3) with the last round's
  answer. There is no "assume it freed" path, because the script that believed it
  would go on to start a service that cannot bind.
- **The bind is plain.** `SO_REUSEADDR` would be accepted on a `TIME_WAIT`
  reservation, and reporting that as "you can bind now" would be false for the
  plain bind the caller is about to make.
- **Every round reads the tables again**, and a round that could not read them is
  `unknown`, never `free`. The count of blind rounds is part of the conclusion:
  "it never freed in 30s" reads very differently when half the rounds were blind.
- **EACCES and EADDRNOTAVAIL stop the wait.** A capability boundary and an address
  that is not on this host are answers, not delays, and waiting for either is
  waiting for a moment that will not arrive.

`-proto both` is refused: a TCP bind and a UDP bind are independent namespaces, and
one deadline and one timeline could only describe one of them. `-interval` below
50ms is refused as well — every round is a real `bind()`, so the floor is a limit on
side effects rather than politeness about CPU.

## The name in the way with nobody behind it

A unix socket is not a port and has no protocol to be shared in. It is a name,
and two independent measurements decide it: whether a row in `/proc/net/unix`
carries that name, and what is at the path. They disagree in both directions,
and both disagreements were verified by binding for real rather than reasoned
about:

```
$ portwhy unix /tmp/demo.sock                   # a listener is running
/tmp/demo.sock — a socket is bound to this name
path: exists (socket)

holders
  stream     listening  inode 46972368   pid 1231 (hold) fd 4 [sole]
```

```
$ kill 1231                                     # no cleanup: the file stays
$ ls -l /tmp/demo.sock
srwxr-xr-x 1 root root 0 Nov 22 12:51 /tmp/demo.sock
$ portwhy unix /tmp/demo.sock
/tmp/demo.sock — the name is in the way, but no running socket holds it
path: exists (socket)

why
  - the socket file is still there and no process holds it: bind() keeps failing
    until that file is removed, and looking for a process to kill will find
    nothing (0 row(s) in the unix table)
```

That is the same shape as a socket bound without `listen()`: the kernel says
nothing, and the bind still fails. It is not `taken`, because no process holds
anything — sending someone to look for a process would waste their afternoon.
Removing the file is the fix, and the report says so.

The mirror case exists too. `unlink()` the name while the socket stays open and
the table keeps its row while the filesystem has nothing, so a new `bind()`
*creates a new file and succeeds*: the old socket is unreachable, not in the way.
That answer is `free`, with a reason naming the released row, because "a row
exists" on its own would be read as "hold on".

Abstract names (`@name`) live only in the kernel: they are never looked up in
the filesystem, and `@demo` and `/demo` are two different sockets that can be
bound at the same time — verified, and the reason the report says which namespace
it is asking about instead of assuming the leading `@` was a typo.

## Whose port, and whose namespace

Two things decide whether an answer is about *your* situation, and both are
measurements rather than assumptions: which network namespace was read, and
whether this process may bind the port at all.

The namespace is the first two lines of every report. `--network host` and the
default bridge report different numbers on the same machine, and neither claims to
be an initial or host namespace — a container's pid 1 is the container's init, so
"the same namespace as pid 1" measures the boundary between two processes and
nothing about the host:

```
$ portwhy why 127.0.0.1:8080
127.0.0.1:8080/tcp — nothing in the kernel tables occupies it
scope: net:[4026532486], this process's network namespace, the same one pid 1 runs in
  the tables read here cover one network namespace; a holder in another one cannot be ruled out
```

The capability boundary is separate from "taken" and from "free". A port below
`net.ipv4.ip_unprivileged_port_start` is refused with `EACCES` before the kernel
looks at any address:

```
$ portwhy why 127.0.0.1:80          # this host measures ip_unprivileged_port_start = 1024
127.0.0.1:80/tcp — nothing in the kernel tables occupies it
scope: net:[4026532486], this process's network namespace, the same one pid 1 runs in
  the tables read here cover one network namespace; a holder in another one cannot be ruled out

why
  - no row in the read tables matches this address
  - binding this port needs a capability this process may not have: it is below the
    boundary this host measured, so a bind is refused with EACCES before the address
    is even considered — that refusal is not a holder (80 is below 1024 read from
    /proc/sys/net/ipv4/ip_unprivileged_port_start)
```

The same port on a host whose boundary is 0 — every container by default — is
reported with no capability line at all, because there nothing needs root. Warning
about port 80 there would be wrong on every run. And when the tunable cannot be
read, the limit says so without printing `1024`: the traditional boundary is not a
measurement of this host.

The last hole is the quiet one. If some processes could not be read, a `free`
answer has no socket to point at, so the holder it missed could be among them:

```
limits
  - not every process could be read, so this answer was never checked against all
    of them: an unreadable one may hold the port (2 of 3 process(es) could not be read)
  - holder lookup walked 1 process(es), 2 not readable
```

That is a limit, not a verdict: the kind stays `free` and the exit code stays 0,
because nothing measured a holder. `-no-holders` is a different sentence — nothing
was read rather than something failing to be read, and it prints neither line.

## Why another one

`ss` and `lsof` list sockets. They do not answer the question people actually
have, which is *which of the four different things* is wrong:

| what you see | what it means | what fixes it |
|---|---|---|
| a listener on the same address | a process is serving there | stop it, or use another port |
| only `TIME_WAIT` rows | a closed connection still reserves the port | a socket option, or wait out 2×MSL |
| a listener on `0.0.0.0` while you asked for one interface | the wildcard covers you | same as the first row |
| a listener on `[::]` while you asked for IPv4 | it depends on `net.ipv6.bindv6only` | measured per host, not assumed |
| nothing at all, but it fails now and then | the port is in the kernel's outbound source-port pool | pick a port outside that range |
| nothing at all, and `EACCES` instead of `EADDRINUSE` | the port is below `net.ipv4.ip_unprivileged_port_start` | bind it with the capability, or use a higher port |
| a row in state `07` in `/proc/net/udp` | a UDP socket is bound and not connected — no listener, still held | stop that process, or share with `SO_REUSEADDR` |
| a unix socket file with no row in `/proc/net/unix` | the process is gone and the name outlived it | remove the file |

The fourth row is why this tool exists. Most advice on the internet collapses all
of these into "kill the process or set `SO_REUSEADDR`", and part of that advice is
wrong on modern systems: Go sets `SO_REUSEADDR` on listeners by default, so a
`TIME_WAIT` row often does not block a Go server at all. A tool that repeats the
folklore is worse than no tool.

The last two rows are why it grew past ports. `ss` and `lsof` both show a bound
UDP socket as something that is not listening and a stale socket file as a file,
which is true and useless: in one case a process must be found, in the other
there is no process at all and the file must be deleted.

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
portwhy wait <host:port> [flags]
portwhy unix <path|@name> [flags]
portwhy states
portwhy version
```

| flag | meaning |
|---|---|
| `-proto tcp\|udp\|both` | which protocol to check (default `tcp`). `both` answers each protocol separately and reports the `tcp` answer's exit code, saying so in the output |
| `-json` | machine-readable report on stdout |
| `-all` | also list every row that mentions the port, with why it did or did not take part (the verdict does not change) |
| `-probe` | attempt a real `bind()` twice — plain, then `SO_REUSEADDR` — and report what the kernel answered. Never calls `listen()`. tcp only, so it is a usage error together with `-proto udp` or `-proto both` |
| `-no-holders` | skip the `/proc/<pid>/fd` walk: kernel state only |
| `-batch` | read targets from stdin, one per line, and write one JSON object per line. Takes no target argument; refuses `-probe` (each target would be a real bind) |
| `-tables DIR` | read the socket tables from DIR instead of `/proc/net` |
| `-sysctl DIR` | read the tunables from DIR instead of `/proc/sys`: `net/ipv6/bindv6only`, `net/ipv4/ip_local_port_range`, `net/ipv4/ip_local_reserved_ports`, `net/ipv4/ip_unprivileged_port_start` |
| `-proc ROOT` | use ROOT instead of `/proc` when naming the holder and when naming this process's network namespace |

`:8080` means every interface (`0.0.0.0:8080`). `[::1]:8080` is IPv6.

`portwhy wait` has its own flags, because a loop has questions a single answer does
not:

| flag | meaning |
|---|---|
| `-timeout D` | deadline (default `30s`). `0` means no deadline, and the report says so in words: a default that quietly becomes an infinite wait is discovered at the worst moment |
| `-interval D` | pause between rounds (default `500ms`, minimum `50ms`). Every round is a real `bind()` |
| `-proto tcp\|udp` | which namespace to wait on (default `tcp`). `both` is a usage error: two answers, one deadline and one timeline could only describe one of them |
| `-until-bindable` | `bindable` only — the one condition this version waits for. Another value is a usage error rather than an ignored flag |
| `-json` | the `waitReport` document |
| `-no-holders`, `-tables DIR`, `-sysctl DIR`, `-proc ROOT` | same meaning as for `why`, applied on every round |

`portwhy unix` takes its own smaller flag set — `-json`, `-tables DIR`, `-proc ROOT`,
`-no-holders` — because none of the port questions apply: there is no ephemeral
pool, no privileged boundary and no probe for a name. `@name` is the abstract
namespace, which is never looked up in the filesystem.

`portwhy states` prints the twelve TCP states with what each one does to a
`bind()`, plus the two states a UDP table actually contains, with the effect each
one has on that protocol. The `0x07` row is the interesting pair: `teardown` in
the TCP column and `blocks` in the UDP column, the same number from one column.

### Exit codes

These are the contract, and the third one is the reason the contract exists:

| code | meaning |
|---|---|
| 0 | free — every relevant table was read and nothing occupies it |
| 1 | taken — a listener, a bound udp socket, a `TIME_WAIT` reservation, another socket, or a unix name that cannot be bound |
| 2 | usage or internal error |
| 3 | unknown — the evidence needed was missing. **This is not "free".** |

A script that treats every non-zero code as "taken" will do the wrong thing on
3. That is intentional: it is the code saying it did not get to look.

With `--probe`, a 0 can become a 3: the tables said nothing held the address and
a `bind()` proved otherwise. The other direction never happens — no flag turns a
3 into a 0.

`wait` uses the same four codes with one extra rule: **0 means a plain `bind()` was
accepted during the wait, not that the waiting finished.** A deadline that passes
exits 1 or 3 with the last round's answer, and `-json` reports `end: "timeout"` so
a consumer can tell "it never freed" from "I never found out".

### JSON output and the batch stream

`-json` prints one document with `schema_version` in it. The full field list —
type, when each field appears, and what its absence means — is
[docs/json-schema.md](docs/json-schema.md), and it is checked against the types by
a test that fails in both directions: a field the code emits and the document
omits, or a field the document promises and the code never emits.

The rule the document spends most of its words on is the same rule the tool
applies to its own evidence: **a field that was not measured is absent or null,
never zero.** `"procs_read": 0` used to be able to mean "the walk was skipped" and
"the walk found no process" at once, which is the JSON version of answering
`free` for a table that could not be read. It is now
`"holder_lookup": {"attempted": false, "procs_read": null}`.

`-batch` answers many targets in one run:

```
$ printf '127.0.0.1:80\n127.0.0.1:443\n' | portwhy why -batch
{"schema_version":1,"target":"127.0.0.1:80","proto":"tcp","kind":"listening",...}
{"schema_version":1,"target":"127.0.0.1:443","proto":"tcp","kind":"listening",...}
```

What a consumer can rely on:

- one object per line, parseable on its own (`jq -c .` on any line succeeds);
- output order matches input order, so a line is matched back to what was asked;
- a line that is not a target gets its own object with `kind: "usage"`, an
  `error`, and no `evidence`, and the other lines still run;
- blank lines are not targets; a batch with none at all is a usage error, because
  "nothing was asked" must never read as "nothing is in the way";
- the tables are read once, before the first line, so every answer in one batch
  describes the same instant;
- the exit code is the most severe line's: `usage (2)` > `unknown (3)` >
  `taken (1)` > `free (0)`. Usage outranks unknown because it is a statement
  about the whole run; unknown outranks taken because a monitor with a blind spot
  is worse off than one that found a busy port.

`-probe` is refused with `-batch`: every target would be a real `bind()`, and N
side effects have to be opted into one target at a time. `portwhy unix` has no
batch mode — a unix name is a different question with a different document.

## What it does not do

Written down because the boundary is the product:

- **It does not attempt the bind unless you ask.** Without `--probe` every report
  says so, because a verdict from tables alone is a different kind of claim from
  one that was tested. With `--probe` it makes two attempts and prints the errno
  and the instant of each.
- **It does not probe UDP.** UDP has no listener to be refused by and no
  `TIME_WAIT` to wait out, so a TCP-style probe would be a different experiment
  reported as the answer to this one. `-proto udp` with `--probe` is rejected, and
  so is `-proto both`, which would run the TCP experiment and print it next to a
  UDP answer.
- **It does not look for the process that left a unix socket file behind.** There
  is no socket for it any more: the kernel dropped the row when the process died,
  and only the directory entry survived. The report says the file is in the way
  and that no process holds it, rather than inventing a pid.
- **It does not merge TCP and UDP into one answer.** They are separate namespaces:
  a bind can fail on one and succeed on the other, so `-proto both` prints both
  and names which one the exit code came from.
- **It does not see other network namespaces.** Inside a container, a port held
  on the host is invisible. Every report now names the namespace it read, and says
  that a holder in another one cannot be ruled out — naming a namespace does not
  let it look inside another.
- **It does not claim to know which namespace is the machine's initial one.** From
  inside, none: a container's pid 1 is the container's init. The report stops at
  what it measured.
- **It does not decide whether a port is privileged from a rule of thumb.** The
  boundary comes from `net.ipv4.ip_unprivileged_port_start`; when that cannot be
  read, the report says so and prints no number. It also never turns that finding
  into `taken`: needing root is not being occupied.
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
- **It cannot see a socket that opted out of dual-stack.** `bindv6only` is the
  default for new sockets; a program may call `setsockopt(IPV6_V6ONLY, 1)` for
  itself, and the kernel publishes no column for it. So when a `[::]` listener is
  the only evidence, the report adds that limit instead of presenting the shadow
  as certain, and `--probe` is what settles it — a bind that succeeds there turns
  the answer into `unknown` with that explanation, not into `free`.
- **It refuses addresses it cannot express.** A scoped IPv6 address (`[fe80::1%eth0]`)
  is rejected rather than approximated, because resolving a zone name to an index
  needs a dependency this project does not take.
- **It does not kill anything.** No `--force`, no `--kill`, on purpose: a port
  diagnostic is the wrong place to hide a destructive action.
- **`wait` does not promise the port afterwards.** A successful wait reports the
  instant a `bind()` was accepted and closes its socket immediately; anyone may
  take the port a microsecond later. It also refuses `-proto both` and any batch
  form, because two answers sharing one deadline and one timeline can only describe
  one of them, and it never keeps waiting through `EACCES` or `EADDRNOTAVAIL`.
- **It does not run on macOS or Windows.** `portwhy` exits with an explicit
  "socket tables are only available on Linux" rather than printing an empty
  report, and `portwhy unix` does the same for `/proc/net/unix`. The binary
  compiles on those platforms so that cross-compilation and `go vet` keep
  working; it refuses at runtime.

## How it works

```
/proc/net/tcp{,6}, /proc/net/udp{,6}   → internal/procnet   rows, addresses, states
                                     (one state column, read per protocol)
/proc/net/unix                         → internal/unixsock  names, socket type, SO_ACCEPTCON
/proc/sys/net/ipv6/bindv6only          → internal/sysctl    does [::] also hold IPv4
/proc/sys/net/ipv4/ip_local_port_range → internal/sysctl    may the kernel take this port
/proc/sys/net/ipv4/ip_local_reserved_ports                   ...and was it excluded
/proc/sys/net/ipv4/ip_unprivileged_port_start                may this process bind it
/proc/self/ns/net, /proc/1/ns/net      → internal/netns     which namespace is this
/proc/<pid>/fd/* → "socket:[inode]"    → internal/sockid    who holds which inode
bind() twice, never listen()           → internal/probe     what the kernel does now
lstat(path)                            → internal/unixsock  is something in the way
                        ↓
                  internal/verdict      classification, pure function
                        ↓
                  cmd/portwhy           text / JSON, exit codes
```

Only `internal/procnet`, `internal/sysctl`, `internal/netns`, `internal/sockid`,
`internal/unixsock` and `internal/probe` touch the system; `internal/verdict` is a
pure function over rows and injected evidence, which is why the causes above — and
every way the probe or the tunable can contradict them — can be tested without
opening a socket. Walking a path is a measurement, so it happens outside the
judgement and arrives as a three-state value: measured-present,
measured-absent, or not measured at all. See [docs/design.md](docs/design.md) for
the decisions behind that split and the cases this version deliberately refuses to
answer.

## How this document is checked

Three gates, each about a claim that would otherwise be trusted:

- `internal/docs` checks the documents against the tree they describe: every
  relative link resolves, every inline-code repository path exists, and the
  README reaches [the design](docs/design.md) and
  [the JSON contract](docs/json-schema.md). It fails closed — a missing README or
  an empty `docs/` is an error, not an empty issue list — because a checker that
  reports "clean" when it could not read its input turns unknown into clean.
- `scripts/readme-rehearsal.sh` executes every `portwhy` command printed in this
  document and asserts the exit code, with all four codes represented. It injects
  every table and tunable and binds its own sockets, so its result does not depend
  on the machine it runs on.
- [docs/ci.md](docs/ci.md) records what the CI jobs actually ran, read from the
  check-runs API rather than from the workflow file — a workflow says what was
  declared, a check-run says what happened.
