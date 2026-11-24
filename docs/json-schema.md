# JSON schema (schema_version 1)

portwhy has four machine-readable documents: one answer for a port, one answer
for a unix socket name, one wrapper for `-proto both`, and one for `wait`. This
file is the contract for all four, and it is enforced: `TestJSONSchemaDocumentMatchesTheTypes`
walks the report types with reflection and compares them to the tables below in
both directions. A field in the code that is missing here fails the build, and a
field here that the code does not emit fails it too. The gate reads this file
directly, so it cannot silently pass on a document that was deleted or renamed.

Field paths use `.` between object members and `[]` for an array's elements.
`findings[].owners[].pid` therefore means "for each finding, for each owner, the
pid field". Nested objects are listed under the document that contains them, not
under a section of their own.

## `schema_version`

Every document carries `schema_version` as an integer, currently `1`. It is the
version of this contract, not of the program (`version` is the program). The
rules:

- adding an optional field does not change it;
- removing a field, renaming one, changing its type, or changing what a value
  means does change it;
- a consumer that does not understand the number it sees should refuse the
  document rather than guess, which is the same rule the tool applies to its own
  evidence.

## `kind` and the exit code

`kind` is the answer; the exit code is the answer as a number. The mapping is a
contract, and the same one the text output states at the bottom of `help`:

| `kind` | exit code | means |
|---|---|---|
| `free` | 0 | every relevant table was read and nothing occupies it |
| `listening` | 1 | a socket in LISTEN holds the address |
| `bound` | 1 | a socket holds the address without listening (every UDP answer) |
| `stale-path` | 1 | a unix socket file is in the way with no socket behind it |
| `time-wait-only` | 1 | only TIME_WAIT rows hold it |
| `occupied-non-listening` | 1 | other socket states hold the address |
| `unknown` | 3 | the evidence needed was missing — this is never `free` |

A process-level usage or internal error exits 2 and, in single-target mode, may
print no document at all: there is nothing to describe. In batch mode it is a
per-line object (see below), because one bad line must not erase the others.

`unknown` shares no code with `free` on purpose. A monitor that treats non-zero
as "taken" would be wrong about `unknown`, and a monitor that treats it as
"free" would be wrong in the dangerous direction.

`wait` uses the same mapping, with one addition: it exits 0 only when `end` is
`bound`. A deadline that passes exits 1 or 3 with the last round's kind, so
"the wait finished" and "the port is free" are never the same fact in a script.

## Documents

### portReport

Printed by `portwhy why <target> -json`, and twice inside `bothReport`.

| field | type | when it appears | absence means |
|---|---|---|---|
| `schema_version` | integer | always | never absent |
| `target` | string | always | never absent; the normalised `host:port` that was asked about |
| `proto` | string | always | never absent; `tcp` or `udp` |
| `kind` | string | always | never absent |
| `findings[].state` | string | one element per matching socket row | the array is `[]` when no row matched — that is a measurement, not a gap |
| `findings[].effect` | string | as above | never absent within an element; how the row affects a `bind()` in *its* protocol |
| `findings[].local` | string | as above | never absent |
| `findings[].remote` | string | only when the row has a peer port | absent means the row has no remote end (a listener, or a bound UDP socket) |
| `findings[].inode` | integer | always within an element | `0` is a measurement: a row with no inode has no file descriptor and therefore no owning process (TIME_WAIT is the normal case) |
| `findings[].table` | string | always within an element | never absent; which kernel table the row came from |
| `findings[].owners[].pid` | integer | one element per process holding the socket | the array is `[]` when no process could be named, which is why `evidence.holder_lookup` exists |
| `findings[].owners[].comm` | string | when the kernel reported a name | absent means the name could not be read, not that it was empty |
| `findings[].owners[].fd` | integer | always within an element | `-1` is a measurement: the descriptor number was not resolvable |
| `findings[].owners[].role` | string | when a role was determined | absent means no role was claimed, never "sole holder" by implication |
| `reasons[].code` | string | one element per reason | the array is `[]` only if no reason applies, which the tool does not currently produce |
| `reasons[].detail` | string | when the reason carries a measurement | absent means the sentence is the whole finding; it does not mean "measured zero" |
| `evidence.tables_read` | integer | always | `0` is a measurement: no relevant table could be read, and `tables_unreadable` says which |
| `evidence.tables_unreadable[].name` | string | one element per table that should have answered | the array is `[]` when everything relevant was read; a table the kernel does not offer for the other address family is not listed, because it hides nothing |
| `evidence.tables_unreadable[].present` | boolean | as above | within an element, never absent |
| `evidence.tables_unreadable[].error` | string | when the failure has a message | absent only if a table failed without a message, which the readers do not do |
| `evidence.holder_lookup.attempted` | boolean | always | never absent; `false` means the walk was not run (`-no-holders`) |
| `evidence.holder_lookup.procs_read` | integer\|null | only after a completed walk | `null` means not measured: either skipped or failed. It is never `0` for a skipped walk |
| `evidence.holder_lookup.procs_denied` | integer\|null | as above | as above |
| `evidence.holder_lookup.error` | string | only when the walk was attempted and failed | absent means the walk either was not attempted or finished |
| `evidence.bindv6only.measured` | boolean | always | `false` means the tunable was not read; `value` is then `null` and must not be assumed to be 0 |
| `evidence.bindv6only.value` | integer\|null | only when measured | `null` is the only honest spelling of "not read" |
| `evidence.bindv6only.raw` | string | only when measured | as above; the file contents as read |
| `evidence.bindv6only.path` | string | always | never absent; the file that was consulted |
| `evidence.bindv6only.error` | string | when the read failed | absent means it was read |
| `evidence.ephemeral_range.measured` | boolean | always | `false` means the range was not read; `low`/`high` are then `null` and no default stands in |
| `evidence.ephemeral_range.low` | integer\|null | only when measured | `null` is never the number 0 |
| `evidence.ephemeral_range.high` | integer\|null | only when measured | as above |
| `evidence.ephemeral_range.raw` | string | only when measured | as above |
| `evidence.ephemeral_range.path` | string | always | never absent |
| `evidence.ephemeral_range.error` | string | when the read failed | absent means it was read |
| `evidence.reserved_ports.measured` | boolean | always | `false` means the file was not read or not understood; `ports` is then empty *and* meaningless |
| `evidence.reserved_ports.present` | boolean | always | `false` means this kernel has no such tunable at all, which is different from a failed read |
| `evidence.reserved_ports.ports[]` | string | always | `[]` with `measured: true` means "nothing is reserved", which is a measurement; `[]` with `measured: false` means nothing was learned |
| `evidence.reserved_ports.raw` | string | only when measured | as above |
| `evidence.reserved_ports.path` | string | always | never absent |
| `evidence.reserved_ports.error` | string | when the read failed | absent means it was read |
| `evidence.netns.inode` | integer | when the namespace was read | absent means `self` could not be read; there is no stand-in value |
| `evidence.netns.self` | string | when the namespace was read | as above |
| `evidence.netns.pid_one` | string | when pid 1's namespace was readable | absent means only this process's namespace was seen, which is stated rather than guessed |
| `evidence.netns.same_as_pid_one` | boolean\|null | only when both namespaces were read | `null` means no comparison was made. It is never `false`, which would claim a difference nobody measured |
| `evidence.netns.path` | string | always | never absent; the procfs path consulted |
| `evidence.netns.error` | string | when this process's namespace could not be read | absent means it was read |
| `evidence.netns.comparison_error` | string | when pid 1's namespace could not be read | absent means it was read |
| `evidence.unprivileged_port_start.measured` | boolean | always | `false` means no number was read, and `value` is `null`; the boundary is never assumed to be 1024 |
| `evidence.unprivileged_port_start.present` | boolean | always | `false` means this kernel does not offer the tunable |
| `evidence.unprivileged_port_start.value` | integer\|null | only when measured | `null` is the only honest spelling of "not read" |
| `evidence.unprivileged_port_start.raw` | string | only when measured | as above |
| `evidence.unprivileged_port_start.path` | string | always | never absent |
| `evidence.unprivileged_port_start.error` | string | when the read failed | absent means it was read |
| `version` | string | always | never absent. It is the program, not evidence, and it deliberately sits outside `evidence` |
| `rows` | array\|null | only with `-all` | `null` means the listing was not asked for. `[]` means it was asked for and the port has no rows — a different statement |
| `probe.attempts[].mode` | string | only with `-probe`, one element per attempt | the object is absent when no bind was attempted |
| `probe.attempts[].at` | string | as above | never absent within an element; RFC 3339, and the time is the point: a bind result describes one instant |
| `probe.attempts[].outcome` | string | as above | never absent within an element |
| `probe.attempts[].errno` | string | when the kernel refused with a known errno name | absent means no errno name was available, not that the bind succeeded |
| `probe.attempts[].message` | string | when there is a message beyond the errno | as above |
| `probe.attempts[].error` | string | when the attempt itself is untrustworthy | absent means the attempt counts as evidence |
| `probe.attempts[].usable_as_evidence` | boolean | as above, always within an element | never absent; `false` means the attempt says nothing about the port |
| `probe.note` | string | only with `-probe` | never absent when `probe` is present; it is the sentence that keeps the attempt from being read as a guarantee |

### unixReport

Printed by `portwhy unix <path|@name> -json`. The field names it shares with
`portReport` mean the same thing: `schema_version`, `target`, `kind`, `reasons`,
`version`. The rest is different because the question is different.

| field | type | when it appears | absence means |
|---|---|---|---|
| `schema_version` | integer | always | never absent |
| `target` | string | always | never absent; the name exactly as typed, including a leading `@` |
| `abstract` | boolean | always | never absent; an abstract name has no filesystem entry and `path` is then absent |
| `kind` | string | always | never absent |
| `holders[].inode` | integer | one element per row carrying the name | `[]` is a measurement: no row carries the name |
| `holders[].type` | string | as above | never absent within an element |
| `holders[].state` | string | as above | never absent within an element |
| `holders[].listening` | boolean | as above | never absent; derived from `SO_ACCEPTCON`, not from the state column |
| `holders[].owners[].pid` | integer | one element per process | `[]` means no process could be named |
| `holders[].owners[].comm` | string | when the kernel reported a name | absent means the name could not be read |
| `holders[].owners[].fd` | integer | always within an element | `-1` means the descriptor was not resolvable |
| `holders[].owners[].role` | string | when a role was determined | absent means no role was claimed |
| `reasons[].code` | string | one element per reason | as in `portReport` |
| `reasons[].detail` | string | when the reason carries a measurement | as in `portReport` |
| `path.measured` | boolean | for a filesystem name only | the whole object is absent for an abstract name: no path was looked at, and a zero-valued object would claim a lookup that never happened |
| `path.exists` | boolean | with `path`, when measured | within a measured object, never absent |
| `path.kind` | string | when the path exists | absent means it does not exist or was not measured |
| `path.error` | string | when the lookup failed | absent means the lookup succeeded |
| `evidence.table.read` | boolean | always | `false` means the rows were not obtained |
| `evidence.table.present` | boolean | always | `false` means this kernel does not offer `/proc/net/unix` at all. `read: false` with `present: true` is a procfs this process may not open — two different worlds |
| `evidence.table.error` | string | when the read failed | absent means it was read |
| `evidence.holder_lookup.attempted` | boolean | always | `false` means the walk was not run |
| `evidence.holder_lookup.procs_read` | integer\|null | only after a completed walk | `null` means not measured, never `0` |
| `evidence.holder_lookup.procs_denied` | integer\|null | as above | as above |
| `evidence.holder_lookup.error` | string | when the walk failed | absent means it was not attempted or finished |
| `version` | string | always | never absent; the program, not evidence |

### bothReport

Printed by `portwhy why <target> -proto both -json`. Two documents, never one:
UDP 53 taken while TCP 53 is free is the normal state of a DNS host, and a single
`kind` would have to be wrong about one of them.

| field | type | when it appears | absence means |
|---|---|---|---|
| `schema_version` | integer | always | never absent |
| `target` | string | always | never absent |
| `both` | boolean | always | never absent; always `true` |
| `exit_from` | string | always | never absent; names the half the process exit code came from (`tcp`) |
| `tcp` | object | always | never absent; a `portReport` |
| `udp` | object | always | never absent; a `portReport` |

### waitReport

Printed by `portwhy wait <target> -json`. It answers about an interval, not an
instant, and the difference shows in every field: `end` says how the loop stopped,
`rounds` counts observations rather than measurements of the port, and `timeline`
is the shape of the wait rather than a log.

The one rule a consumer has to read carefully: `kind` is the answer the wait ended
on, `end` is why it stopped. `end: "timeout"` with `kind: "listening"` is a port
that never freed; `end: "bound"` is the only state in which `kind` is `free`. A
consumer that treats `kind: "free"` as "safe to start the service" is reading the
contract correctly only when `end` is `bound` — and `kind` is never `free` in any
other case, which the tests assert over every combination.

| field | type | when it appears | absence means |
|---|---|---|---|
| `schema_version` | integer | always | never absent |
| `target` | string | always | never absent; the normalised `host:port` |
| `proto` | string | always | never absent; `tcp` or `udp` (`both` is a usage error) |
| `kind` | string | always | never absent; the last round's answer, `free` only when `end` is `bound` |
| `end` | string | always | never absent; `bound`, `timeout` or `stopped` |
| `stop` | string | only when `end` is `stopped` | absent means the deadline ran out; present names what waiting could not change (`not-permitted`, `addr-not-available`, `probe-failed`, `probe-not-run`, `probe-not-evidence`) |
| `timeout.forever` | boolean | always | never absent; `true` when `-timeout 0` was given |
| `timeout.ms` | integer\|null | only when a deadline was set | `null` means no deadline, which is not a duration of zero |
| `interval_ms` | integer | always | never absent; the pause that was actually used |
| `waited_ms` | integer | always | never absent; monotonic, from the first round to the one the wait ended on |
| `rounds` | integer | always | never absent; observations made |
| `attempts` | integer | always | never absent; rounds in which a `bind()` was really made, which is smaller than `rounds` when a socket could not be created |
| `unreadable_rounds` | integer | always | never absent; rounds in which at least one table could not be read. `0` is a measurement |
| `timeline[].round` | integer | one element per kept round | the array is never empty: it always has the first round and the round the wait ended on |
| `timeline[].at_ms` | integer | always within an element | never absent; monotonic milliseconds since the first round |
| `timeline[].kind` | string | always within an element | never absent; what that round supports once its bind is taken into account |
| `timeline[].table_kind` | string | always within an element | never absent; what the tables alone said, kept so a disagreement is visible |
| `timeline[].note` | string | when the round's answer is not the table's own | absent means there was nothing to report: either the two agreed, or the table could not answer. The values are `bind-refused-with-no-row` (the tables were readable and silent, and the bind was refused anyway), `table-said-taken-bind-accepted` (a holder let go between the two measurements), and `table-unreadable-this-round` |
| `timeline[].stop` | string | only on the round that stopped the wait | absent means the round let the wait continue |
| `timeline[].bind.outcome` | string | always within an element | never absent; `bound`, `addr-in-use`, `not-permitted`, `addr-not-available`, `failed` or `not-run` |
| `timeline[].bind.errno` | string | only when the kernel named one | absent means no errno was involved (success, or a failed `socket()`) |
| `timeline[].bind.message` | string | only when the kernel or Go produced one | absent means there was no message to quote |
| `timeline[].bind.error` | string | only when the attempt itself is untrustworthy | absent means the attempt is evidence; a set error means it is not, whatever the outcome says |
| `timeline[].bind.usable_as_evidence` | boolean | always within an element | never absent; false for `not-run` and for any attempt carrying an `error` |
| `note` | string | always | never absent; the side-effect disclosure, in the words the text output uses |
| `version` | string | always | never absent; the program, not evidence |

## Batch mode: NDJSON

`portwhy why -batch` reads targets from stdin and writes one compact JSON object
per line. Three shapes can appear, and they are distinguished by `kind`:

- a line that became a question with one protocol is a `portReport`;
- a line that became a question with `-proto both` is a `bothReport`;
- a line that never became a question is a `batchError`, whose `kind` is
  `usage`.

`usage` is the only kind that carries `error` and no `evidence`. Everything else
carries evidence, because something was measured. A consumer can therefore
decide what to do from `kind` alone.

Rules a stream consumer can rely on:

- **One object per line, always.** No pretty-printing, no array wrapper, no
  trailing commas. `jq -c .` on any single line must succeed.
- **Output order matches input order**, counting only non-blank inputs. That is
  how a line is matched back to what was asked; `target` states the question in
  its normalised form (`:9000` becomes `0.0.0.0:9000`).
- **Blank lines are not targets** and produce no object. A batch with no
  non-blank line at all is a usage error (exit 2) with nothing on stdout:
  "nothing was asked" must never read as "nothing is in the way".
- **Every line is flushed as it is produced**, so a consumer reading a pipe sees
  answers as they are made rather than at exit.
- **The tables are read once**, before the first line. Every answer in one batch
  describes the same instant, which is a fact a monitor can reason about; a
  per-line re-read would produce answers about N instants it cannot.
- **The exit code is the most severe line's**, in this order:
  `usage (2)` > `unknown (3)` > `taken (1)` > `free (0)`. Usage outranks unknown
  because it is a statement about the whole run; unknown outranks taken because a
  monitor with a blind spot is worse off than one that found a busy port.
- **`-probe` is refused with `-batch`**: each target would be a real `bind()`, and
  N side effects have to be opted into one target at a time. The refusal is a
  usage error, not a silently ignored flag.
- **`unix` has no batch mode.** A unix name is a different question with a
  different document, and one stream mixing the two shapes would force every
  consumer to branch on shape before it could read a kind.

### batchError

| field | type | when it appears | absence means |
|---|---|---|---|
| `schema_version` | integer | always | never absent |
| `target` | string | always | never absent; the line exactly as it was read, trimmed |
| `kind` | string | always | never absent; always `usage` |
| `error` | string | always | never absent; why the line is not a question |
| `version` | string | always | never absent; the program, not evidence |

## The two reports are not one report

`target`, `kind`, `reasons`, `version` and `schema_version` appear in both
documents with the same type and the same rule about absence. Everything else
differs on purpose: a unix socket has no port, no protocol, no TIME_WAIT and no
`/proc/net/tcp` row, so a shared field set would be either padded with fields
that mean nothing or missing the fields that matter. What is *not* allowed is a
shared name with two meanings, and that is what the gate is for.

## Prose rules that the gate cannot check

The gate compares names, so these are stated here for the reader and tested by
the behaviour tests instead:

- Numbers come from measurements only. A field that a consumer might divide by
  (`procs_read`, `tables_read`) is present and meaningful, or it is `null`.
- `evidence` never contains `version`. A program version is not evidence about a
  port.
- Risk and scope never become `kind`: `port-in-ephemeral-range`,
  `some-processes-unreadable` and the namespace fields are reasons and evidence,
  and the exit code does not move because of them.
- A missing table of the other address family is not a hole. A kernel without
  `tcp6` hides nothing from an IPv4 question, and listing it as unreadable would
  make every IPv4 answer look degraded.
