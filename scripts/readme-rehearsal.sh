#!/usr/bin/env bash
#
# Rehearse every command the README tells a reader to run.
#
# Why a script and not more tests: the tests exercise the library and the CLI's
# internals, and both can be green while `portwhy why :8080 -proto both` — the
# exact string in the README — has been broken for three weeks. A transcript in a
# document is a promise, and a promise nobody executes is a rumour.
#
# Two rules make this worth keeping:
#
#   1. The assertion is the exit code. Output text is checked only where the
#      text *is* the contract (the kind sentence, the JSON field). A script that
#      greps prose turns every wording improvement into a failure, and then
#      someone deletes it.
#   2. It does not read the machine's kernel state. Every table and tunable is
#      injected with -tables/-sysctl, and the two commands that must touch the
#      live kernel (`wait`, `--probe`) are pointed at a socket this script bound
#      itself. A rehearsal that depends on the host is red on the next machine.
#
# Exit codes covered: 0 (free), 1 (taken), 2 (usage), 3 (unknown). Both output
# forms — text and -json — appear.
#
# Run it from anywhere: bash scripts/readme-rehearsal.sh

set -u

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root" || exit 1

work=$(mktemp -d)
hold_pid=""
hold_tw_pid=""

cleanup() {
	if [ -n "$hold_pid" ]; then kill "$hold_pid" 2>/dev/null; fi
	if [ -n "$hold_tw_pid" ]; then kill "$hold_tw_pid" 2>/dev/null; fi
	rm -rf "$work"
}
trap cleanup EXIT

total=0
passed=0
failed=0

# build puts the two helpers and the binary under test in the work directory.
# The binary is the one `go build` produces, not a previously built bin/portwhy:
# a rehearsal of last week's binary is a rehearsal of nothing.
build() {
	mkdir -p "$work/bin" || return 1
	go build -o "$work/bin/portwhy" ./cmd/portwhy || return 1
	go build -o "$work/bin/mktables" ./scripts/mktables || return 1
	go build -o "$work/bin/holdport" ./scripts/holdport || return 1
	return 0
}

# wait_for_port reads the port a helper wrote, giving up after ~5s.
wait_for_port() {
	local file=$1 i=0
	while [ "$i" -lt 100 ]; do
		if [ -s "$file" ]; then
			cat "$file"
			return 0
		fi
		sleep 0.05
		i=$((i + 1))
	done
	echo "holdport never wrote $file" >&2
	return 1
}

# run case: label, expected exit, output pattern (ERE, "" for none), command...
run_case() {
	local label=$1 want=$2 pattern=$3
	shift 3
	local out status
	out=$("$@" 2>&1)
	status=$?
	total=$((total + 1))
	if [ "$status" -ne "$want" ]; then
		failed=$((failed + 1))
		printf 'FAIL  %s\n      command: %s\n      expected exit %s, got %s\n      output:\n%s\n\n' \
			"$label" "$*" "$want" "$status" "$out"
		return 0
	fi
	if [ -n "$pattern" ] && ! printf '%s' "$out" | grep -qE -- "$pattern"; then
		failed=$((failed + 1))
		printf 'FAIL  %s\n      command: %s\n      exit %s as expected, but the output does not match /%s/\n      output:\n%s\n\n' \
			"$label" "$*" "$status" "$pattern" "$out"
		return 0
	fi
	passed=$((passed + 1))
	return 0
}

# run_stdin case adds the batch stream, which is the one input that is not argv.
# The fourth argument is the number of output lines, because for a batch stream
# the line count is the contract: one object per input line, in input order.
run_stdin() {
	local label=$1 want=$2 want_lines=$3 input=$4
	shift 4
	local out status
	out=$(printf '%s' "$input" | "$@" 2>&1)
	status=$?
	total=$((total + 1))
	if [ "$status" -ne "$want" ]; then
		failed=$((failed + 1))
		printf 'FAIL  %s\n      command: printf %s | %s\n      expected exit %s, got %s\n      output:\n%s\n\n' \
			"$label" "$(printf '%q' "$input")" "$*" "$want" "$status" "$out"
		return 0
	fi
	local lines
	lines=$(printf '%s' "$out" | grep -c .)
	if [ "$lines" -ne "$want_lines" ]; then
		failed=$((failed + 1))
		printf 'FAIL  %s\n      expected %s output lines, got %s\n      output:\n%s\n\n' \
			"$label" "$want_lines" "$lines" "$out"
		return 0
	fi
	passed=$((passed + 1))
	return 0
}

if ! build; then
	echo "readme-rehearsal: build failed" >&2
	exit 1
fi
PW="$work/bin/portwhy"

# --- the two live sockets -----------------------------------------------------
# A listening socket and a port left in TIME_WAIT. Both are held by helpers this
# script starts, so `--probe` and `wait` describe a state the script made rather
# than whatever the host happened to be doing.
"$work/bin/holdport" -port-file "$work/port-hold" >/dev/null 2>&1 &
hold_pid=$!
"$work/bin/holdport" -port-file "$work/port-tw" -timewait >/dev/null 2>&1 &
hold_tw_pid=$!

PORT_HOLD=$(wait_for_port "$work/port-hold") || exit 1
PORT_TW=$(wait_for_port "$work/port-tw") || exit 1

# --- fixtures ----------------------------------------------------------------
# Tables the script declares: 8080 listens, PORT_TW is a TIME_WAIT reservation,
# UDP 53535 is bound, [::]:18080 is a dual-stack wildcard. Everything else the
# cases ask about is absent on purpose — "absent" is a state, not an error.
T="$work/tables"
T_HELD="$work/tables-held"
mkdir -p "$T" "$T_HELD" || exit 1

mk() {
	local dir=$1
	"$work/bin/mktables" -dir "$dir" \
		-tcp 127.0.0.1:8080=0A \
		-tcp "127.0.0.1:$PORT_TW=06" \
		-udp 127.0.0.1:53535=07 \
		-tcp6 "[::]:18080=0A" \
		-unix "@demo=listen"
}
mk "$T" || exit 1
# The second set adds a row for the socket the script is holding, so that one
# case can ask what the tables say when they agree with the probe.
"$work/bin/mktables" -dir "$T_HELD" \
	-tcp 127.0.0.1:8080=0A \
	-tcp "127.0.0.1:$PORT_TW=06" \
	-tcp "127.0.0.1:$PORT_HOLD=0A" \
	-udp 127.0.0.1:53535=07 \
	-tcp6 "[::]:18080=0A" \
	-unix "@demo=listen" || exit 1

S="$work/sysctl"
mkdir -p "$S/net/ipv6" "$S/net/ipv4" || exit 1
printf '0\n' >"$S/net/ipv6/bindv6only"
printf '32768\t60999\n' >"$S/net/ipv4/ip_local_port_range"
: >"$S/net/ipv4/ip_local_reserved_ports"
printf '1024\n' >"$S/net/ipv4/ip_unprivileged_port_start"

# A table that cannot be read at all: the file is there and is not a socket table.
BROKEN="$work/broken"
mkdir -p "$BROKEN" || exit 1
printf 'this is not a socket table\n' >"$BROKEN/tcp"

W="-tables $T -sysctl $S -no-holders"
# unix has no tunables to read: no ephemeral pool, no privilege boundary, no probe.
# Passing -sysctl there is a usage error, which is itself a case below.
WU="-tables $T -no-holders"

# --- the commands the README prints ------------------------------------------
# Port checks. Each label names the README section the command comes from, so a
# failure points at the paragraph that has to change.

# "The answer is a classification": free, listening, TIME_WAIT, unknown.
run_case "why: free" 0 "nothing in the kernel tables occupies it" \
	"$PW" why 127.0.0.1:9099 $W
run_case "why: a listener holds it" 1 "a listening socket holds it" \
	"$PW" why 127.0.0.1:8080 $W
run_case "why: only TIME_WAIT holds it" 1 "only TIME_WAIT rows hold it" \
	"$PW" why "127.0.0.1:$PORT_TW" $W
run_case "why: a table that cannot be parsed is unknown, not free" 3 "unknown|cannot be determined" \
	"$PW" why 127.0.0.1:9099 -tables "$BROKEN" -no-holders

# "The one thing no table can show": the probe, against a socket this script
# holds. The tables have no row for it, so a refused bind is the only evidence
# there is — the answer must be 3, never 0.
run_case "why --probe: refused bind with no row is unknown" 3 "refused" \
	"$PW" why "127.0.0.1:$PORT_HOLD" $W --probe
# And when the tables do have the row, the same refusal confirms them.
run_case "why --probe: table and probe agree" 1 "EADDRINUSE" \
	"$PW" why "127.0.0.1:$PORT_HOLD" -tables "$T_HELD" -sysctl "$S" -no-holders --probe
# TIME_WAIT: plain refused, SO_REUSEADDR accepted. The difference is the answer.
run_case "why --probe: TIME_WAIT needs the socket option" 1 "reuseaddr" \
	"$PW" why "127.0.0.1:$PORT_TW" $W --probe

# "The one question one tunable answers": the dual-stack wildcard, and the
# per-socket opt-out that only a probe can settle.
run_case "why: [::] shadows IPv4 when bindv6only=0" 1 "bindv6only" \
	"$PW" why 127.0.0.1:18080 $W

# "The port that fails one time in fifty": a risk reason, exit code unchanged.
run_case "why: a port inside the ephemeral range is still free" 0 "ephemeral" \
	"$PW" why 127.0.0.1:46883 $W
# "Whose port, and whose namespace": the capability boundary, which is neither
# taken nor free.
run_case "why: a privileged port is a capability answer" 0 "capability|EACCES" \
	"$PW" why 127.0.0.1:80 $W

# "The port that is bound and never listens": UDP, then both protocols.
run_case "why -proto udp" 1 "a bound socket holds it" \
	"$PW" why -proto udp 127.0.0.1:53535 $W
run_case "why -proto both names the answer the exit code came from" 0 "from the tcp answer" \
	"$PW" why -proto both 127.0.0.1:53535 $W
run_case "why --all lists the rows without changing the verdict" 1 "matched" \
	"$PW" why 127.0.0.1:8080 $W --all

# Machine-readable output: the second product surface.
run_case "why -json" 1 '"schema_version": *1' \
	"$PW" why 127.0.0.1:8080 $W -json

# Waiting: a deadline is not a port, and the only success is an accepted bind.
# The held socket is what makes the deadline case real: the tables say listening
# and the kernel agrees, so no round can be accepted.
run_case "wait: deadline expires on a held port" 1 "not bindable at the deadline" \
	"$PW" wait "127.0.0.1:$PORT_HOLD" -tables "$T_HELD" -sysctl "$S" -no-holders -timeout 300ms -interval 50ms
# Release it and the same wait ends differently. A socket that was bound and never
# connected leaves nothing behind, so the first round binds.
kill "$hold_pid" 2>/dev/null
hold_pid=""
run_case "wait: a released port becomes bindable" 0 "bindable:" \
	"$PW" wait "127.0.0.1:$PORT_HOLD" -tables "$T" -sysctl "$S" -no-holders -timeout 2s -interval 50ms

# The name in the way: unix sockets, text and JSON.
run_case "unix: an abstract name with a listener" 1 "bound to this name" \
	"$PW" unix @demo $WU
run_case "unix -json" 1 '"schema_version"' \
	"$PW" unix @demo $WU -json

# The two commands with no target.
run_case "states" 0 "07|teardown" "$PW" states
run_case "version" 0 "portwhy" "$PW" version

# Batch: one object per line, in input order, exit code from the most severe line.
run_stdin "why -batch: one line per target, most severe exit wins" 2 3 \
	'127.0.0.1:8080
127.0.0.1:9099
not-a-target
' "$PW" why -batch $W

# Refusals. A flag that is accepted and ignored is the same lie as a timeout that
# reports success, so each of these has to exit 2 and say why.
run_case "usage: -probe with -proto udp" 2 "probe" \
	"$PW" why -proto udp 127.0.0.1:53535 $W --probe
run_case "usage: -proto both with wait" 2 "both" \
	"$PW" wait -proto both 127.0.0.1:8080 $W -timeout 100ms
run_case "usage: -interval below the floor" 2 "50ms" \
	"$PW" wait 127.0.0.1:8080 $W -timeout 100ms -interval 10ms
run_case "usage: unix has no batch mode" 2 "batch" \
	"$PW" unix -batch @demo $WU
run_case "usage: unix has no tunables to read (-sysctl)" 2 "sysctl" \
	"$PW" unix @demo -tables "$T" -sysctl "$S" -no-holders

printf '%d/%d passed\n' "$passed" "$total"
if [ "$failed" -ne 0 ]; then
	printf '%d failed\n' "$failed"
	exit 1
fi
