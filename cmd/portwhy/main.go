// Command portwhy explains why a TCP or UDP port cannot be bound.
//
// The command has one job and one rule: every sentence it prints has to be
// backed by something it read or something it tried. It prints "I could not
// tell" as its own answer, with its own exit code, because a diagnostic tool
// that guesses is worse than one that is missing.
package main

import (
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/atop0914/portwhy/internal/netns"
	"github.com/atop0914/portwhy/internal/probe"
	"github.com/atop0914/portwhy/internal/procnet"
	"github.com/atop0914/portwhy/internal/sockid"
	"github.com/atop0914/portwhy/internal/sysctl"
	"github.com/atop0914/portwhy/internal/unixsock"
	"github.com/atop0914/portwhy/internal/verdict"
	"github.com/atop0914/portwhy/internal/version"
)

// Exit codes are a contract, and the contract is the point: a script that treats
// every non-zero code as "taken" would do the wrong thing on "could not tell".
const (
	exitFree    = 0
	exitTaken   = 1
	exitUsage   = 2
	exitUnknown = 3
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_ = usage(stderr)
		return exitUsage
	}
	switch args[0] {
	case "why":
		return runWhy(args[1:], stdout, stderr)
	case "unix":
		return runUnix(args[1:], stdout, stderr)
	case "states":
		return runStates(args[1:], stdout, stderr)
	case "version", "--version":
		return runVersion(stdout, stderr)
	case "help", "-h", "--help":
		_ = usage(stdout)
		return exitFree
	default:
		_ = fprintf(stderr, "portwhy: unknown command %q\n\n", args[0])
		_ = usage(stderr)
		return exitUsage
	}
}

// runStates prints the state vocabulary: every state the kernel can report, with
// what it does to a bind() — in both protocols, because the same number does not
// mean the same thing in /proc/net/tcp and /proc/net/udp.
//
// It is a command rather than documentation because the table is the product.
// Anyone who disagrees with a judgement can read the rule that produced it
// instead of inferring it from one output.
func runStates(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		_ = fprintf(stderr, "portwhy: states takes no arguments\n\n")
		_ = usage(stderr)
		return exitUsage
	}
	if err := fprintf(stdout, "TCP states, as the kernel spells them in /proc/net/tcp st\n\n"); err != nil {
		_ = fprintf(stderr, "portwhy: %v\n", err)
		return exitUsage
	}
	if err := fprintf(stdout, "  %-6s %-14s %-11s %-11s %s\n",
		"code", "name", "tcp effect", "udp effect", "what it means for a stream socket"); err != nil {
		_ = fprintf(stderr, "portwhy: %v\n", err)
		return exitUsage
	}
	for _, s := range procnet.KnownStates() {
		if err := fprintf(stdout, "  0x%02x   %-14s %-11s %-11s %s\n",
			uint8(s), s.String(), s.BindingFor(procnet.TCP), effectOrDash(s, procnet.UDP), s.NoteFor(procnet.TCP)); err != nil {
			_ = fprintf(stderr, "portwhy: %v\n", err)
			return exitUsage
		}
	}
	if err := fprintf(stdout,
		"\n  codes this build does not know are printed as UNKNOWN(0x..) and force\n"+
			"  the answer to \"unknown\": an unrecognised state is a hole in the evidence,\n"+
			"  not a row to be counted as occupation.\n"); err != nil {
		_ = fprintf(stderr, "portwhy: %v\n", err)
		return exitUsage
	}

	if err := fprintf(stdout, "\nUDP states, as /proc/net/udp uses the same column\n\n"); err != nil {
		_ = fprintf(stderr, "portwhy: %v\n", err)
		return exitUsage
	}
	for _, s := range procnet.KnownUDPStates() {
		if err := fprintf(stdout, "  0x%02x   %-14s %-11s %s\n",
			uint8(s), s.String(), s.BindingFor(procnet.UDP), s.NoteFor(procnet.UDP)); err != nil {
			_ = fprintf(stderr, "portwhy: %v\n", err)
			return exitUsage
		}
	}
	if err := fprintf(stdout,
		"\n  only these two codes occur in a UDP table, and 0x07 is the important one:\n"+
			"  it means bound-and-unconnected, the ordinary state of a bound UDP socket,\n"+
			"  and a second plain bind() fails with EADDRINUSE while it exists. Read\n"+
			"  through the TCP table it would look like a socket already released.\n"); err != nil {
		_ = fprintf(stderr, "portwhy: %v\n", err)
		return exitUsage
	}
	return exitFree
}

// effectOrDash prints a binding effect, or "-" for a code the protocol does not
// use. A zero value here would read as EffectUnknown, which is a claim.
func effectOrDash(s procnet.State, p procnet.Proto) string {
	if s.BindingFor(p) == procnet.EffectUnknown {
		return "-"
	}
	return s.BindingFor(p).String()
}

func runVersion(stdout, stderr io.Writer) int {
	if err := fprintf(stdout, "%s\n", version.Resolve().String()); err != nil {
		_ = fprintf(stderr, "portwhy: %v\n", err)
		return exitUsage
	}
	return exitFree
}

func runWhy(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("why", flag.ContinueOnError)
	fs.SetOutput(stderr)
	proto := fs.String("proto", "tcp", "protocol to check: tcp, udp or both")
	asJSON := fs.Bool("json", false, "emit a JSON report instead of text")
	tableDir := fs.String("tables", procnet.DefaultDir, "directory holding the kernel socket tables")
	sysctlDir := fs.String("sysctl", sysctl.DefaultDir, "directory holding the kernel tunables")
	procRoot := fs.String("proc", sockid.DefaultRoot, "procfs root used to name the holder")
	skipHolders := fs.Bool("no-holders", false, "do not walk /proc/<pid>/fd: kernel state only")
	showAll := fs.Bool("all", false, "also list every row on this port, with why it did or did not take part")
	useProbe := fs.Bool("probe", false, "attempt a real bind() (plain and SO_REUSEADDR, never listen())")

	if err := fs.Parse(splitFlags(fs, args)); err != nil {
		return exitUsage
	}
	if fs.NArg() != 1 {
		_ = fprintf(stderr, "portwhy: why takes exactly one target, got %d\n\n", fs.NArg())
		_ = usage(stderr)
		return exitUsage
	}

	protos, err := parseProtos(*proto)
	if err != nil {
		_ = fprintf(stderr, "portwhy: %v\n", err)
		return exitUsage
	}
	addr, err := parseTarget(fs.Arg(0))
	if err != nil {
		_ = fprintf(stderr, "portwhy: %v\n", err)
		return exitUsage
	}

	// The probe answers the TCP question — "does bind() on this stream socket
	// fail". A UDP probe would be a different experiment (no listener concept, no
	// TIME_WAIT), so offering one today would mean reporting the result of one
	// experiment as the answer to the other. With -proto both there is no single
	// experiment that answers both, which is why the combination is refused
	// rather than quietly probing the TCP half.
	if *useProbe && (len(protos) > 1 || protos[0] != procnet.TCP) {
		if len(protos) > 1 {
			_ = fprintf(stderr, "portwhy: -probe is tcp only, so it cannot answer -proto both: a udp probe "+
				"is a different experiment, and probing just the tcp half would present one experiment as two answers\n")
		} else {
			_ = fprintf(stderr, "portwhy: -probe is tcp only; a udp probe would answer a different question, "+
				"so this version does not pretend to make one\n")
		}
		return exitUsage
	}

	tables := procnet.ReadAll(*tableDir)

	// The one tunable that decides whether a [::] listener also holds IPv4. It
	// is read unconditionally — one small file — and handed to the judgement as
	// evidence, so that a failed read is reported as a hole and not replaced by
	// the value Linux usually has.
	measuredV6Only := sysctl.ReadBindV6Only(*sysctlDir)

	// The two port-pool tunables. They are read for every question, including
	// the ones outside the pool: reading them is what lets the report say "your
	// port is outside the range this host measured" instead of saying nothing,
	// and a failed read has to be a stated hole rather than a silent silence.
	measuredRange := sysctl.ReadPortRange(*sysctlDir)
	measuredReserved := sysctl.ReadReservedPorts(*sysctlDir)

	// The capability boundary: below it a non-root bind is refused with EACCES
	// before any address is considered, which is neither "taken" nor "free". It
	// is read from the tunable, never assumed to be 1024 — a host whose boundary
	// is 0 (every container by default) has no privileged port at all.
	measuredBoundary := sysctl.ReadPrivilegedPortStart(*sysctlDir)

	// The namespace every row in this report came from. Read from the same
	// procfs root the holder walk uses, so a test can state a namespace without
	// being in one.
	measuredNetNS := netns.Read(*procRoot)

	env := verdict.Env{
		V6Only:     measuredV6Only,
		Ephemeral:  measuredRange,
		Reserved:   measuredReserved,
		Privileged: measuredBoundary,
		NetNS:      measuredNetNS,
	}
	if !*skipHolders {
		idx, err := sockid.Scan(*procRoot)
		if err != nil {
			// The verdict is still buildable from kernel state; what is lost is
			// the ability to name the holder. Say so, and keep going.
			_ = fprintf(stderr, "portwhy: warning: cannot name holders: %v\n", err)
		} else {
			env.Lookup = func(s procnet.Socket) []verdict.Owner {
				holders := idx.Holders(s.Inode)
				out := make([]verdict.Owner, 0, len(holders))
				for _, h := range holders {
					out = append(out, verdict.Owner{PID: h.PID, Comm: h.Comm, FD: h.FD})
				}
				return out
			}
			env.ProcsRead = idx.ProcsRead
			env.ProcsDenied = idx.ProcsDenied
			env.PPID = idx.PPID
		}
	}

	// Tables first, probe second. The order is not an implementation detail: it
	// is what lets the report say "the tables showed X, and a bind at time T
	// said Y" without a reader having to guess which observation is newer.
	if *useProbe {
		env.Probe = probe.Both(netip.AddrPortFrom(addr.IP, addr.Port))
	}

	// --all adds rows; it never re-decides. ExplainAll calls Explain and then
	// attaches the neighbours, so the kind and the exit code cannot depend on the
	// flag — that is a property of the code, not a promise in the help text.
	explain := func(q verdict.Query) verdict.Verdict {
		if *showAll {
			return verdict.ExplainAll(q, tables, env)
		}
		return verdict.Explain(q, tables, env)
	}

	if len(protos) == 1 {
		v := explain(verdict.Query{Addr: addr, Proto: protos[0]})
		if err := writeReport(stdout, v, *asJSON); err != nil {
			_ = fprintf(stderr, "portwhy: writing report: %v\n", err)
			return exitUsage
		}
		return exitCode(v.Kind)
	}

	// Two protocols, two answers. They are never folded into one kind: UDP 53
	// taken while TCP 53 is free is the normal state of a DNS host, and a single
	// kind would have to be wrong about one of them.
	tcp := explain(verdict.Query{Addr: addr, Proto: procnet.TCP})
	udp := explain(verdict.Query{Addr: addr, Proto: procnet.UDP})
	if *asJSON {
		err = renderJSONBoth(stdout, tcp, udp)
	} else {
		err = renderTextBoth(stdout, tcp, udp)
	}
	if err != nil {
		_ = fprintf(stderr, "portwhy: writing report: %v\n", err)
		return exitUsage
	}
	// The exit-code contract predates this flag and has room for one answer. TCP
	// wins, because "is this port taken" is a question people ask about a
	// listener; the report prints the UDP answer and the code it would have had,
	// so the choice is stated rather than hidden.
	return exitCode(tcp.Kind)
}

// writeReport renders one verdict in the requested format.
func writeReport(w io.Writer, v verdict.Verdict, asJSON bool) error {
	if asJSON {
		return renderJSON(w, v)
	}
	return renderText(w, v)
}

// runUnix answers "why can't I bind this unix socket name".
//
// It is a separate command rather than a flag on why: a unix socket has no port,
// no protocol and no TIME_WAIT, and the flags that make sense for a port (proto,
// probe, the port-pool tunables) would all have to be rejected one by one.
func runUnix(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("unix", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "emit a JSON report instead of text")
	tableDir := fs.String("tables", unixsock.DefaultDir, "directory holding the kernel socket tables")
	procRoot := fs.String("proc", sockid.DefaultRoot, "procfs root used to name the holder")
	skipHolders := fs.Bool("no-holders", false, "do not walk /proc/<pid>/fd: kernel state only")

	if err := fs.Parse(splitFlags(fs, args)); err != nil {
		return exitUsage
	}
	if fs.NArg() != 1 {
		_ = fprintf(stderr, "portwhy: unix takes exactly one name, got %d\n\n", fs.NArg())
		_ = usage(stderr)
		return exitUsage
	}

	q := verdict.UnixNameOf(fs.Arg(0))
	if q.Name == "" {
		_ = fprintf(stderr, "portwhy: empty unix socket name\n\n")
		_ = usage(stderr)
		return exitUsage
	}

	table := unixsock.Read(*tableDir)

	env := verdict.UnixEnv{}
	// An abstract name has no filesystem entry, so nothing is inspected: asking
	// the filesystem about "@foo" would answer about a file named "@foo", which
	// is a different socket entirely.
	if !q.Abstract {
		env.Path = unixsock.Inspect(q.Name)
	}
	if !*skipHolders {
		idx, err := sockid.Scan(*procRoot)
		if err != nil {
			_ = fprintf(stderr, "portwhy: warning: cannot name holders: %v\n", err)
		} else {
			env.Lookup = func(inode uint64) []verdict.Owner {
				holders := idx.Holders(inode)
				out := make([]verdict.Owner, 0, len(holders))
				for _, h := range holders {
					out = append(out, verdict.Owner{PID: h.PID, Comm: h.Comm, FD: h.FD})
				}
				return out
			}
			env.ProcsRead = idx.ProcsRead
			env.ProcsDenied = idx.ProcsDenied
			env.PPID = idx.PPID
		}
	}

	v := verdict.ExplainUnix(q, table, env)
	var err error
	if *asJSON {
		err = encodeJSON(stdout, buildUnixReport(v))
	} else {
		err = renderUnixText(stdout, v)
	}
	if err != nil {
		_ = fprintf(stderr, "portwhy: writing report: %v\n", err)
		return exitUsage
	}
	return exitCode(v.Kind)
}

// splitFlags lets flags follow the target.
//
// The standard flag package stops at the first positional argument, so
// "portwhy why :8080 -json" would silently treat "-json" as a second target.
// That is the order people type, and a diagnostic tool that rejects the obvious
// invocation is a diagnostic tool nobody runs twice.
func splitFlags(fs *flag.FlagSet, args []string) []string {
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if len(arg) < 2 || arg[0] != '-' {
			positional = append(positional, arg)
			continue
		}
		flags = append(flags, arg)
		name := strings.TrimLeft(arg, "-")
		if strings.ContainsRune(name, '=') {
			continue
		}
		f := fs.Lookup(name)
		if f == nil {
			// Unknown flag: hand it to Parse so it reports the error.
			continue
		}
		if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
			continue
		}
		if i+1 < len(args) {
			flags = append(flags, args[i+1])
			i++
		}
	}
	// Positionals go last so that Parse leaves them in fs.Args().
	return append(flags, positional...)
}

func exitCode(k verdict.Kind) int {
	switch k {
	case verdict.KindFree:
		return exitFree
	case verdict.KindUnknown:
		return exitUnknown
	default:
		return exitTaken
	}
}

// parseProtos turns -proto into the protocols to answer for, in the order the
// exit code prefers them.
//
// "both" is a request for two answers, not a third protocol. It returns them in
// a fixed order rather than a set, because the exit code has to come from one of
// them and a rule that depends on map iteration would flip between runs.
func parseProtos(s string) ([]procnet.Proto, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "tcp":
		return []procnet.Proto{procnet.TCP}, nil
	case "udp":
		return []procnet.Proto{procnet.UDP}, nil
	case "both":
		return []procnet.Proto{procnet.TCP, procnet.UDP}, nil
	}
	return nil, fmt.Errorf("-proto %q is not tcp, udp or both", s)
}

// parseTarget accepts "host:port", "[v6]:port" and the bare ":port" that people
// type when they mean "every interface".
func parseTarget(s string) (procnet.Addr, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return procnet.Addr{}, fmt.Errorf("empty target; try 127.0.0.1:8080 or :8080")
	}
	if rest, ok := strings.CutPrefix(s, ":"); ok {
		port, err := strconv.ParseUint(rest, 10, 16)
		if err != nil {
			return procnet.Addr{}, fmt.Errorf("target %q has no usable port", s)
		}
		return procnet.Addr{IP: netip.IPv4Unspecified(), Port: uint16(port)}, nil
	}
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return procnet.Addr{}, fmt.Errorf("target %q is not host:port (try 127.0.0.1:8080 or :8080)", s)
	}
	// Unmap turns ::ffff:127.0.0.1 into 127.0.0.1: the table stores those rows
	// as IPv4, and comparing a 4-in-6 address against them would silently
	// answer "free".
	return procnet.Addr{IP: ap.Addr().Unmap(), Port: ap.Port()}, nil
}

var kindSentence = map[verdict.Kind]string{
	verdict.KindFree:                 "nothing in the kernel tables occupies it",
	verdict.KindListening:            "a listening socket holds it",
	verdict.KindBound:                "a bound socket holds it (udp has no listening state)",
	verdict.KindTimeWaitOnly:         "only TIME_WAIT rows hold it",
	verdict.KindOccupiedNonListening: "sockets hold it, but none of them is listening",
	verdict.KindUnknown:              "cannot be determined from what was readable",
}

// unixKindSentence is the same set of answers in a different vocabulary: a unix
// socket name is not a port, and "stale-path" has no port equivalent at all.
var unixKindSentence = map[verdict.Kind]string{
	verdict.KindFree:      "nothing holds this name",
	verdict.KindBound:     "a socket is bound to this name",
	verdict.KindStalePath: "the name is in the way, but no running socket holds it",
	verdict.KindUnknown:   "cannot be determined from what was readable",
}

var reasonSentence = map[string]string{
	verdict.ReasonNoSockets:              "no row in the read tables matches this address",
	verdict.ReasonListener:               "bind() to an address a listener holds fails with EADDRINUSE",
	verdict.ReasonBound:                  "a UDP socket is bound to this address and keeps the port to itself: a second plain bind() fails with EADDRINUSE, and the fix is to find that process — or, if both sides agree to it, to share the port with SO_REUSEADDR",
	verdict.ReasonTimeWait:               "the reservation belongs to a closed connection, not to a running process",
	verdict.ReasonOtherState:             "a bound socket in a non-listening state holds this address; whether bind() fails depends on socket options",
	verdict.ReasonTableUnreadable:        "a socket table could not be read, so absence of a row proves nothing",
	verdict.ReasonV6Wildcard:             "whether the IPv6 wildcard socket also holds this IPv4 address could not be answered: net.ipv6.bindv6only was not readable, and a default is not a measurement",
	verdict.ReasonV6Shadow:               "the IPv6 wildcard socket holds this IPv4 address too: this host runs with bindv6only=0, so a [::] socket is dual-stack",
	verdict.ReasonV6NoShadow:             "the IPv6 wildcard socket does not hold this IPv4 address: this host runs with bindv6only=1, so [::] is IPv6 only",
	verdict.ReasonV6PerSocket:            "bindv6only is the default for new sockets, not a property of an existing one: a socket that set IPV6_V6ONLY for itself would leave IPv4 free, and only -probe can tell which",
	verdict.ReasonV6OptOut:               "the wildcard looked dual-stack but a bind succeeded: that listener is IPv6-only for itself, an option the kernel reports nowhere, so this version does not promote the answer to free",
	verdict.ReasonNoOwnerInode:           "a row with inode 0 has no descriptor behind it (TIME_WAIT, or a socket closed and waiting out its timeout), so no process can be named for it",
	verdict.ReasonProcsDenied:            "some processes could not be read, so an unnamed holder may exist",
	verdict.ReasonProbeNotRun:            "no bind was attempted: this verdict comes from kernel state only",
	verdict.ReasonTeardown:               "rows on this address belong to sockets the kernel is already destroying, so they do not hold the port",
	verdict.ReasonUnknownState:           "a row used a state code this build does not know, so what it does to a bind cannot be stated",
	verdict.ReasonUnlistedBinding:        "a socket bound without listen() holds the port and has no row in these tables, so this answer cannot rule that out",
	verdict.ReasonEphemeralRange:         "this port is inside the kernel's ephemeral range: an outbound connection may take it as its source port, which is why a fixed listener here fails only sometimes — a port a long-lived service depends on belongs outside that range",
	verdict.ReasonEphemeralReserved:      "this port is excluded from the ephemeral range: the kernel will not take it as an outbound source port, so the occasional EADDRINUSE from the pool cannot come from here",
	verdict.ReasonEphemeralUnreadable:    "the ephemeral range could not be read, so whether the kernel may take this port for an outbound connection was not measured — the range Linux usually has is not a measurement of this host",
	verdict.ReasonProbeBound:             "a plain bind succeeded, so the tables' silence was accurate at that instant and nothing — including a socket bound without listen() — held the address",
	verdict.ReasonProbeRefused:           "a plain bind was refused: something holds this address",
	verdict.ReasonProbeHolds:             "a plain bind was refused while no row covers the address: something bound this port without listen(), and no table lists it",
	verdict.ReasonProbeOption:            "SO_REUSEADDR is what unblocks it — both attempts were made, and only the option one was accepted",
	verdict.ReasonProbeDenied:            "the bind probe could not be made, so nothing was learned about the address — this is not a free port",
	verdict.ReasonProbeGap:               "the probe evidence lacks the plain attempt that any conclusion about binding needs",
	verdict.ReasonProbeConflict:          "the tables and the probe describe different instants, and this version cannot say which one you are facing",
	verdict.ReasonHolderLookupIncomplete: "not every process could be read, so this answer was never checked against all of them: an unreadable one may hold the port",
	verdict.ReasonPrivilegedPort:         "binding this port needs a capability this process may not have: it is below the boundary this host measured, so a bind is refused with EACCES before the address is even considered — that refusal is not a holder",
	verdict.ReasonPrivilegedUnreadable:   "the privileged-port boundary could not be read, so whether this port needs root at all was not measured — the traditional limit is not a measurement of this host",
	verdict.ReasonUnixHolder:             "a socket in the kernel table carries this name, so bind() fails with EADDRINUSE",
	verdict.ReasonUnixStaleSocket:        "the socket file is still there and no process holds it: bind() keeps failing until that file is removed, and looking for a process to kill will find nothing",
	verdict.ReasonUnixNonSocketPath:      "something that is not a unix socket occupies this path: bind() fails with EADDRINUSE on any existing entry, so the path has to be removed or chosen differently",
	verdict.ReasonUnixNameReleased:       "the name is free even though the table still shows a socket: the file was removed while that socket stayed open, so a new bind() creates a new file and leaves the old socket unreachable",
	verdict.ReasonUnixAbsent:             "both halves were checked: no row in the unix table carries this name and nothing exists at the path",
	verdict.ReasonUnixAbstractAbsent:     "no socket in the kernel carries this abstract name, so a bind can take it; a name in this namespace disappears with its socket and leaves nothing behind",
	verdict.ReasonUnixTableUnreadable:    "the unix socket table could not be read, so absence of a row proves nothing about this name",
	verdict.ReasonUnixPathUnreadable:     "the path could not be checked, so whether something is in the way was never measured — this is not a free name",
}

// limitReasons are the ones that describe what the answer does not cover. They
// are printed in their own section so the caveat is not lost in the middle of
// the diagnosis.
var limitReasons = map[string]bool{
	verdict.ReasonProbeNotRun:     true,
	verdict.ReasonProbeDenied:     true,
	verdict.ReasonProbeGap:        true,
	verdict.ReasonProcsDenied:     true,
	verdict.ReasonNoOwnerInode:    true,
	verdict.ReasonV6Wildcard:      true,
	verdict.ReasonV6PerSocket:     true,
	verdict.ReasonUnlistedBinding: true,
	// The pool range is a limit only when it could not be read; when it was
	// read, the risk is part of the diagnosis and belongs in "why".
	verdict.ReasonEphemeralUnreadable: true,
	// The two scope statements from Day 6. Both are caveats on a "go ahead", so
	// they are printed under "limits" where a reader looks for what the answer
	// does not cover.
	verdict.ReasonHolderLookupIncomplete: true,
	verdict.ReasonPrivilegedUnreadable:   true,
}

func renderText(w io.Writer, v verdict.Verdict) error {
	if err := fprintf(w, "%s/%s — %s\n", v.Query.Addr, v.Query.Proto, kindSentence[v.Kind]); err != nil {
		return err
	}

	// The scope comes before the holders on purpose: "nothing holds this port"
	// is a statement about one namespace, and a reader who has already decided
	// what it means will not scroll back to find out which one.
	if err := renderScope(w, v.NetNS); err != nil {
		return err
	}

	if len(v.Findings) > 0 {
		if err := fprintf(w, "\nholders\n"); err != nil {
			return err
		}
		for _, f := range v.Findings {
			if err := fprintf(w, "  %-14s %-22s %-28s inode %d\n",
				f.Socket.State, f.Socket.Local.String(), ownerText(f.Owners, f.Socket.Inode), f.Socket.Inode); err != nil {
				return err
			}
		}
	}

	if v.All != nil {
		if err := renderRows(w, v.All); err != nil {
			return err
		}
	}

	if err := fprintf(w, "\nwhy\n"); err != nil {
		return err
	}
	wrote := false
	for _, r := range v.Reasons {
		if limitReasons[r.Code] {
			continue
		}
		if err := writeReason(w, r); err != nil {
			return err
		}
		wrote = true
	}
	if !wrote {
		if err := fprintf(w, "  - no further detail available\n"); err != nil {
			return err
		}
	}

	// The probe goes between the diagnosis and the limits: it is what was done,
	// not what could not be seen, and reading "why" straight into the raw
	// attempts is the order the question is asked in.
	if err := renderProbe(w, v.Probe); err != nil {
		return err
	}

	// An empty "limits" heading is worse than none: it reads as "there are none"
	// and as "the section failed to print" at the same time.
	hasLimits := len(v.TablesUnreadable) > 0 || v.ProcsRead > 0
	for _, r := range v.Reasons {
		if limitReasons[r.Code] {
			hasLimits = true
		}
	}
	if !hasLimits {
		return nil
	}

	if err := fprintf(w, "\nlimits\n"); err != nil {
		return err
	}
	for _, r := range v.Reasons {
		if !limitReasons[r.Code] {
			continue
		}
		if err := writeReason(w, r); err != nil {
			return err
		}
	}
	if len(v.TablesUnreadable) > 0 {
		if err := fprintf(w, "  - unreadable tables: %s\n", strings.Join(v.TablesUnreadable, ", ")); err != nil {
			return err
		}
	}
	if v.ProcsRead > 0 {
		if err := fprintf(w, "  - holder lookup walked %d process(es), %d not readable\n", v.ProcsRead, v.ProcsDenied); err != nil {
			return err
		}
	}
	return nil
}

// renderTextBoth prints two answers, each complete.
//
// Folding them would be the one thing this flag must not do: a DNS host has UDP
// 53 taken and TCP 53 free, and a single kind would be a lie about one of them.
// The exit code has to pick one, so the last line names both numbers instead of
// letting a script believe the one it got covered both.
func renderTextBoth(w io.Writer, tcp, udp verdict.Verdict) error {
	if err := fprintf(w, "%s — two independent answers, one per protocol\n", tcp.Query.Addr); err != nil {
		return err
	}
	if err := fprintf(w, "  a tcp bind and a udp bind are separate namespaces: one can fail while the\n"+
		"  other succeeds, so neither answer is a summary of the other\n\n"); err != nil {
		return err
	}
	if err := renderText(w, tcp); err != nil {
		return err
	}
	if err := fprintf(w, "\n"); err != nil {
		return err
	}
	if err := renderText(w, udp); err != nil {
		return err
	}
	return fprintf(w, "\nexit code: %d, from the tcp answer; the udp answer alone would exit %d\n",
		exitCode(tcp.Kind), exitCode(udp.Kind))
}

// renderUnixText prints a unix socket answer.
//
// The path line comes before the diagnosis for the same reason the namespace line
// does: "nothing holds this name" is a claim about two things — the kernel table
// and the filesystem — and a reader who has already decided what it means will
// not scroll back to find out which of them was checked.
func renderUnixText(w io.Writer, v verdict.UnixVerdict) error {
	kindText, ok := unixKindSentence[v.Kind]
	if !ok {
		kindText = string(v.Kind)
	}
	if err := fprintf(w, "%s — %s\n", v.Query.Name, kindText); err != nil {
		return err
	}
	if v.Query.Abstract {
		if err := fprintf(w, "scope: abstract namespace — the name lives in the kernel; "+
			"no file exists for it, so nothing about a path was measured\n"); err != nil {
			return err
		}
	} else if err := fprintf(w, "path: %s\n", v.Path.Line()); err != nil {
		return err
	}

	if len(v.Holders) > 0 {
		if err := fprintf(w, "\nholders\n"); err != nil {
			return err
		}
		for _, h := range v.Holders {
			// "bound" and "listening" are the two states a unix name can be
			// held in, and the difference decides whether anything can still
			// connect to it — so it is printed rather than folded away.
			state := "bound"
			if h.Socket.Listening() {
				state = "listening"
			}
			if err := fprintf(w, "  %-10s %-10s inode %-10d %s\n",
				h.Socket.Type, state, h.Socket.Inode, ownerText(h.Owners, h.Socket.Inode)); err != nil {
				return err
			}
		}
	}

	if err := fprintf(w, "\nwhy\n"); err != nil {
		return err
	}
	wrote := false
	for _, r := range v.Reasons {
		if limitReasons[r.Code] {
			continue
		}
		if err := writeReason(w, r); err != nil {
			return err
		}
		wrote = true
	}
	if !wrote {
		if err := fprintf(w, "  - no further detail available\n"); err != nil {
			return err
		}
	}

	hasLimits := !v.TableRead || v.ProcsRead > 0
	for _, r := range v.Reasons {
		if limitReasons[r.Code] {
			hasLimits = true
		}
	}
	if !hasLimits {
		return nil
	}
	if err := fprintf(w, "\nlimits\n"); err != nil {
		return err
	}
	for _, r := range v.Reasons {
		if !limitReasons[r.Code] {
			continue
		}
		if err := writeReason(w, r); err != nil {
			return err
		}
	}
	if v.ProcsRead > 0 {
		if err := fprintf(w, "  - holder lookup walked %d process(es), %d not readable\n",
			v.ProcsRead, v.ProcsDenied); err != nil {
			return err
		}
	}
	return nil
}

// renderScope names the network namespace the answer is about.
//
// The second line is unconditional and deliberately says nothing about the host:
// the tool reads one namespace and cannot see the others, so what it owes the
// reader is the boundary of its own view, not a guess about what is on the other
// side of it. The tables it read cover one namespace even when -tables names a
// directory elsewhere, which is why the wording does not claim to be yours.
func renderScope(w io.Writer, n netns.Identity) error {
	if err := fprintf(w, "scope: %s\n", n.Describe()); err != nil {
		return err
	}
	return fprintf(w, "  the tables read here cover one network namespace; a holder in another "+
		"one cannot be ruled out\n")
}

func writeReason(w io.Writer, r verdict.Reason) error {
	text, ok := reasonSentence[r.Code]
	if !ok {
		// An unregistered code is a bug in this file, not a reason to print
		// nothing: the code itself is still the truth.
		text = r.Code
	}
	if r.Detail != "" {
		return fprintf(w, "  - %s (%s)\n", text, r.Detail)
	}
	return fprintf(w, "  - %s\n", text)
}

// renderProbe prints what was actually attempted, and when.
//
// The word "guarantee" does not appear because the answer cannot be one: a bind
// that succeeded at 12:00:00.100 says nothing about 12:00:00.900. Printing the
// instant is what makes that limitation checkable instead of rhetorical.
func renderProbe(w io.Writer, attempts []probe.Attempt) error {
	if len(attempts) == 0 {
		return nil
	}
	if err := fprintf(w, "\nprobe\n"); err != nil {
		return err
	}
	for _, a := range attempts {
		if err := fprintf(w, "  %-10s at %s  %s\n",
			string(a.Mode), a.At.Format(time.RFC3339), probeOutcomeText(a)); err != nil {
			return err
		}
	}
	return fprintf(w, "  what these attempts found at those instants only; anyone may take or release\n"+
		"  the port afterwards, so none of it is a promise. listen() was never called and\n"+
		"  every socket was closed immediately.\n")
}

// probeOutcomeText renders one attempt, errno included: "it failed" without the
// errno sends the reader looking for a different problem than the one found.
func probeOutcomeText(a probe.Attempt) string {
	var text string
	switch a.Outcome {
	case probe.OutcomeBound:
		text = "bind succeeded, socket closed immediately"
	case probe.OutcomeAddrInUse:
		text = namedErrno(a, "EADDRINUSE", "address already in use")
	case probe.OutcomeNotPermitted:
		text = namedErrno(a, "EACCES", "permission denied") + " — refused before the address was considered"
	case probe.OutcomeAddrNotAvailable:
		text = namedErrno(a, "EADDRNOTAVAIL", "cannot assign requested address") + " — not an address of this host"
	case probe.OutcomeFailed:
		text = namedErrno(a, "?", "") + " — an errno this build does not classify"
	case probe.OutcomeNotRun:
		text = "no bind was attempted"
	}
	if a.Err != "" {
		text += "; not usable as evidence: " + a.Err
	}
	return text
}

func namedErrno(a probe.Attempt, fallbackName, fallbackMessage string) string {
	name := a.Errno
	if name == "" {
		name = fallbackName
	}
	msg := a.Message
	if msg == "" {
		msg = fallbackMessage
	}
	if msg == "" || msg == name {
		return name
	}
	return fmt.Sprintf("%s (%s)", name, msg)
}

// renderRows prints every row on the port, the ones that took part first.
//
// The reason is printed as the code it is; the legend underneath saves the reader
// from having to memorise seven words without turning the column into prose that
// cannot be grepped.
func renderRows(w io.Writer, rows []verdict.Row) error {
	if err := fprintf(w, "\nall rows on this port (--all)\n"); err != nil {
		return err
	}
	if len(rows) == 0 {
		return fprintf(w, "  - no row in the read tables mentions this port number\n")
	}
	for _, r := range rows {
		remote := "-"
		if r.Socket.Remote.Port != 0 {
			remote = r.Socket.Remote.String()
		}
		if err := fprintf(w, "  %-18s %-14s %-22s %-22s inode %d  %s\n",
			r.Match, r.Socket.State, r.Socket.Local.String(), remote, r.Socket.Inode,
			ownerText(r.Owners, r.Socket.Inode)); err != nil {
			return err
		}
	}
	return fprintf(w, "  reasons: matched / released / other-port / other-proto / other-family / "+
		"other-address / wildcard-shadowed\n")
}

func ownerText(owners []verdict.Owner, inode uint64) string {
	if len(owners) == 0 {
		if inode == 0 {
			return "no open descriptor"
		}
		return "owner not visible"
	}
	parts := make([]string, 0, len(owners))
	for _, o := range owners {
		label := fmt.Sprintf("pid %d", o.PID)
		if o.Comm != "" {
			label = fmt.Sprintf("pid %d (%s)", o.PID, o.Comm)
		}
		// The role is what tells a user which of several pids to deal with:
		// killing an inherited holder leaves the socket up on the creator.
		if o.Role != "" {
			label += fmt.Sprintf(" fd %d [%s]", o.FD, o.Role)
		} else {
			label += fmt.Sprintf(" fd %d", o.FD)
		}
		parts = append(parts, label)
	}
	return strings.Join(parts, ", ")
}

func usage(w io.Writer) error {
	return fprintf(w, `portwhy — explain why a port cannot be bound

usage
  portwhy why <host:port> [flags]
  portwhy unix <path|@name> [flags]
  portwhy states
  portwhy version

"unix" asks the other question this tool answers: a unix socket name is not a
port. Two facts decide it — whether a socket in /proc/net/unix carries the name,
and what is at the path — and they can disagree in both directions:
  a socket file with no process behind it still makes bind() fail (remove it);
  a name removed while its socket stayed open is free for a new bind.
It has its own flags: -json, -tables DIR, -proc ROOT, -no-holders. An abstract
name (@name) is never looked up in the filesystem: the two namespaces are
independent.

flags for "why"
  -proto SPEC      tcp, udp or both (default tcp)
                   both answers each protocol separately — a udp bind and a tcp
                   bind are different namespaces — and never folds them into one
                   kind. The exit code then reports the tcp answer; the udp
                   answer and the code it would have had are printed too
  -json            machine-readable report
  -all             also list every row on this port, with why it did or did not
                   take part in the judgement (the judgement does not change)
  -probe           attempt a real bind() and report what the kernel answered:
                   one plain attempt and one with SO_REUSEADDR, never listen().
                   tcp only, so it is a usage error together with -proto both.
                   Exit code may become 3 where the tables had said free, because
                   a refused bind disproves that answer
  -no-holders      skip the /proc/<pid>/fd walk
  -tables DIR      kernel socket table directory (default %s)
  -sysctl DIR      kernel tunable directory (default %s). Four are read:
                   net/ipv6/bindv6only (does a [::] listener also hold IPv4),
                   net/ipv4/ip_local_port_range and
                   net/ipv4/ip_local_reserved_ports (may the kernel hand this
                   port out itself), and
                   net/ipv4/ip_unprivileged_port_start (may this process bind
                   it without a capability). A tunable that cannot be read is
                   reported as a limit, never replaced by the usual value
  -proc ROOT       procfs root used to name holders and to name this process's
                   network namespace (default %s)

every report states its scope
  the first two lines name the network namespace the answer is about, because
  "nothing holds this port" is only ever true of one namespace. portwhy reads
  exactly one and cannot see a holder in another, so it says so instead of
  implying the answer covers the machine

exit codes
  0  free: nothing readable occupies it
  1  taken: a listener, a bound udp socket, a TIME_WAIT reservation, another
     socket, or a unix name that cannot be bound holds it
  2  usage or internal error
  3  unknown: the evidence needed was missing — this is not "free"

example
  portwhy why 127.0.0.1:8080
  portwhy why :53 -proto udp -json
  portwhy why :53 -proto both
  portwhy why :8080 -all
  portwhy why :8080 -probe
  portwhy unix /run/app.sock
  portwhy unix @my-service -json
  portwhy states
`, procnet.DefaultDir, sysctl.DefaultDir, sockid.DefaultRoot)
}

func fprintf(w io.Writer, format string, a ...any) error {
	_, err := fmt.Fprintf(w, format, a...)
	return err
}
