// Command portwhy explains why a TCP or UDP port cannot be bound.
//
// The command has one job and one rule: every sentence it prints has to be
// backed by something it read or something it tried. It prints "I could not
// tell" as its own answer, with its own exit code, because a diagnostic tool
// that guesses is worse than one that is missing.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/atop0914/portwhy/internal/probe"
	"github.com/atop0914/portwhy/internal/procnet"
	"github.com/atop0914/portwhy/internal/sockid"
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

// runStates prints the state vocabulary: every TCP state the kernel can report,
// with what it does to a bind().
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
	if err := fprintf(stdout, "  %-6s %-14s %-15s %s\n", "code", "name", "bind effect", "what it means"); err != nil {
		_ = fprintf(stderr, "portwhy: %v\n", err)
		return exitUsage
	}
	for _, s := range procnet.KnownStates() {
		if err := fprintf(stdout, "  0x%02x   %-14s %-15s %s\n",
			uint8(s), s.String(), s.Binding(), s.Note()); err != nil {
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
	return exitFree
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
	proto := fs.String("proto", "tcp", "protocol to check: tcp or udp")
	asJSON := fs.Bool("json", false, "emit a JSON report instead of text")
	tableDir := fs.String("tables", procnet.DefaultDir, "directory holding the kernel socket tables")
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

	q, err := parseQuery(fs.Arg(0), *proto)
	if err != nil {
		_ = fprintf(stderr, "portwhy: %v\n", err)
		return exitUsage
	}

	// The probe answers the TCP question — "does bind() on this stream socket
	// fail". A UDP probe would be a different experiment (no listener concept, no
	// TIME_WAIT), so offering one today would mean reporting the result of one
	// experiment as the answer to the other.
	if *useProbe && q.Proto != procnet.TCP {
		_ = fprintf(stderr, "portwhy: -probe is tcp only; a udp probe would answer a different question, "+
			"so this version does not pretend to make one\n")
		return exitUsage
	}

	tables := procnet.ReadAll(*tableDir)

	env := verdict.Env{}
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
		env.Probe = probe.Both(netip.AddrPortFrom(q.Addr.IP, q.Addr.Port))
	}

	// --all adds rows; it never re-decides. ExplainAll calls Explain and then
	// attaches the neighbours, so the kind and the exit code cannot depend on the
	// flag — that is a property of the code, not a promise in the help text.
	var v verdict.Verdict
	if *showAll {
		v = verdict.ExplainAll(q, tables, env)
	} else {
		v = verdict.Explain(q, tables, env)
	}

	if *asJSON {
		err = renderJSON(stdout, v)
	} else {
		err = renderText(stdout, v)
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

func parseQuery(target, proto string) (verdict.Query, error) {
	p, err := parseProto(proto)
	if err != nil {
		return verdict.Query{}, err
	}
	addr, err := parseTarget(target)
	if err != nil {
		return verdict.Query{}, err
	}
	return verdict.Query{Addr: addr, Proto: p}, nil
}

func parseProto(s string) (procnet.Proto, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "tcp":
		return procnet.TCP, nil
	case "udp":
		return procnet.UDP, nil
	}
	return 0, fmt.Errorf("-proto %q is not tcp or udp", s)
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
	verdict.KindTimeWaitOnly:         "only TIME_WAIT rows hold it",
	verdict.KindOccupiedNonListening: "sockets hold it, but none of them is listening",
	verdict.KindUnknown:              "cannot be determined from what was readable",
}

var reasonSentence = map[string]string{
	verdict.ReasonNoSockets:       "no row in the read tables matches this address",
	verdict.ReasonListener:        "bind() to an address a listener holds fails with EADDRINUSE",
	verdict.ReasonTimeWait:        "the reservation belongs to a closed connection, not to a running process",
	verdict.ReasonOtherState:      "a bound socket in a non-listening state holds this address; whether bind() fails depends on socket options",
	verdict.ReasonTableUnreadable: "a socket table could not be read, so absence of a row proves nothing",
	verdict.ReasonV6Wildcard:      "an IPv6 wildcard listener may also occupy IPv4, depending on net.ipv6.bindv6only",
	verdict.ReasonNoOwnerInode:    "a row with inode 0 has no descriptor behind it (TIME_WAIT, or a socket closed and waiting out its timeout), so no process can be named for it",
	verdict.ReasonProcsDenied:     "some processes could not be read, so an unnamed holder may exist",
	verdict.ReasonProbeNotRun:     "no bind was attempted: this verdict comes from kernel state only",
	verdict.ReasonTeardown:        "rows on this address belong to sockets the kernel is already destroying, so they do not hold the port",
	verdict.ReasonUnknownState:    "a row used a state code this build does not know, so what it does to a bind cannot be stated",
	verdict.ReasonUnlistedBinding: "a socket bound without listen() holds the port and has no row in these tables, so this answer cannot rule that out",
	verdict.ReasonProbeBound:      "a plain bind succeeded, so the tables' silence was accurate at that instant and nothing — including a socket bound without listen() — held the address",
	verdict.ReasonProbeRefused:    "a plain bind was refused, which is what the rows above predict",
	verdict.ReasonProbeHolds:      "a plain bind was refused while no row covers the address: something bound this port without listen(), and no table lists it",
	verdict.ReasonProbeOption:     "a plain bind is refused but SO_REUSEADDR succeeds: the reservation belongs to a closed connection, not to a running process",
	verdict.ReasonProbeDenied:     "the bind probe could not be made, so nothing was learned about the address — this is not a free port",
	verdict.ReasonProbeGap:        "the probe evidence lacks the plain attempt that any conclusion about binding needs",
	verdict.ReasonProbeConflict:   "the tables and the probe describe different instants, and this version cannot say which one you are facing",
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
	verdict.ReasonUnlistedBinding: true,
}

func renderText(w io.Writer, v verdict.Verdict) error {
	if err := fprintf(w, "%s/%s — %s\n", v.Query.Addr, v.Query.Proto, kindSentence[v.Kind]); err != nil {
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

// JSON types are defined here, not on the domain types, so that the file format
// is a decision someone made rather than a side effect of Go field names.
type jsonReport struct {
	Target   string        `json:"target"`
	Proto    string        `json:"proto"`
	Kind     string        `json:"kind"`
	Findings []jsonFinding `json:"findings"`
	Reasons  []jsonReason  `json:"reasons"`
	Evidence jsonEvidence  `json:"evidence"`
	Version  string        `json:"version"`
	// Rows is present only with --all, and present even when it is empty: a
	// consumer must be able to tell "asked, found none" from "did not ask".
	Rows *[]jsonRow `json:"rows,omitempty"`
	// Probe is present only with --probe, for the same reason: absence means the
	// experiment was not run, and no zero value stands in for it.
	Probe *jsonProbe `json:"probe,omitempty"`
}

// jsonProbe carries the attempts and the sentence that keeps them from being
// mistaken for a promise. There is no field for a guarantee, deliberately.
type jsonProbe struct {
	Attempts []jsonAttempt `json:"attempts"`
	Note     string        `json:"note"`
}

type jsonAttempt struct {
	Mode    string `json:"mode"`
	At      string `json:"at"`
	Outcome string `json:"outcome"`
	Errno   string `json:"errno,omitempty"`
	Message string `json:"message,omitempty"`
	// Error is set when the attempt itself is not trustworthy (socket() refused,
	// close() failed); a consumer that ignores it would read a broken attempt as
	// a result.
	Error            string `json:"error,omitempty"`
	UsableAsEvidence bool   `json:"usable_as_evidence"`
}

type jsonFinding struct {
	State  string      `json:"state"`
	Effect string      `json:"effect"`
	Local  string      `json:"local"`
	Remote string      `json:"remote,omitempty"`
	Inode  uint64      `json:"inode"`
	Table  string      `json:"table"`
	Owners []jsonOwner `json:"owners"`
}

// jsonRow is one line of the --all listing: the row, and why it did or did not
// take part.
type jsonRow struct {
	Match  string      `json:"match"`
	State  string      `json:"state"`
	Effect string      `json:"effect"`
	Local  string      `json:"local"`
	Remote string      `json:"remote,omitempty"`
	Inode  uint64      `json:"inode"`
	Table  string      `json:"table"`
	Owners []jsonOwner `json:"owners"`
}

type jsonOwner struct {
	PID  int    `json:"pid"`
	Comm string `json:"comm,omitempty"`
	FD   int    `json:"fd"`
	Role string `json:"role,omitempty"`
}

func jsonOwners(owners []verdict.Owner) []jsonOwner {
	out := make([]jsonOwner, 0, len(owners))
	for _, o := range owners {
		out = append(out, jsonOwner{PID: o.PID, Comm: o.Comm, FD: o.FD, Role: o.Role.String()})
	}
	return out
}

type jsonReason struct {
	Code   string `json:"code"`
	Detail string `json:"detail,omitempty"`
}

type jsonEvidence struct {
	TablesRead       int      `json:"tables_read"`
	TablesUnreadable []string `json:"tables_unreadable"`
	ProcsRead        int      `json:"procs_read"`
	ProcsDenied      int      `json:"procs_denied"`
}

func renderJSON(w io.Writer, v verdict.Verdict) error {
	rep := jsonReport{
		Target:   v.Query.Addr.String(),
		Proto:    v.Query.Proto.String(),
		Kind:     string(v.Kind),
		Findings: make([]jsonFinding, 0, len(v.Findings)),
		Reasons:  make([]jsonReason, 0, len(v.Reasons)),
		Evidence: jsonEvidence{
			TablesRead:       v.TablesRead,
			TablesUnreadable: v.TablesUnreadable,
			ProcsRead:        v.ProcsRead,
			ProcsDenied:      v.ProcsDenied,
		},
		Version: version.Resolve().Version,
	}
	if rep.Evidence.TablesUnreadable == nil {
		rep.Evidence.TablesUnreadable = []string{}
	}
	for _, f := range v.Findings {
		jf := jsonFinding{
			State:  f.Socket.State.String(),
			Effect: f.Socket.State.Binding().String(),
			Local:  f.Socket.Local.String(),
			Inode:  f.Socket.Inode,
			Table:  f.Socket.Table,
			Owners: jsonOwners(f.Owners),
		}
		if f.Socket.Remote.Port != 0 {
			jf.Remote = f.Socket.Remote.String()
		}
		rep.Findings = append(rep.Findings, jf)
	}
	if v.All != nil {
		rows := make([]jsonRow, 0, len(v.All))
		for _, r := range v.All {
			jr := jsonRow{
				Match:  string(r.Match),
				State:  r.Socket.State.String(),
				Effect: r.Socket.State.Binding().String(),
				Local:  r.Socket.Local.String(),
				Inode:  r.Socket.Inode,
				Table:  r.Socket.Table,
				Owners: jsonOwners(r.Owners),
			}
			if r.Socket.Remote.Port != 0 {
				jr.Remote = r.Socket.Remote.String()
			}
			rows = append(rows, jr)
		}
		rep.Rows = &rows
	}
	if len(v.Probe) > 0 {
		jp := jsonProbe{
			Attempts: make([]jsonAttempt, 0, len(v.Probe)),
			Note: "one bind() per attempt at the time shown, listen() never called, socket closed " +
				"immediately; the port may be taken or released afterwards",
		}
		for _, a := range v.Probe {
			jp.Attempts = append(jp.Attempts, jsonAttempt{
				Mode:             string(a.Mode),
				At:               a.At.Format(time.RFC3339),
				Outcome:          string(a.Outcome),
				Errno:            a.Errno,
				Message:          a.Message,
				Error:            a.Err,
				UsableAsEvidence: a.Trustworthy(),
			})
		}
		rep.Probe = &jp
	}
	for _, r := range v.Reasons {
		rep.Reasons = append(rep.Reasons, jsonReason{Code: r.Code, Detail: r.Detail})
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rep); err != nil {
		return fmt.Errorf("encode json: %w", err)
	}
	return nil
}

func usage(w io.Writer) error {
	return fprintf(w, `portwhy — explain why a port cannot be bound

usage
  portwhy why <host:port> [flags]
  portwhy states
  portwhy version

flags for "why"
  -proto tcp|udp   protocol to check (default tcp)
  -json            machine-readable report
  -all             also list every row on this port, with why it did or did not
                   take part in the judgement (the judgement does not change)
  -probe           attempt a real bind() and report what the kernel answered:
                   one plain attempt and one with SO_REUSEADDR, never listen().
                   tcp only. Exit code may become 3 where the tables had said
                   free, because a refused bind disproves that answer
  -no-holders      skip the /proc/<pid>/fd walk
  -tables DIR      kernel socket table directory (default %s)
  -proc ROOT       procfs root used to name holders (default %s)

exit codes
  0  free: nothing readable occupies it
  1  taken: a listener, a TIME_WAIT reservation or another socket holds it
  2  usage or internal error
  3  unknown: the evidence needed was missing — this is not "free"

example
  portwhy why 127.0.0.1:8080
  portwhy why :53 -proto udp -json
  portwhy why :8080 -all
  portwhy why :8080 -probe
  portwhy states
`, procnet.DefaultDir, sockid.DefaultRoot)
}

func fprintf(w io.Writer, format string, a ...any) error {
	_, err := fmt.Fprintf(w, format, a...)
	return err
}
