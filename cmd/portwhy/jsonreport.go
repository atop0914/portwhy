package main

// The JSON output is a contract, so the shapes live here rather than inside the
// render functions that fill them. A type defined at package level can be walked
// by a test — which is what docs/json-schema.md is checked against — and a
// reviewer can see the whole file format in one screen.
//
// Three rules decide every field below, and they are the same three the text
// output follows:
//
//  1. A field that was not measured is absent or null, never a zero value. A
//     consumer that reads procs_read: 0 has to be able to tell "the walk was
//     skipped" from "the walk read no process"; a consumer cannot if both spell
//     the same bytes.
//  2. A field that never changes the judgement (the pool range, the capability
//     boundary, the namespace) is evidence, not a kind. Nothing here turns a
//     limit into an answer.
//  3. Same name means same meaning in both reports. The port report and the
//     unix report are different documents about different questions, so their
//     field sets differ; where a name repeats (kind, reasons, target, version,
//     schema_version) it repeats with the same type and the same rule.

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/atop0914/portwhy/internal/netns"
	"github.com/atop0914/portwhy/internal/sysctl"
	"github.com/atop0914/portwhy/internal/verdict"
	"github.com/atop0914/portwhy/internal/version"
	"github.com/atop0914/portwhy/internal/wait"
)

// schemaVersion is the version of the document contract, not of the program.
//
// It is an integer on purpose: a consumer has to be able to say "I understand
// schema 1" and refuse anything else, and that decision cannot be made from a
// program version string. The rules for changing it are in docs/json-schema.md;
// the short form is that adding an optional field does not bump it, and changing
// the meaning or the type of a field does.
const schemaVersion = 1

// portReport is the answer to one port question.
type portReport struct {
	SchemaVersion int           `json:"schema_version"`
	Target        string        `json:"target"`
	Proto         string        `json:"proto"`
	Kind          string        `json:"kind"`
	Findings      []portFinding `json:"findings"`
	Reasons       []reasonJSON  `json:"reasons"`
	Evidence      portEvidence  `json:"evidence"`
	// Version is the program that produced this document. It is not evidence:
	// it says nothing about the port, and putting it inside evidence would
	// invite a consumer to treat it as a measurement.
	Version string `json:"version"`
	// Rows is present only with --all, and present even when it is empty: a
	// consumer must be able to tell "asked, found none" from "did not ask".
	Rows *[]portRow `json:"rows,omitempty"`
	// Probe is present only with --probe, for the same reason: absence means the
	// experiment was not run, and no zero value stands in for it.
	Probe *portProbe `json:"probe,omitempty"`
}

// bothReport answers -proto both without merging the two answers.
//
// A consumer that received one object with "kind: bound" and both protocols'
// findings would have no way to tell which row belonged to which question. The
// wrapper names the exit-code rule in the payload, so a script that only reads
// JSON is told the same thing the text reader is.
type bothReport struct {
	SchemaVersion int        `json:"schema_version"`
	Target        string     `json:"target"`
	Both          bool       `json:"both"`
	ExitFrom      string     `json:"exit_from"`
	TCP           portReport `json:"tcp"`
	UDP           portReport `json:"udp"`
}

// portProbe carries the attempts and the sentence that keeps them from being
// mistaken for a promise. There is no field for a guarantee, deliberately.
type portProbe struct {
	Attempts []probeAttemptJSON `json:"attempts"`
	Note     string             `json:"note"`
}

type probeAttemptJSON struct {
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

type portFinding struct {
	State  string      `json:"state"`
	Effect string      `json:"effect"`
	Local  string      `json:"local"`
	Remote string      `json:"remote,omitempty"`
	Inode  uint64      `json:"inode"`
	Table  string      `json:"table"`
	Owners []ownerJSON `json:"owners"`
}

// portRow is one line of the --all listing: the row, and why it did or did not
// take part.
type portRow struct {
	Match  string      `json:"match"`
	State  string      `json:"state"`
	Effect string      `json:"effect"`
	Local  string      `json:"local"`
	Remote string      `json:"remote,omitempty"`
	Inode  uint64      `json:"inode"`
	Table  string      `json:"table"`
	Owners []ownerJSON `json:"owners"`
}

type ownerJSON struct {
	PID  int    `json:"pid"`
	Comm string `json:"comm,omitempty"`
	FD   int    `json:"fd"`
	Role string `json:"role,omitempty"`
}

type reasonJSON struct {
	Code   string `json:"code"`
	Detail string `json:"detail,omitempty"`
}

// waitReport is the answer to "did it become bindable, and if not, why did the
// wait stop looking".
//
// It is a fourth document rather than a portReport with a timeline attached: the
// port report answers about one instant, this one about an interval, and a shared
// shape would have to leave half its fields empty in both uses. The names that
// repeat (target, proto, kind, version, schema_version) repeat with the same type
// and the same rule about absence.
type waitReport struct {
	SchemaVersion int    `json:"schema_version"`
	Target        string `json:"target"`
	Proto         string `json:"proto"`
	Kind          string `json:"kind"`
	// End is why the loop stopped: bound, timeout, or stopped. It is not inferred
	// from kind, because a timeout can end on "taken" while a stop ends on
	// "unknown" — and a consumer that only saw kind could not tell the two apart.
	End string `json:"end"`
	// Stop names the answer that made further waiting pointless. It is present only
	// when end is "stopped": absence means the deadline ran out.
	Stop string `json:"stop,omitempty"`
	// Timeout is an object because zero milliseconds is a real deadline (bind
	// immediately, once) while no deadline at all is not a number. `forever` is the
	// switch; `ms` is null when it is set.
	Timeout          waitTimeoutJSON `json:"timeout"`
	IntervalMS       int64           `json:"interval_ms"`
	WaitedMS         int64           `json:"waited_ms"`
	Rounds           int             `json:"rounds"`
	Attempts         int             `json:"attempts"`
	UnreadableRounds int             `json:"unreadable_rounds"`
	// Timeline is the first round, every round whose kind changed, and the round
	// the wait ended on. It is not a log: identical rounds collapse, and a consumer
	// that needs every round should count them, not read them.
	Timeline []waitStepJSON `json:"timeline"`
	// Note is the side-effect disclosure, in the same words the text output uses.
	// It is a field rather than documentation because the effects are per round.
	Note    string `json:"note"`
	Version string `json:"version"`
}

// waitTimeoutJSON keeps "no deadline" out of the integer space.
type waitTimeoutJSON struct {
	Forever bool   `json:"forever"`
	MS      *int64 `json:"ms"`
}

// waitStepJSON is one row of the timeline.
type waitStepJSON struct {
	Round int    `json:"round"`
	AtMS  int64  `json:"at_ms"`
	Kind  string `json:"kind"`
	// TableKind is what the tables alone said. It is present even when it differs
	// from kind, which is the whole point: a disagreement between two measurements
	// is information, not noise to be reconciled silently.
	TableKind string       `json:"table_kind"`
	Note      string       `json:"note,omitempty"`
	Stop      string       `json:"stop,omitempty"`
	Bind      waitBindJSON `json:"bind"`
}

// waitBindJSON is the attempt behind one row. It repeats the fields of a probe
// attempt on purpose: a consumer of this document must not have to know that the
// other document spells them the same way.
type waitBindJSON struct {
	Outcome          string `json:"outcome"`
	Errno            string `json:"errno,omitempty"`
	Message          string `json:"message,omitempty"`
	Error            string `json:"error,omitempty"`
	UsableAsEvidence bool   `json:"usable_as_evidence"`
}

// batchError is the object for a line of a batch that never became a question.
//
// It carries no evidence, no findings and no reasons: nothing was measured and
// nothing was judged, and a zero-valued report would say both had happened. That
// is why it is a different shape rather than a portReport with kind "usage" — and
// why the rule "usage is the only kind without evidence" is written down.
type batchError struct {
	SchemaVersion int    `json:"schema_version"`
	Target        string `json:"target"`
	Kind          string `json:"kind"`
	Error         string `json:"error"`
	Version       string `json:"version"`
}

type portEvidence struct {
	TablesRead       int              `json:"tables_read"`
	TablesUnreadable []tableHoleJSON  `json:"tables_unreadable"`
	Holders          holderLookupJSON `json:"holder_lookup"`
	// BindV6Only is the tunable an IPv6 wildcard answer depends on. It is always
	// present, including when it could not be read: a consumer that only sees a
	// value would never learn that the value was missing.
	BindV6Only bindV6OnlyJSON `json:"bindv6only"`
	// EphemeralRange and ReservedPorts are the port-pool evidence. They are
	// always present for the same reason: "not read" has to be visible as such.
	EphemeralRange portRangeJSON     `json:"ephemeral_range"`
	ReservedPorts  reservedPortsJSON `json:"reserved_ports"`
	// NetNS is the namespace this report is about. A consumer that files the
	// answer somewhere durable needs to know which namespace it describes.
	NetNS netnsJSON `json:"netns"`
	// UnprivilegedPortStart is the capability boundary. Always present, and
	// measured=false with no value is the only honest form of "not read".
	UnprivilegedPortStart privStartJSON `json:"unprivileged_port_start"`
}

// tableHoleJSON is one table that should have answered and did not.
//
// Present is what keeps "this kernel has no tcp6" from reading as "I was not
// allowed to read tcp6". Both are holes, and only the second one is something
// the user can act on, so the document has to say which one it is.
type tableHoleJSON struct {
	Name    string `json:"name"`
	Present bool   `json:"present"`
	Error   string `json:"error,omitempty"`
}

// holderLookupJSON says whether /proc was walked at all.
//
// A bare procs_read: 0 cannot tell "the walk was skipped" from "the walk read no
// process", and that is the same mistake as reporting a failed measurement as
// zero everywhere else in this document. Attempted is the switch; the counts are
// absent (null) until a walk actually happened, and stay absent when the walk
// failed, because a count from a failed walk is not a count.
type holderLookupJSON struct {
	Attempted   bool   `json:"attempted"`
	ProcsRead   *int   `json:"procs_read"`
	ProcsDenied *int   `json:"procs_denied"`
	Error       string `json:"error,omitempty"`
}

// netnsJSON keeps the two halves of the reading apart: Error is "this process's
// namespace was not read", ComparisonError is "pid 1's was not, so nothing was
// compared". SameAsPIDOne is a pointer so that "no comparison" is null rather
// than false — false would claim a difference nobody measured.
type netnsJSON struct {
	Inode           uint64 `json:"inode,omitempty"`
	Self            string `json:"self,omitempty"`
	PIDOne          string `json:"pid_one,omitempty"`
	SameAsPIDOne    *bool  `json:"same_as_pid_one"`
	Path            string `json:"path"`
	Error           string `json:"error,omitempty"`
	ComparisonError string `json:"comparison_error,omitempty"`
}

// privStartJSON follows the same shape as the other tunables: Measured says a
// number was read (so Value is authoritative), Present says the file exists at
// all. Measured=false + Present=true is a file that could not be understood;
// Measured=false + Present=false is a kernel that does not offer the tunable.
// Neither of them is 1024.
type privStartJSON struct {
	Measured bool   `json:"measured"`
	Present  bool   `json:"present"`
	Value    *int   `json:"value,omitempty"`
	Raw      string `json:"raw,omitempty"`
	Path     string `json:"path"`
	Error    string `json:"error,omitempty"`
}

// portRangeJSON has no zero value that reads as a measurement. Measured is the
// switch and Low/High are pointers, so a failed read can never be decoded as the
// interval 0-0 — which would claim every port on the host is outside the pool.
type portRangeJSON struct {
	Measured bool   `json:"measured"`
	Low      *int   `json:"low,omitempty"`
	High     *int   `json:"high,omitempty"`
	Raw      string `json:"raw,omitempty"`
	Path     string `json:"path"`
	Error    string `json:"error,omitempty"`
}

// reservedPortsJSON keeps the three states apart with two switches rather than
// one: Measured says the file was read (so Ports is authoritative, [] meaning
// "none reserved"), Present says the tunable exists at all. Measured=false with
// Present=false is a kernel without the tunable; Measured=false with
// Present=true is a file that could not be understood.
type reservedPortsJSON struct {
	Measured bool     `json:"measured"`
	Present  bool     `json:"present"`
	Ports    []string `json:"ports"`
	Raw      string   `json:"raw,omitempty"`
	Path     string   `json:"path"`
	Error    string   `json:"error,omitempty"`
}

// bindV6OnlyJSON has no zero value that reads as a measurement. Measured is the
// switch, and Value is a pointer so that a failed read cannot be decoded as 0 —
// the one mistake that would turn "I could not look" into "dual-stack".
type bindV6OnlyJSON struct {
	Measured bool   `json:"measured"`
	Value    *int   `json:"value,omitempty"`
	Raw      string `json:"raw,omitempty"`
	Path     string `json:"path"`
	Error    string `json:"error,omitempty"`
}

// unixReport is the answer to one unix socket name question.
//
// "path" is omitted for an abstract name: there is no path, and a zero-valued
// object saying exists=false would be a claim about a filesystem lookup that was
// deliberately not made.
type unixReport struct {
	SchemaVersion int              `json:"schema_version"`
	Target        string           `json:"target"`
	Abstract      bool             `json:"abstract"`
	Kind          string           `json:"kind"`
	Holders       []unixHolderJSON `json:"holders"`
	Reasons       []reasonJSON     `json:"reasons"`
	Path          *unixPathJSON    `json:"path,omitempty"`
	Evidence      unixEvidenceJSON `json:"evidence"`
	Version       string           `json:"version"`
}

type unixHolderJSON struct {
	Inode     uint64      `json:"inode"`
	Type      string      `json:"type"`
	State     string      `json:"state"`
	Listening bool        `json:"listening"`
	Owners    []ownerJSON `json:"owners"`
}

type unixPathJSON struct {
	Measured bool   `json:"measured"`
	Exists   bool   `json:"exists"`
	Kind     string `json:"kind,omitempty"`
	Error    string `json:"error,omitempty"`
}

// tableJSON is the unix table's own evidence.
//
// Read and Present are two switches rather than one because they answer two
// questions: "did I get the rows" and "does this kernel have the table". A
// document with only Read=false cannot tell a kernel without /proc/net/unix
// from a procfs this process may not open.
type tableJSON struct {
	Read    bool   `json:"read"`
	Present bool   `json:"present"`
	Error   string `json:"error,omitempty"`
}

type unixEvidenceJSON struct {
	Table   tableJSON        `json:"table"`
	Holders holderLookupJSON `json:"holder_lookup"`
}

// holderLookupJSONOf builds the walk's evidence from a verdict. A walk that
// failed reports no counts: the numbers exist, but they describe a walk that did
// not finish, and printing them would invite a consumer to divide by them.
func holderLookupJSONOf(attempted bool, read, denied int, errMsg string) holderLookupJSON {
	out := holderLookupJSON{Attempted: attempted, Error: errMsg}
	if attempted && errMsg == "" {
		r, d := read, denied
		out.ProcsRead, out.ProcsDenied = &r, &d
	}
	return out
}

func ownersJSON(owners []verdict.Owner) []ownerJSON {
	out := make([]ownerJSON, 0, len(owners))
	for _, o := range owners {
		out = append(out, ownerJSON{PID: o.PID, Comm: o.Comm, FD: o.FD, Role: o.Role.String()})
	}
	return out
}

func netnsJSONOf(n netns.Identity) netnsJSON {
	out := netnsJSON{
		Inode:           n.Inode,
		Self:            n.Self,
		PIDOne:          n.PIDOne,
		Path:            n.Path,
		Error:           n.Err,
		ComparisonError: n.SameErr,
	}
	switch n.Same {
	case netns.PIDOneSame:
		same := true
		out.SameAsPIDOne = &same
	case netns.PIDOneDifferent:
		same := false
		out.SameAsPIDOne = &same
	}
	return out
}

func privStartJSONOf(p sysctl.PrivilegedPortStart) privStartJSON {
	out := privStartJSON{
		Measured: p.Known(),
		Present:  !p.Absent(),
		Path:     p.Path,
		Error:    p.Err,
	}
	if p.Known() {
		value := int(p.Port)
		out.Value = &value
		out.Raw = trimRaw(p.Raw)
	}
	return out
}

func portRangeJSONOf(p sysctl.PortRange) portRangeJSON {
	out := portRangeJSON{Path: p.Path, Error: p.Err}
	if p.Known() {
		low, high := int(p.Low), int(p.High)
		out.Measured = true
		out.Low, out.High = &low, &high
		out.Raw = trimRaw(p.Raw)
	}
	return out
}

func reservedPortsJSONOf(r sysctl.ReservedPorts) reservedPortsJSON {
	out := reservedPortsJSON{
		Measured: r.Known(),
		Present:  !r.Absent(),
		Ports:    make([]string, 0, len(r.Intervals)),
		Path:     r.Path,
		Error:    r.Err,
	}
	for _, iv := range r.Intervals {
		out.Ports = append(out.Ports, iv.String())
	}
	if r.Known() {
		out.Raw = trimRaw(r.Raw)
	}
	return out
}

// tableHolesJSON never returns nil: an empty list is the contract, and a null
// would make "all four tables were read" indistinguishable from "the field was
// not written".
func tableHolesJSON(holes []verdict.TableHole) []tableHoleJSON {
	out := make([]tableHoleJSON, 0, len(holes))
	for _, h := range holes {
		out = append(out, tableHoleJSON{Name: h.Name, Present: !h.Missing, Error: h.Err})
	}
	return out
}

func bindV6OnlyJSONOf(b sysctl.BindV6Only) bindV6OnlyJSON {
	out := bindV6OnlyJSON{Path: b.Path, Error: b.Err}
	if v, ok := b.Value(); ok {
		value := v
		out.Measured = true
		out.Value = &value
		out.Raw = trimRaw(b.Raw)
	}
	return out
}

// buildPortReport turns one verdict into the JSON document. It is a separate
// function because the two-protocol report embeds two of them.
func buildPortReport(v verdict.Verdict) portReport {
	rep := portReport{
		SchemaVersion: schemaVersion,
		Target:        v.Query.Addr.String(),
		Proto:         v.Query.Proto.String(),
		Kind:          string(v.Kind),
		Findings:      make([]portFinding, 0, len(v.Findings)),
		Reasons:       make([]reasonJSON, 0, len(v.Reasons)),
		Evidence: portEvidence{
			TablesRead:            v.TablesRead,
			TablesUnreadable:      tableHolesJSON(v.TablesUnreadable),
			Holders:               holderLookupJSONOf(v.HoldersAttempted, v.ProcsRead, v.ProcsDenied, v.HoldersErr),
			BindV6Only:            bindV6OnlyJSONOf(v.V6Only),
			EphemeralRange:        portRangeJSONOf(v.Ephemeral),
			ReservedPorts:         reservedPortsJSONOf(v.Reserved),
			NetNS:                 netnsJSONOf(v.NetNS),
			UnprivilegedPortStart: privStartJSONOf(v.Privileged),
		},
		Version: version.Resolve().Version,
	}
	for _, f := range v.Findings {
		jf := portFinding{
			State:  f.Socket.State.String(),
			Effect: f.Socket.Binding().String(),
			Local:  f.Socket.Local.String(),
			Inode:  f.Socket.Inode,
			Table:  f.Socket.Table,
			Owners: ownersJSON(f.Owners),
		}
		if f.Socket.Remote.Port != 0 {
			jf.Remote = f.Socket.Remote.String()
		}
		rep.Findings = append(rep.Findings, jf)
	}
	if v.All != nil {
		rows := make([]portRow, 0, len(v.All))
		for _, r := range v.All {
			jr := portRow{
				Match:  string(r.Match),
				State:  r.Socket.State.String(),
				Effect: r.Socket.Binding().String(),
				Local:  r.Socket.Local.String(),
				Inode:  r.Socket.Inode,
				Table:  r.Socket.Table,
				Owners: ownersJSON(r.Owners),
			}
			if r.Socket.Remote.Port != 0 {
				jr.Remote = r.Socket.Remote.String()
			}
			rows = append(rows, jr)
		}
		rep.Rows = &rows
	}
	if len(v.Probe) > 0 {
		jp := portProbe{
			Attempts: make([]probeAttemptJSON, 0, len(v.Probe)),
			Note: "one bind() per attempt at the time shown, listen() never called, socket closed " +
				"immediately; the port may be taken or released afterwards",
		}
		for _, a := range v.Probe {
			jp.Attempts = append(jp.Attempts, probeAttemptJSON{
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
		rep.Reasons = append(rep.Reasons, reasonJSON{Code: r.Code, Detail: r.Detail})
	}
	return rep
}

func buildUnixReport(v verdict.UnixVerdict) unixReport {
	rep := unixReport{
		SchemaVersion: schemaVersion,
		Target:        v.Query.Name,
		Abstract:      v.Query.Abstract,
		Kind:          string(v.Kind),
		Holders:       make([]unixHolderJSON, 0, len(v.Holders)),
		Reasons:       make([]reasonJSON, 0, len(v.Reasons)),
		Evidence: unixEvidenceJSON{
			Table: tableJSON{
				Read:    v.TableRead,
				Present: !v.TableMissing,
				Error:   v.TableErr,
			},
			Holders: holderLookupJSONOf(v.HoldersAttempted, v.ProcsRead, v.ProcsDenied, v.HoldersErr),
		},
		Version: version.Resolve().Version,
	}
	if !v.Query.Abstract {
		rep.Path = &unixPathJSON{
			Measured: v.Path.Measured,
			Exists:   v.Path.Exists,
			Kind:     v.Path.Kind,
			Error:    v.Path.Err,
		}
	}
	for _, h := range v.Holders {
		rep.Holders = append(rep.Holders, unixHolderJSON{
			Inode:     h.Socket.Inode,
			Type:      h.Socket.Type.String(),
			State:     h.Socket.State.String(),
			Listening: h.Socket.Listening(),
			Owners:    ownersJSON(h.Owners),
		})
	}
	for _, r := range v.Reasons {
		rep.Reasons = append(rep.Reasons, reasonJSON{Code: r.Code, Detail: r.Detail})
	}
	return rep
}

// buildWaitReport turns the loop's result into the document.
//
// Nothing here recomputes an answer: every number is a count the loop made, and
// every kind is the kind of the round it came from. A builder that recalculated
// anything would be a second place for the rules to live.
func buildWaitReport(res wait.Result, p waitParams) waitReport {
	rep := waitReport{
		SchemaVersion:    schemaVersion,
		Target:           p.Addr.String(),
		Proto:            p.Proto.String(),
		Kind:             string(res.Kind),
		End:              string(res.End),
		Stop:             res.Stop,
		IntervalMS:       p.Interval.Milliseconds(),
		WaitedMS:         res.Waited.Milliseconds(),
		Rounds:           res.Rounds,
		Attempts:         res.Attempts,
		UnreadableRounds: res.Unreadable,
		Timeline:         make([]waitStepJSON, 0, len(res.Timeline)),
		Note:             waitNote(),
		Version:          version.Resolve().String(),
	}
	if p.Timeout > 0 {
		ms := p.Timeout.Milliseconds()
		rep.Timeout.MS = &ms
	} else {
		// No deadline is not a duration of zero: that would be a deadline that has
		// already passed.
		rep.Timeout.Forever = true
	}
	for _, r := range res.Timeline {
		rep.Timeline = append(rep.Timeline, waitStepJSON{
			Round:     r.Index,
			AtMS:      r.At.Milliseconds(),
			Kind:      string(r.Kind),
			TableKind: string(r.TableKind),
			Note:      r.Note,
			Stop:      r.Stop,
			Bind: waitBindJSON{
				Outcome:          string(r.Bind.Outcome),
				Errno:            r.Bind.Errno,
				Message:          r.Bind.Message,
				Error:            r.Bind.Err,
				UsableAsEvidence: r.Bind.Trustworthy(),
			},
		})
	}
	return rep
}

// renderJSON and renderJSONBoth are the two entry points the CLI uses; they
// exist so the call sites read as "render", not as "build then encode".
func renderJSON(w io.Writer, v verdict.Verdict) error {
	return encodeJSON(w, buildPortReport(v))
}

// renderWaitJSON is the wait document. It is a separate entry point because the
// command has no verdict to hand it: a wait ends on a result, not on one answer.
func renderWaitJSON(w io.Writer, res wait.Result, p waitParams) error {
	return encodeJSON(w, buildWaitReport(res, p))
}

func renderJSONBoth(w io.Writer, tcp, udp verdict.Verdict) error {
	return encodeJSON(w, bothReport{
		SchemaVersion: schemaVersion,
		Target:        tcp.Query.Addr.String(),
		Both:          true,
		ExitFrom:      "tcp",
		TCP:           buildPortReport(tcp),
		UDP:           buildPortReport(udp),
	})
}

// trimRaw strips the newline a /proc/sys file ends with. The raw text is kept
// in the document for a reader who wants to see exactly what the kernel said.
func trimRaw(s string) string { return strings.TrimSpace(s) }

// encodeJSON writes one document. Indented for a human reading a report, and
// without a trailing blank line beyond the one Encode adds.
func encodeJSON(w io.Writer, payload any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(payload); err != nil {
		return fmt.Errorf("encode json: %w", err)
	}
	return nil
}
