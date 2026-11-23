package main

// Batch mode answers many targets in one run, one JSON object per line.
//
// The rules it follows are the rules the single-target mode follows, applied N
// times: one target, one answer, one exit code's worth of opinion, and a line
// that could not become a question says so instead of vanishing. What batch adds
// is an aggregation rule and a shape that a stream consumer can parse without
// knowing how many answers were asked for.
//
// Two things are deliberately refused rather than supported:
//
//   - -probe, because each attempt is a real bind() and N binds are N side
//     effects. They have to be opted into one at a time, not by the hundred.
//   - unix names, because "why can't this port be bound" and "why can't this
//     unix name be bound" are two questions with two document shapes, and a
//     single stream that mixed them would make every consumer branch on shape
//     before it could read a kind.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/atop0914/portwhy/internal/procnet"
	"github.com/atop0914/portwhy/internal/verdict"
	"github.com/atop0914/portwhy/internal/version"
)

// kindUsage is the kind of a line that never became a question.
//
// It is not a verdict.Kind: nothing was judged, so no verdict exists. It uses the
// same field name as the other documents so that a consumer can switch on kind
// first and then decide whether to look for evidence — and the rule that makes
// that safe is stated once, in docs/json-schema.md: usage is the only kind that
// carries error and no evidence.
const kindUsage = "usage"

// runBatch reads targets from stdin and writes one JSON object per line.
//
// The tables and the environment are read once, before the first line, and every
// line is answered from that snapshot. That is a deliberate choice over reading
// again per line: a monitor asking about 200 ports gets 200 answers about the
// same instant, which is a fact it can reason about, instead of 200 answers about
// 200 instants it cannot.
func runBatch(protos []procnet.Proto, showAll bool, tables []procnet.Table, base verdict.Env,
	stdin io.Reader, stdout, stderr io.Writer,
) int {
	out := bufio.NewWriter(stdout)
	sc := bufio.NewScanner(stdin)
	// Targets are short, but a caller piping a log through a transform should
	// get a parse error rather than a truncated target.
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)

	worst := exitFree
	answered := 0
	for sc.Scan() {
		target := strings.TrimSpace(sc.Text())
		if target == "" {
			// A blank line is not a target and not an error: it cannot be a
			// question, so there is nothing to answer about it.
			continue
		}
		answered++

		payload, code, asQuestion := answerLine(target, protos, showAll, tables, base)
		if !asQuestion {
			// The line is not a question. It still gets an object, so a consumer
			// counting lines against answers never loses its place.
			payload = batchError{
				SchemaVersion: schemaVersion,
				Target:        target,
				Kind:          kindUsage,
				Error:         errLineText(payload),
				Version:       version.Resolve().Version,
			}
			code = exitUsage
		}

		err, fatal := writeJSONLine(out, payload)
		if err != nil {
			_ = fprintf(stderr, "portwhy: line %d (%s): %v\n", answered, target, err)
			if fatal {
				// stdout is gone; there is nothing left to deliver.
				return exitUsage
			}
			worst = worseOf(worst, exitUsage)
			continue
		}
		worst = worseOf(worst, code)
	}

	if err := sc.Err(); err != nil {
		_ = fprintf(stderr, "portwhy: reading targets from stdin: %v\n", err)
		return exitUsage
	}
	if answered == 0 {
		// "Nothing was asked" is not "nothing is in the way". Exit 0 here would
		// let a monitor whose input file failed to generate pass silently.
		_ = fprintf(stderr, "portwhy: -batch read no target from stdin; "+
			"an empty batch is a usage error, not a clean bill of health\n")
		return exitUsage
	}
	if err := out.Flush(); err != nil {
		_ = fprintf(stderr, "portwhy: writing report: %v\n", err)
		return exitUsage
	}
	return worst
}

// answerLine turns one line into a document and the exit code it argues for.
//
// The third return value is false when the line could not become a question at
// all; payload is then the reason, and the caller turns it into an error object.
func answerLine(target string, protos []procnet.Proto, showAll bool, tables []procnet.Table,
	base verdict.Env,
) (payload any, code int, asQuestion bool) {
	addr, err := parseTarget(target)
	if err != nil {
		return err, exitUsage, false
	}
	explain := func(q verdict.Query) verdict.Verdict {
		if showAll {
			return verdict.ExplainAll(q, tables, base)
		}
		return verdict.Explain(q, tables, base)
	}
	if len(protos) == 1 {
		v := explain(verdict.Query{Addr: addr, Proto: protos[0]})
		return buildPortReport(v), exitCode(v.Kind), true
	}
	// -proto both keeps its single-target rule: two answers never fold into one
	// kind, and the exit code comes from the tcp half. The payload says so in
	// exit_from, so a stream consumer is told the same thing a reader is.
	tcp := explain(verdict.Query{Addr: addr, Proto: procnet.TCP})
	udp := explain(verdict.Query{Addr: addr, Proto: procnet.UDP})
	return bothReport{
		SchemaVersion: schemaVersion,
		Target:        tcp.Query.Addr.String(),
		Both:          true,
		ExitFrom:      "tcp",
		TCP:           buildPortReport(tcp),
		UDP:           buildPortReport(udp),
	}, exitCode(tcp.Kind), true
}

// errLineText formats the reason a line was not a question.
func errLineText(payload any) string {
	if err, ok := payload.(error); ok {
		return err.Error()
	}
	return fmt.Sprint(payload)
}

// writeJSONLine writes one compact object and flushes it.
//
// The flush is per line, not per buffer: a consumer reading this stream live (a
// pipe into a monitor, a terminal with head -3) must see each answer as it is
// produced rather than when the buffer happens to fill.
//
// The two errors are kept apart because they mean different things: a payload
// that cannot be encoded is one broken line and the run continues, while a failed
// write means the destination is gone and every later line would fail too.
func writeJSONLine(w *bufio.Writer, payload any) (err error, fatal bool) {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode line: %w", err), false
	}
	data = append(data, '\n')
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("write line: %w", err), true
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("flush line: %w", err), true
	}
	return nil, false
}

// worseOf combines two exit codes by severity, and the order is not numeric.
//
// usage(2) outranks unknown(3): "I cannot read what you gave me" is a statement
// about the whole run, while an unknown answer is a statement about one target.
// unknown outranks taken because a monitor with a blind spot is in more trouble
// than a monitor that found a busy port. taken outranks free because a batch that
// contains a taken port is not a clean batch.
func worseOf(a, b int) int {
	if severity(b) > severity(a) {
		return b
	}
	return a
}

func severity(code int) int {
	switch code {
	case exitUsage:
		return 3
	case exitUnknown:
		return 2
	case exitTaken:
		return 1
	case exitFree:
		return 0
	}
	// Not reachable with the four codes this program defines; treating an
	// unknown code as the most severe keeps a future addition from being
	// silently swallowed by a batch.
	return 3
}
