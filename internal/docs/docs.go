// Package docs checks the documents in this repository against the tree they
// describe.
//
// A document is a report, and reports lie in the same quiet way code does: a
// file is renamed, a section is split, and the sentence pointing at it keeps
// reading as if nothing happened. Nothing fails, nothing is logged, and the
// reader who follows the link gets a 404 from GitHub. The feedback loop for that
// is months long, which is why the mechanical part is an assertion instead.
//
// Three rules, each one about a claim the text makes:
//
//   - a relative link points at a file that exists;
//   - an inline-code repository path (`internal/...`, `docs/...`, `Makefile`)
//     exists — wildcards allowed, since the text says "every file under" as
//     often as it names one;
//   - the README reaches the two documents a reader needs to judge an answer:
//     docs/design.md (why it says what it says) and docs/json-schema.md (what a
//     program may rely on).
//
// What this package deliberately does not do: check anchors (GitHub's slug
// algorithm is a moving target, and a wrong check produces false reds, which is
// how a gate gets deleted), check prose for factual accuracy, or read files
// outside the repository. It reports issues and never exits; the test that calls
// it decides what a failure means.
//
// The one property that makes the gate worth having: it fails closed. A missing
// README, an unreadable docs directory, or an empty one is an error, not an
// empty issue list. A checker that reports "everything is fine" when it could
// not read its input is worse than no checker — it converts "unknown" into
// "clean", which is the exact failure this project exists to name.
package docs

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Rule names. They end up in test failure messages, so they say what was
// violated rather than which function noticed.
const (
	// RuleLink: a relative markdown link does not resolve to a file.
	RuleLink = "link"
	// RulePath: an inline-code repository path does not exist.
	RulePath = "path"
	// RuleEntry: the README does not link to a document it must reach.
	RuleEntry = "entry"
)

// Issue is one broken claim, located well enough to fix without searching.
type Issue struct {
	File   string // repository-relative, slash-separated
	Line   int    // 1-based; 0 when the issue is about the file as a whole
	Rule   string
	Detail string
}

func (i Issue) String() string {
	if i.Line == 0 {
		return fmt.Sprintf("%s: [%s] %s", i.File, i.Rule, i.Detail)
	}
	return fmt.Sprintf("%s:%d: [%s] %s", i.File, i.Line, i.Rule, i.Detail)
}

// RequiredDocs are the documents the README has to reach. They are named here
// rather than discovered: "every document is linked" is a different (and
// stricter) rule, and it belongs to whoever adds the next document.
var RequiredDocs = []string{"docs/design.md", "docs/json-schema.md"}

// repoPrefixes are the first path elements that make an inline-code token a
// claim about this repository. Everything else in backticks — /proc/net/tcp,
// net/ipv6/bindv6only, @name — is about the system, not about the tree, and
// checking it would produce a red on every run.
var repoPrefixes = []string{"internal/", "cmd/", "docs/", "scripts/", ".github/"}

// repoFiles are single-element repository paths, checked by exact name.
var repoFiles = []string{"Makefile", "go.mod", "go.sum", "README.md", "LICENSE"}

// Report is what one run saw, not only what it disliked.
//
// The counts are the difference between "clean" and "clean because nothing was
// looked at": a checker whose markdown scanner silently matched no links returns
// zero issues for any tree, and the caller cannot tell. The gate therefore
// asserts a floor on Links and Paths as well as an empty Issues.
type Report struct {
	Issues []Issue
	Links  int // relative links resolved (or not) against the tree
	Paths  int // inline-code repository paths checked
}

// Check reads root/README.md and root/docs/*.md and reports every claim that does
// not hold. An error means the checker could not do its job — not that the
// documents are broken; broken documents come back as issues.
func Check(root string) (Report, error) {
	var rep Report
	readme := filepath.Join(root, "README.md")
	if _, err := os.Stat(readme); err != nil {
		return rep, fmt.Errorf("docs: the README is the entry point and cannot be read: %w", err)
	}

	docsDir := filepath.Join(root, "docs")
	entries, err := os.ReadDir(docsDir)
	if err != nil {
		return rep, fmt.Errorf("docs: cannot list %s: %w", docsDir, err)
	}
	var pages []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		pages = append(pages, filepath.Join(docsDir, e.Name()))
	}
	sort.Strings(pages)
	if len(pages) == 0 {
		// An empty directory would pass every rule below by having nothing to
		// check, and the gate would call a repository with no documentation clean.
		return rep, fmt.Errorf("docs: %s holds no .md files; the gate would pass against nothing", docsDir)
	}

	readmeTargets := map[string]bool{}

	var scan func(abs string) error
	scan = func(abs string) error {
		rel, err := filepath.Rel(root, abs)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		found, counts, err := checkFile(root, abs, rel)
		if err != nil {
			return err
		}
		rep.Issues = append(rep.Issues, found...)
		rep.Links += counts.Links
		rep.Paths += counts.Paths
		if rel == "README.md" {
			readmeTargets = linkTargets(abs, root)
		}
		return nil
	}

	if err := scan(readme); err != nil {
		return rep, err
	}
	for _, p := range pages {
		if err := scan(p); err != nil {
			return rep, err
		}
	}

	for _, want := range RequiredDocs {
		// The requirement is that a reader starting at the README can get there,
		// so a link that only exists in a document nobody links to does not count.
		if !readmeTargets[want] {
			rep.Issues = append(rep.Issues, Issue{
				File:   "README.md",
				Rule:   RuleEntry,
				Detail: fmt.Sprintf("does not link to %s; a document nothing links to is a document nobody reads", want),
			})
		}
	}
	return rep, nil
}

var (
	// [text](target) — the parenthesised part cannot contain a closing paren in
	// anything this repository writes, and a stricter parser here would be a
	// second, worse markdown implementation.
	linkRE = regexp.MustCompile(`\]\(([^()\s]+)\)`)
	// A placeholder in a path: `testdata/fuzz/<Target>/` names a directory that
	// exists for every target. Treated as a wildcard rather than skipped, so the
	// check still proves the *rest* of the path is real.
	placeholderRE = regexp.MustCompile(`<[^<>]*>`)
)

// counts is what one document contributed to the report, so that "no issues"
// can be told apart from "nothing was matched".
type counts struct {
	Links int
	Paths int
}

// checkFile applies the three rules to one document.
func checkFile(root, abs, rel string) ([]Issue, counts, error) {
	var c counts
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, c, fmt.Errorf("docs: cannot read %s: %w", rel, err)
	}
	var issues []Issue
	inFence := false
	for n, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			inFence = !inFence
			continue
		}
		if inFence {
			// Fenced blocks hold shell transcripts and diagrams, where a
			// backticked word is part of an example rather than a claim.
			continue
		}
		for _, m := range linkRE.FindAllStringSubmatch(line, -1) {
			target := m[1]
			if !isRelativeLink(target) {
				continue
			}
			c.Links++
			if !exists(root, abs, stripAnchor(target)) {
				issues = append(issues, Issue{
					File:   rel,
					Line:   n + 1,
					Rule:   RuleLink,
					Detail: fmt.Sprintf("link %q does not resolve to a file", target),
				})
			}
		}
		for _, span := range inlineCode(line) {
			if !claimsRepoPath(span) {
				continue
			}
			c.Paths++
			ok, err := existsPattern(root, span)
			if err != nil {
				// A malformed glob is a broken claim, not a broken checker: the
				// text is the thing that has to change.
				issues = append(issues, Issue{File: rel, Line: n + 1, Rule: RulePath, Detail: err.Error()})
				continue
			}
			if !ok {
				issues = append(issues, Issue{
					File:   rel,
					Line:   n + 1,
					Rule:   RulePath,
					Detail: fmt.Sprintf("%q does not exist", span),
				})
			}
		}
	}
	return issues, c, nil
}

// inlineCode returns the contents of the single-backtick spans on one line.
//
// A line with an odd number of backticks leaves an unterminated span; that last
// piece is dropped rather than treated as code, because guessing where it ends is
// how a checker invents failures.
func inlineCode(line string) []string {
	parts := strings.Split(line, "`")
	var out []string
	for i := 1; i < len(parts); i += 2 {
		out = append(out, parts[i])
	}
	return out
}

// isRelativeLink says whether a link target is this repository's business.
func isRelativeLink(target string) bool {
	if target == "" || strings.HasPrefix(target, "#") {
		return false
	}
	if strings.Contains(target, "://") || strings.HasPrefix(target, "mailto:") {
		return false
	}
	// A root-absolute link would work on GitHub only if the site were the repo;
	// this repository never uses one, and checking it against the filesystem
	// would be checking a different claim.
	return !strings.HasPrefix(target, "/")
}

func stripAnchor(target string) string {
	base, _, _ := strings.Cut(target, "#")
	return base
}

// exists resolves a link target relative to the document that contains it.
func exists(root, docPath, target string) bool {
	if target == "" {
		return false
	}
	p := filepath.Join(filepath.Dir(docPath), filepath.FromSlash(target))
	// A link must not escape the repository: `../../etc/passwd` "exists" and
	// would pass, which is the wrong answer to "is this link good".
	if !within(root, p) {
		return false
	}
	_, err := os.Stat(p)
	return err == nil
}

func within(root, p string) bool {
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// claimsRepoPath decides whether an inline-code span is a claim about this tree.
func claimsRepoPath(span string) bool {
	s := strings.TrimSpace(span)
	if s == "" || strings.HasPrefix(s, "/") || strings.ContainsAny(s, " \t") {
		return false
	}
	for _, name := range repoFiles {
		if s == name {
			return true
		}
	}
	for _, prefix := range repoPrefixes {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

// existsPattern checks a repository path that may contain `*` and `<placeholder>`
// segments.
func existsPattern(root, span string) (bool, error) {
	s := strings.TrimSpace(span)
	s = placeholderRE.ReplaceAllString(s, "*")
	// A trailing slash means "this directory"; the glob below would also accept a
	// file with that name, which is not what the text says.
	wantDir := strings.HasSuffix(s, "/")
	s = strings.TrimSuffix(s, "/")

	if !strings.Contains(s, "*") {
		info, err := os.Stat(filepath.Join(root, filepath.FromSlash(s)))
		if err != nil {
			return false, nil
		}
		return !wantDir || info.IsDir(), nil
	}

	pattern := filepath.Join(root, filepath.FromSlash(s))
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return false, fmt.Errorf("%q is not a usable pattern: %w", span, err)
	}
	for _, m := range matches {
		if !wantDir {
			return true, nil
		}
		if info, statErr := os.Stat(m); statErr == nil && info.IsDir() {
			return true, nil
		}
	}
	return false, nil
}

// linkTargets returns the repository-relative paths the README links to.
func linkTargets(readmeAbs, root string) map[string]bool {
	data, err := os.ReadFile(readmeAbs)
	if err != nil {
		return nil
	}
	out := map[string]bool{}
	inFence := false
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		for _, m := range linkRE.FindAllStringSubmatch(line, -1) {
			if !isRelativeLink(m[1]) {
				continue
			}
			p := filepath.Join(filepath.Dir(readmeAbs), filepath.FromSlash(stripAnchor(m[1])))
			if rel, err := filepath.Rel(root, p); err == nil {
				out[path.Clean(filepath.ToSlash(rel))] = true
			}
		}
	}
	return out
}
