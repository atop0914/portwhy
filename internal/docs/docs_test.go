package docs

// The gate is the first test; the rest are the evidence that it can go red.
// A gate whose only test is "the repository is clean" is green on a checker whose
// body is `return nil, nil`, and this repository has already learned that lesson
// twice (a fixture the parser never read; a behavioural assertion a mutant could
// satisfy).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tree writes a repository skeleton and returns its root. Every document it
// writes satisfies every rule, so a test that expects no issues proves the rule
// under test is what changed it.
func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	write(t, root, "internal/x/x.go", "package x\n")
	write(t, root, "Makefile", "all:\n")
	write(t, root, "README.md", "# demo\n\n"+
		"Read [the design](docs/design.md) and [the schema](docs/json-schema.md).\n"+
		"The code is in `internal/x/x.go` and the build in `Makefile`.\n")
	write(t, root, "docs/design.md", "# design\n\nthe reasoning\n")
	write(t, root, "docs/json-schema.md", "### portReport\n\n| field | type |\n|---|---|\n| `kind` | string |\n")
	for name, body := range files {
		write(t, root, name, body)
	}
	return root
}

func write(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", rel, err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

// mustCheck runs the checker and fails on an error: in every test below the
// checker itself is expected to work, so an error means the checker broke.
func mustCheck(t *testing.T, root string) Report {
	t.Helper()
	rep, err := Check(root)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	return rep
}

// TestRepositoryDocumentsMatchTheTree is the gate: every relative link and every
// inline-code repository path in README.md and docs/*.md resolves.
//
// The floors on Links and Paths are not decoration. Without them a scanner that
// matches nothing returns zero issues and this test passes on a repository whose
// documentation it never opened.
func TestRepositoryDocumentsMatchTheTree(t *testing.T) {
	rep := mustCheck(t, "../..")
	for _, i := range rep.Issues {
		t.Error(i)
	}
	if rep.Links < 2 {
		t.Errorf("only %d relative links were checked; the scanner is not reading the documents", rep.Links)
	}
	if rep.Paths < 20 {
		t.Errorf("only %d repository paths were checked; the scanner is not reading the documents", rep.Paths)
	}
}

// TestCheckRefusesToPassWithoutAReadme is the fail-closed half: the one input the
// gate cannot work without. Returning "no issues" here would report a tree with
// no entry point as documented.
func TestCheckRefusesToPassWithoutAReadme(t *testing.T) {
	root := t.TempDir()
	if _, err := Check(root); err == nil {
		t.Fatal("Check on a tree without README.md returned no error; that is the fail-open shape")
	}
}

// TestCheckRefusesToPassOnAnEmptyDocsDirectory closes the other door to the same
// mistake: a directory that exists but holds nothing would satisfy every rule by
// having nothing to check.
func TestCheckRefusesToPassOnAnEmptyDocsDirectory(t *testing.T) {
	root := t.TempDir()
	write(t, root, "README.md", "# demo\n")
	if err := os.MkdirAll(filepath.Join(root, "docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Check(root); err == nil {
		t.Fatal("Check passed on a docs directory with no documents")
	}
}

func TestCheckReportsADanglingLink(t *testing.T) {
	root := tree(t, map[string]string{
		"docs/design.md": "# design\n\nsee [the schema](json-schema-gone.md)\n",
	})
	rep := mustCheck(t, root)
	if !hasIssue(rep, RuleLink, "json-schema-gone.md") {
		t.Fatalf("a link to a missing file was not reported: %v", rep.Issues)
	}
}

func TestCheckReportsALinkThatEscapesTheRepository(t *testing.T) {
	root := tree(t, map[string]string{
		"README.md": "# demo\n\n[the design](docs/design.md) [the schema](docs/json-schema.md)\n\n" +
			"[passwd](../../../etc/passwd)\n",
	})
	rep := mustCheck(t, root)
	// On a machine where ../../../etc/passwd is a real file, an os.Stat-only
	// check calls that link good. It is not: it leaves the repository.
	if !hasIssue(rep, RuleLink, "../../../etc/passwd") {
		t.Fatalf("a link escaping the repository was not reported: %v", rep.Issues)
	}
}

func TestCheckReportsAMissingRepositoryPath(t *testing.T) {
	root := tree(t, map[string]string{
		"README.md": "# demo\n\n[the design](docs/design.md) [the schema](docs/json-schema.md)\n\n" +
			"see `internal/renamed/away.go`\n",
	})
	rep := mustCheck(t, root)
	if !hasIssue(rep, RulePath, "internal/renamed/away.go") {
		t.Fatalf("a repository path that does not exist was not reported: %v", rep.Issues)
	}
}

// TestCheckWildcardsHaveToMatchSomething is the pair the glob support needs: a
// pattern that matches is clean, and the same pattern with nothing behind it is
// red. Only the first half would pass against a checker that skipped wildcards.
func TestCheckWildcardsHaveToMatchSomething(t *testing.T) {
	root := tree(t, map[string]string{
		"README.md": "# demo\n\n[the design](docs/design.md) [the schema](docs/json-schema.md)\n\n" +
			"see `internal/*/x.go` and `internal/x/testdata/fuzz/<Target>/`\n",
		"internal/x/testdata/fuzz/FuzzParse/seed": "x\n",
	})
	rep := mustCheck(t, root)
	for _, i := range rep.Issues {
		t.Errorf("a wildcard that matches was reported: %v", i)
	}
	if rep.Paths != 2 {
		t.Errorf("checked %d paths, want 2 (a placeholder must be a wildcard, not a skip)", rep.Paths)
	}

	write(t, root, "README.md", "# demo\n\n[the design](docs/design.md) [the schema](docs/json-schema.md)\n\n"+
		"see `internal/*/missing.go`\n")
	rep = mustCheck(t, root)
	if !hasIssue(rep, RulePath, "internal/*/missing.go") {
		t.Fatalf("a wildcard matching nothing was not reported: %v", rep.Issues)
	}
}

func TestCheckReportsAReadmeThatCannotReachTheDesign(t *testing.T) {
	root := tree(t, map[string]string{
		"README.md": "# demo\n\n[the schema](docs/json-schema.md)\n",
	})
	rep := mustCheck(t, root)
	if !hasIssue(rep, RuleEntry, "docs/design.md") {
		t.Fatalf("a README that never links the design document was not reported: %v", rep.Issues)
	}
}

// TestCheckIgnoresSystemPaths is the reverse assertion, and the reason the gate
// can stay on: most backticks in these documents are about the host —
// /proc/net/tcp, net.ipv6.bindv6only, @name — and a checker that treated those as
// repository paths would be red on every run, then removed.
func TestCheckIgnoresSystemPaths(t *testing.T) {
	root := tree(t, map[string]string{
		"README.md": "# demo\n\n[the design](docs/design.md) [the schema](docs/json-schema.md)\n\n" +
			"the code is in `internal/x/x.go`\n\n" +
			"`/proc/net/tcp`, `/proc/<pid>/fd/*`, `net/ipv6/bindv6only`, `@demo`, `[::]:8080`, `07`\n",
	})
	rep := mustCheck(t, root)
	for _, i := range rep.Issues {
		t.Errorf("a system path was reported as a repository path: %v", i)
	}
	// Exactly one claim about this tree: if the scanner were counting the system
	// paths too, the empty issue list above would mean something else.
	if rep.Paths != 1 {
		t.Errorf("checked %d repository paths, want 1 (the one real path, none of the system paths)", rep.Paths)
	}
}

// TestCheckIgnoresFencedBlocks: a transcript is an example of output, not a claim
// about the tree. The README's own samples contain `$ portwhy ...` lines and
// indented rows; scanning them would make every example a liability.
func TestCheckIgnoresFencedBlocks(t *testing.T) {
	root := tree(t, map[string]string{
		"README.md": "# demo\n\n[the design](docs/design.md) [the schema](docs/json-schema.md)\n\n" +
			"```\n$ portwhy why 127.0.0.1:8080\n`internal/example/in/a/fence.go`\n```\n",
	})
	rep := mustCheck(t, root)
	for _, i := range rep.Issues {
		t.Errorf("a fenced example was checked as a claim: %v", i)
	}
	if rep.Paths != 0 {
		t.Errorf("checked %d repository paths inside a fence, want 0", rep.Paths)
	}
}

func hasIssue(rep Report, rule, substr string) bool {
	for _, i := range rep.Issues {
		if i.Rule == rule && strings.Contains(i.Detail, substr) {
			return true
		}
	}
	return false
}
