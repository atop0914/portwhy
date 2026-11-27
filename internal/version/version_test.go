package version

import (
	"runtime/debug"
	"strings"
	"testing"
)

// buildInfo builds the record `go install module@version` leaves behind. The
// revision is the full 40 hex digits, because that is what the toolchain
// writes; a fixture with a short one would never exercise the truncation.
func buildInfo(modVersion string, settings ...[2]string) *debug.BuildInfo {
	bi := &debug.BuildInfo{Main: debug.Module{Version: modVersion}}
	for _, s := range settings {
		bi.Settings = append(bi.Settings, debug.BuildSetting{Key: s[0], Value: s[1]})
	}
	return bi
}

// A released binary must report the release. The Makefile path is the one that
// works, and the build-info path is the one users take; both have to land on the
// same string, or the release-day check (`portwhy version` says v1.0.0) passes
// or fails depending on how the binary was built.
func TestBothSourcesSpellTheReleaseTheSameWay(t *testing.T) {
	injected := resolve("v1.0.0", "658bc6c7a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
		"2026-11-27T20:00:00Z", nil, false)
	fromInstall := resolve("dev", "", "",
		buildInfo("v1.0.0",
			[2]string{"vcs.revision", "658bc6c7a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"},
			[2]string{"vcs.time", "2026-11-27T20:00:00Z"}), true)

	if injected.Version != "v1.0.0" {
		t.Errorf("injected version = %q, want v1.0.0", injected.Version)
	}
	if fromInstall.Version != "v1.0.0" {
		t.Errorf("go install version = %q, want v1.0.0 (a trimmed %q is the same release spelled differently)",
			fromInstall.Version, "1.0.0")
	}
	if injected.Version != fromInstall.Version {
		t.Errorf("one release, two spellings: ldflags %q vs buildinfo %q",
			injected.Version, fromInstall.Version)
	}
	if injected.Source != "ldflags" || fromInstall.Source != "buildinfo" {
		t.Errorf("sources = %q/%q, want ldflags/buildinfo", injected.Source, fromInstall.Source)
	}
	if injected.Commit != fromInstall.Commit {
		t.Errorf("commit = %q vs %q, want the same 12 characters", injected.Commit, fromInstall.Commit)
	}
	if len(fromInstall.Commit) != 12 {
		t.Errorf("commit = %q (%d chars), want 12", fromInstall.Commit, len(fromInstall.Commit))
	}
	if injected.Date != fromInstall.Date {
		t.Errorf("date = %q vs %q, want the same stamp", injected.Date, fromInstall.Date)
	}
}

// The reverse of the test above: build info must not talk over an injected
// value. Otherwise `make build` on a dirty tree would report the tag it happens
// to sit next to instead of the version the Makefile computed.
func TestInjectedValuesWinOverBuildInfo(t *testing.T) {
	got := resolve("v1.0.0", "abc123", "2026-11-27T20:00:00Z",
		buildInfo("v0.9.9",
			[2]string{"vcs.revision", "ffffffffffffffffffffffffffffffffffffffff"},
			[2]string{"vcs.time", "2020-01-01T00:00:00Z"}), true)

	if got.Source != "ldflags" {
		t.Fatalf("source = %q, want ldflags", got.Source)
	}
	if got.Version != "v1.0.0" || got.Commit != "abc123" || got.Date != "2026-11-27T20:00:00Z" {
		t.Errorf("got %+v, want the injected triple untouched (build info must not overwrite it)", got)
	}
}

// A bare `go build` is a legitimate way to get a binary, and it has to say what
// it is: dev, with no commit and no date. What it must not do is borrow an
// identity from whatever checkout it was built in and imply a release.
func TestBareBuildIsDevAndSaysSo(t *testing.T) {
	got := resolve("dev", "", "", nil, false)

	if got.Version != "dev" {
		t.Errorf("version = %q, want dev", got.Version)
	}
	if got.Source != "none" {
		t.Errorf("source = %q, want none", got.Source)
	}
	if got.Commit != "" || got.Date != "" {
		t.Errorf("got %+v, want no commit and no date", got)
	}
	if line := got.String(); line != "portwhy dev" {
		t.Errorf("String() = %q, want %q", line, "portwhy dev")
	}
}

// `go install module@dev` yields a pseudo-version and `go build` in a checkout
// yields "(devel)". The second is not a version and must not be printed as one.
func TestDevelPlaceholderIsNotAVersion(t *testing.T) {
	got := resolve("dev", "", "", buildInfo("(devel)"), true)
	if got.Version != "dev" {
		t.Errorf("version = %q, want dev for (devel)", got.Version)
	}

	pseudo := resolve("dev", "", "", buildInfo("v0.0.0-20261127200000-658bc6c7a1b2"), true)
	if pseudo.Version != "v0.0.0-20261127200000-658bc6c7a1b2" {
		t.Errorf("version = %q, want the pseudo-version as printed by the toolchain", pseudo.Version)
	}
	if !strings.HasPrefix(pseudo.Version, "v") {
		t.Errorf("pseudo-version lost its %q prefix: %q", "v", pseudo.Version)
	}
}

// Build info without VCS settings is what a binary built from a module cache
// looks like. Version may be known while commit and date are not, and that is
// the honest state — not a reason to print a placeholder.
func TestMissingVCSFieldsStayEmpty(t *testing.T) {
	got := resolve("dev", "", "", buildInfo("v1.0.0"), true)

	if got.Version != "v1.0.0" {
		t.Errorf("version = %q, want v1.0.0", got.Version)
	}
	if got.Commit != "" || got.Date != "" {
		t.Errorf("got commit %q date %q, want both empty", got.Commit, got.Date)
	}
	if line := got.String(); line != "portwhy v1.0.0" {
		t.Errorf("String() = %q, want %q", line, "portwhy v1.0.0")
	}
}

// A short revision is kept whole: cutting it to 12 characters when it is 7 long
// would produce an empty or mangled commit, and a commit that does not exist is
// worse than no commit at all.
func TestShortRevisionIsKeptWhole(t *testing.T) {
	cases := []struct{ in, want string }{
		{"658bc6c", "658bc6c"},
		{"658bc6c7a1b2", "658bc6c7a1b2"},
		{"658bc6c7a1b2c3d4", "658bc6c7a1b2"},
		{"", ""},
	}
	for _, c := range cases {
		got := resolve("dev", "", "", buildInfo("v1.0.0", [2]string{"vcs.revision", c.in}), true)
		if got.Commit != c.want {
			t.Errorf("revision %q -> commit %q, want %q", c.in, got.Commit, c.want)
		}
	}
}

// An injected commit/date is not overwritten by the VCS settings of the build
// that happens to be running — the same rule as the version, applied per field.
func TestInjectedCommitSurvivesBuildInfo(t *testing.T) {
	got := resolve("dev", "abc123", "",
		buildInfo("v1.0.0",
			[2]string{"vcs.revision", "658bc6c7a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"},
			[2]string{"vcs.time", "2026-11-27T20:00:00Z"}), true)

	if got.Commit != "abc123" {
		t.Errorf("commit = %q, want the injected abc123", got.Commit)
	}
	if got.Date != "2026-11-27T20:00:00Z" {
		t.Errorf("date = %q, want the one build info supplied", got.Date)
	}
}

// The rendered line has three variable parts, so the thing worth asserting is
// what it never contains: a placeholder. "unknown" and "dev" read as facts, and
// a caller cannot tell them apart from a real answer.
func TestStringPrintsNoPlaceholders(t *testing.T) {
	infos := []Info{
		{Version: "v1.0.0", Commit: "658bc6c", Date: "2026-11-27T20:00:00Z", Source: "ldflags"},
		{Version: "v1.0.0", Source: "buildinfo"},
		{Version: "dev", Source: "none"},
	}
	for _, i := range infos {
		line := i.String()
		for _, banned := range []string{"unknown", "UNKNOWN", "<nil>", "%!"} {
			if strings.Contains(line, banned) {
				t.Errorf("String() = %q contains %q", line, banned)
			}
		}
		if !strings.HasPrefix(line, "portwhy ") {
			t.Errorf("String() = %q, want a portwhy prefix", line)
		}
		if strings.HasSuffix(line, " ") {
			t.Errorf("String() = %q, want no trailing space (an empty field must not leave a gap)", line)
		}
		fields := strings.Fields(line)
		want := 1
		if i.Commit != "" {
			want++
		}
		if i.Date != "" {
			want++
		}
		if len(fields) != want+1 {
			t.Errorf("String() = %q has %d fields, want %d (one per known part)", line, len(fields), want+1)
		}
	}
}
