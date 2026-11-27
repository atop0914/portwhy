// Package version reports what this binary is.
//
// Two sources, in order: values injected with -ldflags by the Makefile, then
// the module build info that `go install` leaves behind. The second one is not
// decoration: `go install` runs no Makefile, so without it the binary a user
// installs reports "dev" while the release notes claim a version.
package version

import (
	"runtime/debug"
	"strings"
)

// Injected at build time. Left as-is here, they are the fallback signal.
var (
	Version = "dev"
	Commit  = ""
	Date    = ""
)

// Info is what the CLI prints and what the JSON output carries.
type Info struct {
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"`
	Date    string `json:"date,omitempty"`
	Source  string `json:"source"` // "ldflags" or "buildinfo"
}

// Resolve returns the best identity available. Fields that cannot be
// established are left empty rather than filled with a placeholder: a printed
// "unknown" is a fact, a printed "dev" on a released binary is a lie.
func Resolve() Info {
	bi, ok := debug.ReadBuildInfo()
	return resolve(Version, Commit, Date, bi, ok)
}

// commitWidth is how much of a revision is printed. It lives here, not in the
// Makefile, because two places deciding it is how one release ends up described
// by a 7-character commit in one binary and a 12-character one in the next.
const commitWidth = 12

// shortenCommit keeps a revision that is already short, and cuts a full one to
// commitWidth. Cutting a 7-character value to 12 would produce a commit that
// does not exist; that is worse than no commit at all.
func shortenCommit(rev string) string {
	if len(rev) > commitWidth {
		return rev[:commitWidth]
	}
	return rev
}

// resolve is Resolve with its three inputs handed in, because a test cannot
// inject a build info record through the real one. Every field below exists to
// keep one promise: the same release is spelled the same way no matter which
// source answered. `go install ...@v1.0.0` yields Main.Version "v1.0.0" and
// `git describe --tags` yields "v1.0.0"; stripping the "v" from one of them
// would print two different strings for one release, and the release-day
// check (`portwhy version` must say v1.0.0) would depend on how it was built.
func resolve(injVersion, injCommit, injDate string, bi *debug.BuildInfo, hasBuildInfo bool) Info {
	info := Info{Version: injVersion, Commit: shortenCommit(injCommit), Date: injDate}
	if injVersion != "" && injVersion != "dev" {
		info.Source = "ldflags"
		return info
	}

	if !hasBuildInfo || bi == nil {
		info.Source = "none"
		return info
	}
	if v := bi.Main.Version; v != "" && v != "(devel)" {
		info.Version = v
		info.Source = "buildinfo"
	} else {
		info.Version = "dev"
		info.Source = "buildinfo"
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			if info.Commit == "" {
				info.Commit = shortenCommit(s.Value)
			}
		case "vcs.time":
			if info.Date == "" {
				info.Date = s.Value
			}
		}
	}
	return info
}

// String renders one line, omitting what is not known.
func (i Info) String() string {
	parts := []string{i.Version}
	if i.Commit != "" {
		parts = append(parts, i.Commit)
	}
	if i.Date != "" {
		parts = append(parts, i.Date)
	}
	return "portwhy " + strings.Join(parts, " ")
}
