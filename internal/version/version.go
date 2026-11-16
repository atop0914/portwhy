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
	info := Info{Version: Version, Commit: Commit, Date: Date}
	if Version != "" && Version != "dev" {
		info.Source = "ldflags"
		return info
	}

	bi, ok := debug.ReadBuildInfo()
	if !ok {
		info.Source = "none"
		return info
	}
	if v := bi.Main.Version; v != "" && v != "(devel)" {
		info.Version = strings.TrimPrefix(v, "v")
		info.Source = "buildinfo"
	} else {
		info.Version = "dev"
		info.Source = "buildinfo"
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			if info.Commit == "" {
				if len(s.Value) > 12 {
					info.Commit = s.Value[:12]
				} else {
					info.Commit = s.Value
				}
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
