package unixsock

import (
	"errors"
	"io/fs"
	"os"
)

// PathState is what the filesystem says about one socket path.
//
// It is a measurement with its own three-state honesty: Measured=false means
// nobody looked, Exists=false with Measured=true means the path really was
// absent, and Err means the look itself failed (a permission problem is not an
// absence). A judgement that received the zero value must answer "unknown" — the
// one thing it may not do is read the zero value as "no file there".
type PathState struct {
	Measured bool
	Exists   bool
	// Kind is what the filesystem reports: "socket", "regular file",
	// "directory", "named pipe", "symbolic link". Empty when nothing is there.
	Kind string
	// Err is why the look failed. Non-empty means Exists carries no information.
	Err string
}

// Describe is the evidence sentence a report cites: the kind of thing that is
// there, or the reason the question could not be answered.
func (p PathState) Describe() string {
	switch {
	case !p.Measured:
		return "the path was not checked"
	case p.Err != "":
		return "the path could not be checked: " + p.Err
	case p.Exists:
		return "the path exists and is a " + p.Kind
	}
	return "the path does not exist"
}

// IsSocket reports whether the existing entry is a unix socket file.
func (p PathState) IsSocket() bool {
	return p.Measured && p.Err == "" && p.Exists && p.Kind == "socket"
}

func (p PathState) String() string { return p.Describe() }

// Line is the one-line form for a report header, where the field is already
// labelled "path": repeating the word there reads as two measurements.
func (p PathState) Line() string {
	switch {
	case !p.Measured:
		return "not checked"
	case p.Err != "":
		return "could not be checked: " + p.Err
	case p.Exists:
		return "exists (" + p.Kind + ")"
	}
	return "does not exist"
}

// Inspect measures one path with Lstat.
//
// Lstat, not Stat: a symlink pointing at a socket occupies the name as far as
// bind() is concerned, and following the link would report the target's kind
// while the name the user typed is a symlink. The report should describe the
// name they typed.
//
// It lives in the shared file because measuring a path is portable; only reading
// /proc/net/unix is not, and that is the part with the build tag.
func Inspect(path string) PathState {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return PathState{Measured: true}
		}
		return PathState{Measured: true, Err: err.Error()}
	}
	return PathState{Measured: true, Exists: true, Kind: kindOf(info.Mode())}
}

// kindOf names the mode in the words a person would use for it. The name matters:
// "the path exists and is a regular file" sends a reader to remove the right
// thing, while "the path exists" alone invites them to look for a process.
func kindOf(mode fs.FileMode) string {
	switch {
	case mode&fs.ModeSocket != 0:
		return "socket"
	case mode&fs.ModeDir != 0:
		return "directory"
	case mode&fs.ModeNamedPipe != 0:
		return "named pipe"
	case mode&fs.ModeSymlink != 0:
		return "symbolic link"
	case mode&fs.ModeDevice != 0:
		return "device"
	case mode.IsRegular():
		return "regular file"
	}
	return "file of an unusual type"
}
