package unixsock

import (
	"os"
	"path/filepath"
	"testing"
)

// The three states of a path measurement have to stay apart: "not there",
// "there", and "I could not look". The zero value is the third one, and reading
// it as the first is how a stale file becomes a free name.
func TestZeroPathStateIsNotAnAbsence(t *testing.T) {
	var zero PathState
	if zero.Measured {
		t.Fatal("the zero value claims it was measured")
	}
	if zero.IsSocket() {
		t.Fatal("the zero value claims it is a socket")
	}
	if zero.Describe() != "the path was not checked" {
		t.Errorf("Describe() = %q", zero.Describe())
	}
}

func TestInspectMissingPath(t *testing.T) {
	p := Inspect(filepath.Join(t.TempDir(), "gone.sock"))
	if !p.Measured {
		t.Error("a missing path is reported as unmeasured")
	}
	if p.Exists {
		t.Error("a missing path is reported as existing")
	}
	if p.Err != "" {
		t.Errorf("a missing path carries an error %q", p.Err)
	}
	if p.Describe() != "the path does not exist" {
		t.Errorf("Describe() = %q", p.Describe())
	}
}

// Every existing entry blocks bind(), so the report has to name what is there:
// "remove the file" is different advice from "find the process".
func TestInspectNamesWhatIsThere(t *testing.T) {
	dir := t.TempDir()

	reg := filepath.Join(dir, "regular")
	if err := os.WriteFile(reg, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if p := Inspect(reg); !p.Exists || p.Kind != "regular file" || p.IsSocket() {
		t.Errorf("regular file = %+v", p)
	}

	if p := Inspect(dir); !p.Exists || p.Kind != "directory" || p.IsSocket() {
		t.Errorf("directory = %+v", p)
	}

	link := filepath.Join(dir, "link")
	if err := os.Symlink(reg, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if p := Inspect(link); !p.Exists || p.Kind != "symbolic link" {
		t.Errorf("symlink = %+v (Lstat, not Stat: the name the user typed is what bind() collides with)", p)
	}
}
