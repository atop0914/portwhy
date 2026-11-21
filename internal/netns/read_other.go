//go:build !linux

package netns

import (
	"fmt"
	"path/filepath"
	"runtime"
)

// Read refuses on every non-Linux platform.
//
// There is no network namespace to name, and returning an empty Identity that
// reads as "not measured" would let the caller print a scope line with no scope
// in it. The refusal carries the platform so the report says which build it was.
func Read(root string) Identity {
	return Identity{
		Path: filepath.Join(root, selfLink),
		Err: fmt.Sprintf("network namespaces are a Linux concept (this build runs on %s)",
			runtime.GOOS),
	}
}
