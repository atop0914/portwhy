//go:build linux

package sockid

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Scan walks root once and indexes every socket descriptor it can see.
//
// The walk is deliberately single-pass: /proc is a moving target, and a
// long-lived cache would answer questions about a system that no longer exists.
func Scan(root string) (*Index, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("sockid: read %s: %w", root, err)
	}

	idx := &Index{
		ByInode: make(map[uint64][]Holder),
		PPID:    make(map[int]int),
	}
	for _, e := range entries {
		pid, ok := parsePID(e.Name())
		if !ok {
			continue
		}
		idx.scanProc(root, pid)
	}
	idx.sortHolders()
	return idx, nil
}

func (i *Index) scanProc(root string, pid int) {
	fdDir := filepath.Join(root, strconv.Itoa(pid), "fd")
	fds, err := os.ReadDir(fdDir)
	if err != nil {
		switch {
		case errors.Is(err, fs.ErrPermission):
			i.ProcsDenied++
		default:
			// The process exited between listing /proc and reading it, or it is
			// a thread-group artifact. Neither is a hole in the walk.
			i.ProcsSkipped++
		}
		return
	}
	i.ProcsRead++

	comm := readComm(root, pid)
	if ppid, ok := readPPID(root, pid); ok {
		i.PPID[pid] = ppid
	}
	for _, fd := range fds {
		target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
		if err != nil {
			// A descriptor closed mid-walk. Not a hole either.
			continue
		}
		inode, ok := ParseSockLink(target)
		if !ok {
			continue
		}
		fdNum, err := strconv.Atoi(fd.Name())
		if err != nil {
			continue
		}
		i.add(inode, Holder{PID: pid, Comm: comm, FD: fdNum})
	}
}

// readComm returns the process name, or "" when it is not readable. An empty
// name is honest: the pid is still the pid.
func readComm(root string, pid int) string {
	b, err := os.ReadFile(filepath.Join(root, strconv.Itoa(pid), "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// readPPID returns the parent pid from /proc/<pid>/stat.
//
// The second field is the command name in parentheses and may itself contain
// spaces and parentheses ("(my app (v2))"), so the fields are counted from the
// last ')' instead of being split from the start: splitting naively shifts every
// field after the name and reports a pid that is not the parent.
func readPPID(root string, pid int) (int, bool) {
	b, err := os.ReadFile(filepath.Join(root, strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, false
	}
	end := bytes.LastIndexByte(b, ')')
	if end < 0 {
		return 0, false
	}
	// After the name: state, ppid, pgrp, ...
	fields := strings.Fields(string(b[end+1:]))
	if len(fields) < 2 {
		return 0, false
	}
	ppid, err := strconv.Atoi(fields[1])
	if err != nil || ppid < 0 {
		return 0, false
	}
	return ppid, true
}

func parsePID(name string) (int, bool) {
	pid, err := strconv.Atoi(name)
	if err != nil || pid <= 0 {
		return 0, false
	}
	return pid, true
}
