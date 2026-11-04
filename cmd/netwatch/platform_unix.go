//go:build unix

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// lockRun takes an exclusive, non-blocking lock so only one monitor writes
// to a log directory. The kernel drops the lock if the process dies.
func lockRun(path string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("another netwatch is already running for %s", filepath.Dir(path))
	}
	_ = f.Truncate(0)
	fmt.Fprintf(f, "%d\n", os.Getpid())
	return func() { f.Close() }, nil
}

// background lowers our priority: monitoring must never compete with the
// work it is watching.
func background() {
	_ = syscall.Setpriority(syscall.PRIO_PROCESS, 0, 10)
}
