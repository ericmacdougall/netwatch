//go:build !windows

package main

import (
	"os"
	"os/exec"
	"syscall"
)

// startTestJob starts a test daemon's job in a new process group of its
// own, so the group holds only the job and its descendants.
func startTestJob(argv []string, out *os.File) (*exec.Cmd, error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin = nil
	cmd.Stdout, cmd.Stderr = out, out
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return cmd, cmd.Start()
}
