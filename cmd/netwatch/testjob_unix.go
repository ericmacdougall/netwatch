//go:build !windows

package main

import (
	"os"
	"os/exec"
	"syscall"
)

// startTestJob starts a test daemon's job as the leader of a new session
// and process group, so the group holds only the job and its descendants,
// like a Claude Code tool shell. A new session also matters for safety: a
// job in the daemon's session whose group is stopped gets SIGHUP from the
// kernel (orphaned process group) if the daemon dies, which killed the
// paused job in the first crash-path run.
func startTestJob(argv []string, out *os.File) (*exec.Cmd, error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin = nil
	cmd.Stdout, cmd.Stderr = out, out
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd, cmd.Start()
}
