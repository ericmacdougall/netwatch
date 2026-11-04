//go:build !windows

package guard

import "syscall"

const (
	sigSTOP = syscall.SIGSTOP
	sigCONT = syscall.SIGCONT
	sigTERM = syscall.SIGTERM
	sigKILL = syscall.SIGKILL
)

// kill sends sig to pid.
func kill(pid int, sig syscall.Signal) error { return syscall.Kill(pid, sig) }
