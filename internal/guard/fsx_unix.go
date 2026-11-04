//go:build !windows

package guard

import (
	"os"
	"syscall"
)

const (
	sigSTOP = syscall.SIGSTOP
	sigCONT = syscall.SIGCONT
	sigTERM = syscall.SIGTERM
	sigKILL = syscall.SIGKILL
)

const (
	oNoFollow = syscall.O_NOFOLLOW
	oNonblock = syscall.O_NONBLOCK
)

// ownedBySelf reports whether fi belongs to our uid.
func ownedBySelf(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Getuid()
}

func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// kill sends sig to pid.
func kill(pid int, sig syscall.Signal) error { return syscall.Kill(pid, sig) }
