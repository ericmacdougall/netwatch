//go:build !windows

package safeio

import (
	"errors"
	"os"
	"syscall"
)

// O_NONBLOCK keeps open(2) on a FIFO from blocking; the fstat check then
// rejects it before any read.
const readFlags = os.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_CLOEXEC

const dirFlags = os.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_DIRECTORY | syscall.O_CLOEXEC

const appendFlags = os.O_WRONLY | os.O_APPEND | os.O_CREATE | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_CLOEXEC

const tmpFlags = os.O_WRONLY | os.O_CREATE | os.O_EXCL | syscall.O_NOFOLLOW | syscall.O_CLOEXEC

func isSymlinkLoop(err error) bool {
	return errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.EMLINK)
}

func ownerUID(fi os.FileInfo) (uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}

func syncDir(d *os.File) error { return d.Sync() }
