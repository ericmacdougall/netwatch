//go:build windows

package guard

import (
	"errors"
	"os"
	"syscall"
)

// Windows has no guard; the numbers only keep the package compiling.
const (
	sigSTOP = syscall.Signal(19)
	sigCONT = syscall.Signal(18)
	sigTERM = syscall.Signal(15)
	sigKILL = syscall.Signal(9)
)

const (
	oNoFollow = 0
	oNonblock = 0
)

func ownedBySelf(os.FileInfo) bool { return true }
func fsyncDir(string) error        { return nil }

// kill is unsupported: there is no guard on Windows.
func kill(int, syscall.Signal) error {
	return errors.New("guard: signals are not supported on windows")
}
