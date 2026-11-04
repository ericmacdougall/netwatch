//go:build windows

package guard

import (
	"errors"
	"syscall"
)

// Windows has no guard; the numbers only keep the package compiling.
const (
	sigSTOP = syscall.Signal(19)
	sigCONT = syscall.Signal(18)
	sigTERM = syscall.Signal(15)
	sigKILL = syscall.Signal(9)
)

// kill is unsupported: there is no guard on Windows.
func kill(int, syscall.Signal) error {
	return errors.New("guard: signals are not supported on windows")
}
