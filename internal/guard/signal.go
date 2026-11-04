package guard

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

// Signal errors.
var (
	// ErrStartMismatch means the pid now belongs to a different process
	// (or is gone): nothing was signalled.
	ErrStartMismatch = errors.New("guard: process start time differs, not signalled")
	// ErrRefused means the target is never signalled (pid 1, ourselves).
	ErrRefused = errors.New("guard: refusing to signal this pid")
)

// StartReader reads a process start time; resources.Reader adapts to it
// with ReaderStart.
type StartReader interface {
	Start(pid int) (time.Time, error)
}

// OSSignaller is the real Signaller. Immediately before kill(2) it
// re-reads the start time and refuses on a mismatch. The check and the
// kill are not atomic (no pidfd on macOS); the spec accepts that window.
type OSSignaller struct {
	Starts StartReader
	Self   int // our own pid, never signalled
}

// startTolerance absorbs the precision lost when a start time is stored.
const startTolerance = 10 * time.Millisecond

func sameStart(a, b time.Time) bool {
	d := a.Sub(b)
	if d < 0 {
		d = -d
	}
	return d <= startTolerance
}

// Signal implements Signaller.
func (o OSSignaller) Signal(pid int, start time.Time, sig syscall.Signal) error {
	if pid <= 1 || pid == o.Self || pid == os.Getpid() {
		return fmt.Errorf("%w: %d", ErrRefused, pid)
	}
	cur, err := o.Starts.Start(pid)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStartMismatch, err)
	}
	if !sameStart(cur, start) {
		return ErrStartMismatch
	}
	return kill(pid, sig)
}
