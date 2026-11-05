//go:build darwin

package watcher

import (
	"context"
	"errors"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Kq watches Claude pids with kqueue EVFILT_PROC. NOTE_FORK arrives with
// data=0 (the child pid is not reported, and several forks can coalesce
// into one event), so each event triggers a PPID_ONLY listing through the
// Book rather than trusting the event.
type Kq struct {
	book *Book
	fd   int

	mu     sync.Mutex
	closed bool
}

// ErrGone means the pid exited before it could be watched.
var ErrGone = errors.New("watcher: process gone")

// NewKq creates the kqueue.
func NewKq(b *Book) (*Kq, error) {
	fd, err := unix.Kqueue()
	if err != nil {
		return nil, err
	}
	unix.CloseOnExec(fd)
	return &Kq{book: b, fd: fd}, nil
}

// Add watches pid for fork and exit. The caller must also Track it on the
// Book (with its start time and exe) so children are attributed.
func (k *Kq) Add(pid int) error {
	ev := unix.Kevent_t{
		Ident:  uint64(pid),
		Filter: unix.EVFILT_PROC,
		Flags:  unix.EV_ADD | unix.EV_CLEAR,
		Fflags: unix.NOTE_FORK | unix.NOTE_EXIT,
	}
	_, err := unix.Kevent(k.fd, []unix.Kevent_t{ev}, nil, nil)
	if err == unix.ESRCH {
		return ErrGone
	}
	return err
}

// Remove stops watching pid. It is not an error if the pid already exited
// (the kernel drops the knote itself).
func (k *Kq) Remove(pid int) {
	ev := unix.Kevent_t{Ident: uint64(pid), Filter: unix.EVFILT_PROC, Flags: unix.EV_DELETE}
	unix.Kevent(k.fd, []unix.Kevent_t{ev}, nil, nil)
}

// Run delivers events until ctx ends, then closes the kqueue. After each
// fork event it lists the children, and again after a short delay so a
// child that execs a moment later is classified without waiting for the
// next poll.
func (k *Kq) Run(ctx context.Context) error {
	defer k.Close()
	evs := make([]unix.Kevent_t, 16)
	for ctx.Err() == nil {
		ts := unix.NsecToTimespec(int64(250 * time.Millisecond))
		n, err := unix.Kevent(k.fd, nil, evs, &ts)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return err
		}
		forked := map[int]bool{}
		for _, e := range evs[:n] {
			pid := int(e.Ident)
			if e.Fflags&unix.NOTE_FORK != 0 {
				forked[pid] = true
			}
			if e.Fflags&unix.NOTE_EXIT != 0 {
				k.book.Untrack(pid)
			}
		}
		for pid := range forked {
			k.book.OnFork(pid)
		}
		if len(forked) > 0 {
			time.AfterFunc(150*time.Millisecond, func() {
				for pid := range forked {
					k.book.OnFork(pid)
				}
			})
		}
	}
	return ctx.Err()
}

// Close releases the kqueue.
func (k *Kq) Close() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed {
		return nil
	}
	k.closed = true
	return unix.Close(k.fd)
}
