//go:build darwin

package resmon

import (
	"context"

	"github.com/ericmacdougall/netwatch/internal/resources"
	"github.com/ericmacdougall/netwatch/internal/watcher"
)

// kqWatcher adapts the watcher Book and its kqueue to the loop.
type kqWatcher struct {
	book *watcher.Book
	kq   *watcher.Kq
}

// NewWatcher starts the kqueue watcher. It returns nil (no watcher; groups
// reach the fallback tier at most) if kqueue cannot be created.
func NewWatcher(ctx context.Context, r resources.Full, errs func(string, error)) Watcher {
	b := watcher.NewBook(r, nil)
	kq, err := watcher.NewKq(b)
	if err != nil {
		errs("watcher", err)
		return nil
	}
	go func() {
		if err := kq.Run(ctx); err != nil && ctx.Err() == nil {
			errs("watcher", err)
		}
	}()
	return &kqWatcher{book: b, kq: kq}
}

// Watch tracks every Claude process the classifier found and stops
// tracking ones that are gone. A Claude process that starts between scans
// is watched from the next scan (spec: until then its children reach the
// fallback tier at most).
func (w *kqWatcher) Watch(claude []resources.Proc) {
	live := make(map[int]bool, len(claude))
	for _, c := range claude {
		live[c.PID] = true
	}
	tracked := map[int]bool{}
	for _, pid := range w.book.Tracked() {
		tracked[pid] = true
		if !live[pid] {
			w.book.Untrack(pid)
			w.kq.Remove(pid)
		}
	}
	for _, c := range claude {
		if tracked[c.PID] {
			continue
		}
		if err := w.kq.Add(c.PID); err != nil {
			continue // exited before we could watch it
		}
		w.book.Track(c.PID, c.Start, c.Exe)
		// Children forked before the knote existed are picked up now.
		w.book.OnFork(c.PID)
	}
	w.book.Settle()
}

func (w *kqWatcher) Records() []watcher.Record { return w.book.Records() }

func (w *kqWatcher) AfterScan(s watcher.Scan) { w.book.Retire(s) }
