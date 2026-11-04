//go:build darwin

package watcher

import (
	"context"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/ericmacdougall/netwatch/internal/resources"
)

// TestRealKqueueForkThenSetsid watches this test process as the stand-in
// for Claude Code. It starts a shell in its own session that backgrounds a
// short sleep and exits at once, as a tool shell does. The book must record
// the shell from the NOTE_FORK event alone, and the record must survive the
// shell's exit for as long as the backgrounded job leads the group.
func TestRealKqueueForkThenSetsid(t *testing.T) {
	r := resources.New()
	self := os.Getpid()
	var me resources.Proc
	if err := r.Probe(self, &me); err != nil {
		t.Fatal(err)
	}
	book := NewBook(r, nil)
	book.Track(self, me.Start, r.ExePath(self))
	kq, err := NewKq(book)
	if err != nil {
		t.Fatal(err)
	}
	if err := kq.Add(self); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { kq.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	// The shell is a child we spawn; the sleep it backgrounds runs 4s and
	// is never signalled.
	c := exec.Command("/bin/sh", "-c", "(sleep 4 &) ; exit 0")
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	pid := c.Process.Pid
	c.Wait()

	var rec Record
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if x, ok := book.Lookup(pid); ok {
			rec = x
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if rec.PID != pid {
		t.Fatalf("no record for the forked shell %d; records %+v", pid, book.Records())
	}
	if rec.ClaudePID != self || !rec.ClaudeStart.Equal(me.Start) {
		t.Fatalf("claude identity not recorded: %+v", rec)
	}
	// The shell has exited, but its backgrounded job leads pgid == sid ==
	// pid. A scan taken now, even once the record is old enough, must keep it.
	procs, err := r.Procs()
	if err != nil {
		t.Fatal(err)
	}
	holder := false
	for _, p := range procs {
		if p.PID != pid && (p.SID == pid || p.PGID == pid) {
			holder = true
		}
	}
	if !holder {
		t.Skip("the backgrounded sleep already ended; cannot exercise the survival rule")
	}
	book.now = func() time.Time { return time.Now().Add(MinRetireAge + time.Second) }
	book.SetFresh(time.Hour)
	if n := book.Retire(Scan{At: time.Now().Add(MinRetireAge + time.Second), OK: true, Procs: procs}); n != 0 {
		t.Fatal("record retired while a live process still led its group")
	}
}
