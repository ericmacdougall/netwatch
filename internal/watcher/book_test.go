package watcher

import (
	"sort"
	"testing"
	"time"

	"github.com/ericmacdougall/netwatch/internal/resources"
)

// world is a fake process table with a controllable clock.
type world struct {
	now   time.Time
	procs map[int]resources.Proc
	exe   map[int]string
}

func newWorld() *world {
	return &world{now: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC), procs: map[int]resources.Proc{}, exe: map[int]string{}}
}

func (w *world) add(pid, ppid, pgid, sid int, exe string) resources.Proc {
	p := resources.Proc{PID: pid, PPID: ppid, PGID: pgid, SID: sid, Start: w.now, Exe: exe, FootprintOK: true}
	w.procs[pid] = p
	w.exe[pid] = exe
	return p
}

func (w *world) kill(pid int) { delete(w.procs, pid); delete(w.exe, pid) }

func (w *world) setsid(pid int) {
	p := w.procs[pid]
	p.PGID, p.SID = pid, pid
	w.procs[pid] = p
}

func (w *world) exec(pid int, exe string) { w.exe[pid] = exe }

func (w *world) AppendChildren(dst []int, pid int) ([]int, error) {
	var out []int
	for _, p := range w.procs {
		if p.PPID == pid {
			out = append(out, p.PID)
		}
	}
	sort.Ints(out)
	return append(dst, out...), nil
}

func (w *world) Probe(pid int, p *resources.Proc) error {
	q, ok := w.procs[pid]
	if !ok {
		return resources.ErrGone
	}
	*p = q
	return nil
}

func (w *world) ExePath(pid int) string { return w.exe[pid] }

func (w *world) scan() Scan {
	s := Scan{At: w.now, OK: true}
	for _, p := range w.procs {
		s.Procs = append(s.Procs, p)
	}
	return s
}

func (w *world) advance(d time.Duration) { w.now = w.now.Add(d) }

const claudeExe = "/home/user/.local/share/claude/versions/2.1.318"

func setup(t *testing.T) (*world, *Book) {
	w := newWorld()
	w.add(100, 1, 100, 100, claudeExe)
	b := NewBook(w, func() time.Time { return w.now })
	b.Track(100, w.procs[100].Start, claudeExe)
	return w, b
}

// CR-3: fork, then scan, then setsid; the record must survive. The naive
// variant retires on "pid dead" alone and loses the record before the
// grandchildren become visible as a group.
func TestCR3ForkScanSetsidSurvival(t *testing.T) {
	w, b := setup(t)
	w.add(200, 100, 100, 100, claudeExe) // forked, still a copy of Claude
	if n, err := b.OnFork(100); err != nil || n != 1 {
		t.Fatalf("OnFork = %d, %v", n, err)
	}
	if r, _ := b.Lookup(200); r.State != Pending || r.ClaudePID != 100 || r.ClaudeStart.IsZero() {
		t.Fatalf("record %+v", r)
	}
	// The child execs a shell, then dies after starting a background job
	// that has not called setsid yet. Scan 5s later: pid dead, no leader.
	w.exec(200, "/bin/bash")
	b.Settle()
	w.kill(200)
	w.advance(5 * time.Second)
	if n := b.Retire(w.scan()); n != 0 {
		t.Fatal("retired a 5s-old record")
	}
	// The grandchild now exists in the child's group and session.
	w.add(300, 1, 200, 200, "/bin/sleep")
	w.advance(8 * time.Second) // 13s old
	if n := b.Retire(w.scan()); n != 0 {
		t.Fatal("retired a record whose pid still leads a live group/session")
	}
	// The group is gone: now it may go.
	w.kill(300)
	w.advance(time.Second)
	if n := b.Retire(w.scan()); n != 1 || b.Len() != 0 {
		t.Fatalf("retire after group exit = %d, len %d", n, b.Len())
	}
}

func TestRetireNeedsBothSidAndPgidChecks(t *testing.T) {
	for _, tc := range []struct {
		name      string
		pgid, sid int
	}{{"pgid only", 200, 7}, {"sid only", 7, 200}} {
		t.Run(tc.name, func(t *testing.T) {
			w, b := setup(t)
			w.add(200, 100, 100, 100, "/bin/bash")
			b.OnFork(100)
			w.kill(200)
			w.add(300, 1, tc.pgid, tc.sid, "/bin/sleep")
			w.advance(30 * time.Second)
			if n := b.Retire(w.scan()); n != 0 {
				t.Fatalf("retired with a process claiming %s", tc.name)
			}
		})
	}
}

// CR-11: a failed or stale scan retires nothing.
func TestCR11FailedOrStaleScanRetiresNothing(t *testing.T) {
	w, b := setup(t)
	w.add(200, 100, 100, 100, "/bin/bash")
	b.OnFork(100)
	w.kill(200)
	w.advance(time.Minute)
	good := w.scan()

	failed := good
	failed.OK = false
	failed.Procs = nil // what a failed scan looks like: empty, so everything seems dead
	if n := b.Retire(failed); n != 0 {
		t.Fatal("retired on a failed scan")
	}
	stale := good
	stale.At = w.now.Add(-time.Hour)
	if n := b.Retire(stale); n != 0 {
		t.Fatal("retired on a stale scan")
	}
	zero := Scan{OK: true}
	if n := b.Retire(zero); n != 0 {
		t.Fatal("retired on a scan with no timestamp")
	}
	if b.Len() != 1 {
		t.Fatalf("len %d", b.Len())
	}
	if n := b.Retire(good); n != 1 {
		t.Fatalf("a fresh good scan should retire, got %d", n)
	}
}

func TestScanTakenBeforeMinAgeDoesNotRetire(t *testing.T) {
	w, b := setup(t)
	w.add(200, 100, 100, 100, "/bin/bash")
	b.OnFork(100)
	w.kill(200)
	early := w.scan() // taken at the record's first sighting
	w.advance(time.Minute)
	b.SetFresh(2 * time.Minute) // fresh by clock, but observed before the record aged
	if n := b.Retire(early); n != 0 {
		t.Fatal("a scan older than the record's minimum age retired it")
	}
}

func TestPendingNeverRetired(t *testing.T) {
	w, b := setup(t)
	w.add(200, 100, 100, 100, claudeExe) // exec never completes
	b.OnFork(100)
	w.advance(time.Minute)
	b.Settle()
	if r, _ := b.Lookup(200); r.State != Pending {
		t.Fatalf("state %v", r.State)
	}
	// Drop the process from the table behind the book's back: even a
	// perfect scan must not retire a record that is still Pending.
	delete(w.procs, 200)
	if n := b.Retire(w.scan()); n != 0 {
		t.Fatal("retired a pending record")
	}
}

func TestClassifyOnlyAfterExec(t *testing.T) {
	w, b := setup(t)
	w.add(200, 100, 100, 100, claudeExe)
	b.OnFork(100)
	b.Settle()
	if r, _ := b.Lookup(200); r.State != Pending || r.Exe != "" {
		t.Fatalf("classified before exec: %+v", r)
	}
	w.exec(200, "/bin/zsh")
	b.Settle()
	if r, _ := b.Lookup(200); r.State != Classified || r.Exe != "/bin/zsh" || r.SetsidSeen {
		t.Fatalf("after exec: %+v", r)
	}
	w.setsid(200)
	b.Settle()
	if r, _ := b.Lookup(200); !r.SetsidSeen {
		t.Fatal("setsid not noticed")
	}
}

func TestUnverifiedWhenChildGoneBeforeExec(t *testing.T) {
	w, b := setup(t)
	w.add(200, 100, 100, 100, claudeExe)
	b.OnFork(100)
	w.kill(200)
	b.Settle()
	if r, _ := b.Lookup(200); r.State != Unverified {
		t.Fatalf("state %v", r.State)
	}
	// Child that was already gone when listed.
	w2, b2 := setup(t)
	w2.add(250, 100, 100, 100, "/bin/zsh")
	orig := w2.procs[250]
	_ = orig
	b2.src = &listsGhost{world: w2, ghost: 251}
	b2.OnFork(100)
	if r, ok := b2.Lookup(251); !ok || r.State != Unverified || !r.Start.IsZero() {
		t.Fatalf("ghost child: %+v %v", r, ok)
	}
}

// listsGhost reports a child pid that is gone by the time it is probed.
type listsGhost struct {
	*world
	ghost int
}

func (g *listsGhost) AppendChildren(dst []int, pid int) ([]int, error) {
	dst, err := g.world.AppendChildren(dst, pid)
	return append(dst, g.ghost), err
}

func TestPidReuseCountsAsDead(t *testing.T) {
	w, b := setup(t)
	w.add(200, 100, 100, 100, "/bin/bash")
	b.OnFork(100)
	w.kill(200)
	w.advance(30 * time.Second)
	p := w.add(200, 1, 5, 5, "/bin/other") // same pid, new process, not a leader of 200
	p.Start = w.now
	w.procs[200] = p
	if n := b.Retire(w.scan()); n != 1 {
		t.Fatalf("reused pid kept the record alive (retired %d)", n)
	}
}

func TestLimitsCapAndLifetime(t *testing.T) {
	w, b := setup(t)
	for i := 0; i < MaxRecords+50; i++ {
		w.add(1000+i, 100, 100, 100, "/bin/bash")
	}
	b.OnFork(100)
	if b.Len() != MaxRecords {
		t.Fatalf("len %d, want the cap %d", b.Len(), MaxRecords)
	}
	if b.Dropped() != 50 {
		t.Fatalf("dropped %d", b.Dropped())
	}
	// Unrecorded children are simply not eligible: no record exists.
	if _, ok := b.Lookup(1000 + MaxRecords + 10); ok {
		t.Fatal("a record was created past the cap")
	}
	// Free some slots with a good scan: the next listing records again.
	for i := 0; i < 100; i++ {
		w.kill(1000 + i)
	}
	w.advance(time.Minute)
	if n := b.Retire(w.scan()); n != 100 {
		t.Fatalf("retired %d", n)
	}
	b.OnFork(100)
	if want := MaxRecords + 50 - 100; b.Len() != want {
		t.Fatalf("len after refill %d, want %d", b.Len(), want)
	}
	// 24h lifetime: even a live record expires.
	w.advance(MaxLife + time.Hour)
	if b.Retire(Scan{}); b.Len() != 0 {
		t.Fatalf("lifetime expiry left %d records", b.Len())
	}
}

func TestTrackedOnlyAndUntrack(t *testing.T) {
	w, b := setup(t)
	w.add(200, 555, 555, 555, "/bin/bash") // child of an untracked process
	if n, _ := b.OnFork(555); n != 0 {
		t.Fatal("recorded a child of an untracked pid")
	}
	b.Untrack(100)
	w.add(201, 100, 100, 100, "/bin/bash")
	if n, _ := b.OnFork(100); n != 0 || len(b.Tracked()) != 0 {
		t.Fatal("recorded after Untrack")
	}
}

func TestSweepRecordsAllTracked(t *testing.T) {
	w, b := setup(t)
	w.add(101, 1, 101, 101, claudeExe)
	b.Track(101, w.now, claudeExe)
	w.add(200, 100, 100, 100, "/bin/bash")
	w.add(201, 101, 101, 101, "/bin/bash")
	b.Sweep()
	if b.Len() != 2 {
		t.Fatalf("len %d", b.Len())
	}
	r, _ := b.Lookup(201)
	if r.ClaudePID != 101 {
		t.Fatalf("%+v", r)
	}
}
