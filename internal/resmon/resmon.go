// Package resmon is the resource side of the netwatch daemon: it samples
// memory, tracks agent-owned process groups, raises early-warning alerts,
// writes resources.jsonl, and drives the guard state machine. The network
// monitor (internal/monitor) runs beside it in its own goroutine; the two
// share nothing but the event log.
//
// One loop does everything in a fixed order per tick, so a guard decision
// always sees the scan, the tracker and the danger signals of the same
// moment:
//
//	read system -> (scan when due: budgets, classify, watcher, jetsam)
//	-> tracker poll -> danger -> guard step -> executor -> alerts -> sample
//
// The tick is 10s, or 2s while the host or any agent group is hot. The
// scan is every 10s, or 5s while hot.
package resmon

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"sync"
	"time"

	"github.com/ericmacdougall/netwatch/internal/alerts"
	"github.com/ericmacdougall/netwatch/internal/budget"
	"github.com/ericmacdougall/netwatch/internal/danger"
	"github.com/ericmacdougall/netwatch/internal/guard"
	"github.com/ericmacdougall/netwatch/internal/jetsam"
	"github.com/ericmacdougall/netwatch/internal/resources"
	"github.com/ericmacdougall/netwatch/internal/sampler"
	"github.com/ericmacdougall/netwatch/internal/tracker"
	"github.com/ericmacdougall/netwatch/internal/watcher"
)

// Classification is what the eligibility classifier derives from one scan.
type Classification struct {
	Groups []tracker.GroupInfo
	// OwnerOf gives the ineligible-aggregate key of a process.
	OwnerOf func(resources.Proc) string
	// Excluded reports a never-signal member (its subtree is excluded).
	Excluded func(p *resources.Proc, exe string) bool
	// Claude lists the Claude Code processes found, for the watcher.
	Claude []resources.Proc
}

// Classifier turns a full scan into guard groups. It is the only place
// that decides what may ever be signalled.
type Classifier interface {
	Classify(scan []resources.Proc, recs []watcher.Record, budgets map[int]budget.Declared) Classification
}

// Watcher records the children Claude Code forks (darwin kqueue). Nil on
// platforms without one; groups then reach the fallback tier at most.
type Watcher interface {
	// Watch makes sure every listed Claude process is watched.
	Watch(claude []resources.Proc)
	// Records returns the current tool-shell records.
	Records() []watcher.Record
	// AfterScan retires records the scan proves dead (CR-3, CR-11).
	AfterScan(s watcher.Scan)
}

// ModeSource returns the mode the user last chose, or ok=false to keep the
// current one (a missing or unreadable mode file never changes the mode).
type ModeSource func() (guard.Mode, bool)

// Deps wires the loop. Every field without a comment is required.
type Deps struct {
	R          resources.Full
	Classifier Classifier
	Machine    *guard.Machine
	Exec       *guard.Executor
	Alerts     *alerts.Engine
	Sampler    *sampler.Sampler
	Resources  Appender // resources.jsonl (rotating), one record per sample
	Events     guard.EventSink
	Budget     budget.Config
	Watcher    Watcher        // optional
	Mode       ModeSource     // optional
	Notify     guard.Notifier // optional; a mode change notifies
	JetsamDir  string         // optional; "" disables D5
	Now        func() time.Time
	Errs       func(what string, err error) // optional, rate-limited by the caller

	Interval, HotInterval time.Duration // 10s, 2s
	ScanEvery, HotScan    time.Duration // 10s, 5s
	SampleEvery           time.Duration // 10s
	HotAlways             bool          // test daemon only
	HotBytes              uint64        // a group at or above this makes us hot (2 GB)
	TestTarget            *TestTarget   // test daemon only
}

// TestTarget limits the guard to one process group. Every other group is
// demoted to alert-only before the machine sees it.
type TestTarget struct {
	PGID  int
	Start time.Time
}

// Loop is the running daemon state. Use New, then Run.
type Loop struct {
	d    Deps
	trk  *tracker.Tracker
	det  *danger.Detector
	view guard.ReaderView

	mu       sync.Mutex
	cls      Classification
	procs    []resources.Proc
	scanAt   time.Time
	scanOK   bool
	nextScan time.Time
	nextSamp time.Time
	selfErr  error
	jetsamAt time.Time // newest report already seen
	d5       bool      // a new non-idle report arrived since the last poll
}

// New builds a loop. The tracker consults the latest classification for
// exclusions, so a member excluded by the classifier is never counted or
// signalled even between scans.
func New(d Deps) *Loop {
	setDefaults(&d)
	l := &Loop{d: d, det: &danger.Detector{Cfg: danger.Defaults()}, view: guard.ReaderView{R: d.R}}
	l.trk = tracker.New(d.R, tracker.Config{Excluded: func(p *resources.Proc, exe string) bool {
		l.mu.Lock()
		f := l.cls.Excluded
		l.mu.Unlock()
		return f != nil && f(p, exe)
	}})
	return l
}

func setDefaults(d *Deps) {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Interval == 0 {
		d.Interval = 10 * time.Second
	}
	if d.HotInterval == 0 {
		d.HotInterval = 2 * time.Second
	}
	if d.ScanEvery == 0 {
		d.ScanEvery = 10 * time.Second
	}
	if d.HotScan == 0 {
		d.HotScan = 5 * time.Second
	}
	if d.SampleEvery == 0 {
		d.SampleEvery = 10 * time.Second
	}
	if d.HotBytes == 0 {
		d.HotBytes = 2 << 30
	}
	if d.Errs == nil {
		d.Errs = func(string, error) {}
	}
}

// Run starts the guard (self-test, crash recovery) and ticks until ctx is
// cancelled. On cancellation every group the guard paused is resumed.
func (l *Loop) Run(ctx context.Context) error {
	if err := l.d.R.SelfTest(); err != nil {
		l.selfErr = err
		l.d.Events.Event("GUARD_SELFTEST_FAILED", map[string]any{"error": err.Error(), "effect": "pause and kill disabled"})
	}
	l.d.Exec.Recover()
	defer l.d.Exec.Shutdown()
	for {
		hot := l.Tick()
		wait := l.d.Interval
		if hot {
			wait = l.d.HotInterval
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
}

// Tick runs one poll and reports whether the next one should come soon.
func (l *Loop) Tick() (hot bool) {
	now := l.d.Now()
	sys, err := l.d.R.System()
	if err != nil {
		// No reading, no decision: the guard never acts on a failed read.
		l.d.Errs("system", err)
		return false
	}
	if sys.At.IsZero() {
		sys.At = now
	}
	if l.d.Mode != nil {
		if m, ok := l.d.Mode(); ok && m != l.d.Machine.Mode() {
			old := l.d.Machine.Mode()
			l.d.Machine.SetMode(m)
			l.d.Events.Event("MODE_CHANGE", map[string]any{"from": string(old), "to": string(m)})
			if l.d.Notify != nil {
				// Spec: every change is visible to the user, including one an
				// agent made.
				l.d.Notify.Notify("mode-change", "netwatch memory guard",
					fmt.Sprintf("Guard mode changed from %s to %s. Set it with: netwatch guard MODE", old, m))
			}
		}
	}
	if !now.Before(l.nextScan) {
		l.scan(now, sys)
	}

	terms := l.trk.Poll(now, sys)
	if l.d.TestTarget != nil {
		demoteOthers(terms, *l.d.TestTarget)
	}
	sig := l.det.Observe(sys, l.takeD5(), groupSeries(terms))

	l.mu.Lock()
	snap := guard.Snapshot{At: now, Sys: sys, Signals: sig, Terms: terms,
		ScanAt: l.scanAt, ScanOK: l.scanOK, SelfTest: l.selfErr, Alive: l.view.Alive}
	procs := l.procs
	l.mu.Unlock()

	// A missing state file just means nothing has been paused yet.
	if err := l.d.Exec.Reconcile(); err != nil && !errors.Is(err, guard.ErrMissing) {
		l.d.Errs("guard reconcile", err)
	}
	l.d.Exec.Apply(l.d.Machine.Step(snap))

	l.d.Alerts.Run(alerts.Input{At: now, Sys: sys, Procs: procs, Series: alertSeries(terms)})

	if !now.Before(l.nextSamp) {
		l.sample(now, sys, procs)
	}

	hot = l.d.HotAlways || sig.Danger || len(l.d.Machine.RecordKeys()) > 0
	for _, t := range terms {
		if t.Group != nil && t.Group.Footprint >= l.d.HotBytes {
			hot = true
		}
	}
	scanGap := l.d.ScanEvery
	if hot {
		scanGap = l.d.HotScan
	}
	if l.nextScan.After(now.Add(scanGap)) {
		l.nextScan = now.Add(scanGap)
	}
	return hot
}

// scan reads the process table and refreshes everything derived from it.
func (l *Loop) scan(now time.Time, sys resources.System) {
	procs, err := l.d.R.Procs()
	ok := err == nil
	if err != nil {
		l.d.Errs("scan", err)
	}
	var budgets map[int]budget.Declared
	if ok {
		cfg := l.d.Budget
		cfg.RAM = sys.RAM
		if res, err := budget.Load(cfg, budget.FactsFromProcs(l.d.R, procs)); err != nil {
			l.d.Errs("budget", err)
		} else {
			budgets = res.Budgets
		}
	}
	var recs []watcher.Record
	if l.d.Watcher != nil {
		recs = l.d.Watcher.Records()
	}
	var cls Classification
	if ok {
		cls = l.d.Classifier.Classify(procs, recs, budgets)
		if l.d.Watcher != nil {
			l.d.Watcher.Watch(cls.Claude)
		}
		l.trk.SetScan(procs, cls.OwnerOf)
		l.trk.SetGroups(cls.Groups)
	}
	if l.d.Watcher != nil {
		// A failed scan is passed on with OK=false so it retires nothing.
		l.d.Watcher.AfterScan(watcher.Scan{At: now, OK: ok, Procs: procs})
	}
	l.checkJetsam()

	l.mu.Lock()
	if ok {
		l.cls, l.procs = cls, procs
	}
	l.scanAt, l.scanOK = now, ok
	l.mu.Unlock()
	l.nextScan = now.Add(l.d.ScanEvery)
}

// checkJetsam sets d5 when a new jetsam report with a non-idle kill has
// appeared. D5 never raises danger alone; it only shortens D1.
func (l *Loop) checkJetsam() {
	if l.d.JetsamDir == "" {
		return
	}
	since := l.jetsamAt
	res, err := jetsam.ScanDir(l.d.JetsamDir, jetsam.ScanLimits{MaxFiles: 4, MaxBytes: 4 * jetsam.MaxReportBytes, Since: since})
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			l.d.Errs("jetsam", err)
		}
		return
	}
	for _, r := range res.Reports {
		if !r.Date.After(l.jetsamAt) {
			continue
		}
		if l.jetsamAt.IsZero() {
			// First scan after start: remember the newest report but do not
			// treat history as a fresh signal.
			continue
		}
		if r.NonIdleKill {
			l.mu.Lock()
			l.d5 = true
			l.mu.Unlock()
		}
	}
	for _, r := range res.Reports {
		if r.Date.After(l.jetsamAt) {
			l.jetsamAt = r.Date
		}
	}
	if l.jetsamAt.IsZero() {
		// No reports at all: use "now" so the next new one counts.
		l.jetsamAt = l.d.Now()
	}
}

func (l *Loop) takeD5() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	d5 := l.d5
	l.d5 = false
	return d5
}

// sample writes one resources.jsonl record, labelling rows with the agent
// of their group when the classifier knows it.
func (l *Loop) sample(now time.Time, sys resources.System, procs []resources.Proc) {
	l.nextSamp = now.Add(l.d.SampleEvery)
	if procs == nil || l.d.Resources == nil {
		return
	}
	rec := l.d.Sampler.From(sys, procs, now)
	l.mu.Lock()
	agents := make(map[int]string, len(l.cls.Groups))
	for _, g := range l.cls.Groups {
		if g.Agent != "" {
			agents[g.PGID] = g.Agent
		}
	}
	l.mu.Unlock()
	label := func(rows []sampler.Row) {
		for i := range rows {
			if a, ok := agents[rows[i].PGID]; ok {
				rows[i].Agent = a
			}
		}
	}
	label(rec.TopMem)
	label(rec.TopCPU)
	if err := l.d.Resources.Append(rec); err != nil {
		l.d.Errs("sample write", err)
	}
}

// demoteOthers makes every group other than the test target alert-only,
// so a test daemon can never signal anything but its own job.
func demoteOthers(terms []guard.Term, t TestTarget) {
	for i := range terms {
		g := terms[i].Group
		if g == nil {
			continue
		}
		if g.PGID != t.PGID || !g.LeaderStart.Equal(t.Start) {
			c := *g
			c.Tier = guard.TierNone
			terms[i].Group = &c
		}
	}
}

func groupSeries(terms []guard.Term) []danger.GroupSeries {
	out := make([]danger.GroupSeries, 0, len(terms))
	for _, t := range terms {
		if t.Group != nil {
			out = append(out, danger.GroupSeries{PGID: t.Group.PGID, Series: t.Series})
		}
	}
	return out
}

// alertSeries passes every term except "unattributed", which has no owner
// to warn about.
func alertSeries(terms []guard.Term) []alerts.Series {
	out := make([]alerts.Series, 0, len(terms))
	for _, t := range terms {
		if t.Key == "unattributed" {
			continue
		}
		pts := make([]alerts.Point, len(t.Series))
		for i, p := range t.Series {
			pts[i] = alerts.Point{At: p.At, Bytes: p.Bytes}
		}
		out = append(out, alerts.Series{Key: t.Key, Points: pts})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}
