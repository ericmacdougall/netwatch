package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sync"
	"time"

	"github.com/ericmacdougall/netwatch/internal/alerts"
	"github.com/ericmacdougall/netwatch/internal/attrib"
	"github.com/ericmacdougall/netwatch/internal/budget"
	"github.com/ericmacdougall/netwatch/internal/collector"
	"github.com/ericmacdougall/netwatch/internal/config"
	"github.com/ericmacdougall/netwatch/internal/eventlog"
	"github.com/ericmacdougall/netwatch/internal/guard"
	"github.com/ericmacdougall/netwatch/internal/incident"
	"github.com/ericmacdougall/netwatch/internal/notify"
	"github.com/ericmacdougall/netwatch/internal/record"
	"github.com/ericmacdougall/netwatch/internal/resmon"
	"github.com/ericmacdougall/netwatch/internal/resources"
	"github.com/ericmacdougall/netwatch/internal/safeio"
	"github.com/ericmacdougall/netwatch/internal/sampler"
	"github.com/ericmacdougall/netwatch/internal/shapecheck"
	"github.com/ericmacdougall/netwatch/internal/transcript"
)

// daemonMemLimit is the Go soft memory limit for the daemon, under the
// 30 MB RSS budget with room for the binary and stacks.
const daemonMemLimit = 20 << 20

// resourceDeps is what the resource daemon needs from cmdRun.
type resourceDeps struct {
	cfg      *config.Config
	events   *eventlog.Writer
	notifier *notify.Limiter
	target   *resmon.TestTarget // non-nil only for a validated test daemon
}

// recordSink adapts the events writer to alerts.Sink.
type recordSink struct{ w *eventlog.Writer }

func (s recordSink) Emit(ev record.Event) { _ = s.w.Append(ev) }

// checkUnclean records one INCIDENT event when the previous run ended
// without a clean STOP (spec: at start, before the new START).
func (a *app) checkUnclean(events *eventlog.Writer) {
	evPath, _ := a.paths()
	cfg := incident.DetectConfig{EventsPath: evPath,
		ActivityPaths: []string{filepath.Join(a.logDir, "resources.jsonl")}, Now: time.Now()}
	if d := diagDir(); d != "" {
		cfg.DiagDirs = []string{d}
	}
	if _, _, err := incident.CheckAndRecord(cfg, events, nil); err != nil {
		fmt.Fprintln(a.stderr, "netwatch: incident check:", err)
	}
}

// testJobTier maps --test-tier to what the guard may do to the job.
func testJobTier(s string) (guard.Tier, error) {
	switch s {
	case "pause":
		return guard.TierFallback, nil
	case "kill":
		if !guardtestBuild {
			return guard.TierNone, errors.New("--test-tier kill needs a guardtest build")
		}
		return guard.TierTool, nil
	}
	return guard.TierNone, usageError{fmt.Errorf("--test-tier: want pause or kill, not %q", s)}
}

// spawnTestJob starts the test daemon's job in its own process group and
// records the group in <state>/test-target. The job's output goes to
// test-job.log. When the job exits, stop is called so the daemon exits too.
// The returned target is the only group the daemon may ever signal.
func (a *app) spawnTestJob(argv []string, tier guard.Tier, stop func()) (*resmon.TestTarget, <-chan error, error) {
	stateDir, _, _ := statePaths(a.logDir)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, nil, err
	}
	out, err := safeio.OpenAppend(filepath.Join(a.logDir, "test-job.log"))
	if err != nil {
		return nil, nil, err
	}
	cmd, err := startTestJob(argv, out)
	out.Close()
	if err != nil {
		return nil, nil, fmt.Errorf("test job: %w", err)
	}
	pid := cmd.Process.Pid
	var p resources.Proc
	if err := resources.New().Probe(pid, &p); err != nil || p.PGID != pid {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, nil, fmt.Errorf("test job %d: cannot confirm its process group: %v", pid, err)
	}
	t := &resmon.TestTarget{PGID: pid, Start: p.Start, Tier: tier}
	rec := fmt.Sprintf("%d %d\n", t.PGID, t.Start.UnixNano())
	if err := safeio.WriteFileAtomic(stateDir, "test-target", []byte(rec)); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, nil, err
	}
	fmt.Fprintf(a.stderr, "netwatch: test daemon guarding job group %d (%s only)\n", pid, tierText(tier))
	done := make(chan error, 1)
	go func() { done <- cmd.Wait(); stop() }()
	return t, done, nil
}

func tierText(t guard.Tier) string {
	if t == guard.TierTool {
		return "pause and kill"
	}
	return "pause"
}

// exitText describes how a job ended.
func exitText(err error) string {
	if err == nil {
		return "status 0"
	}
	return err.Error()
}

// refuseInstalledPaths keeps a test daemon away from the installed
// agent's config, log directory and state.
func (a *app) refuseInstalledPaths() error {
	if !a.configFlagSet || !a.logDirFlagSet {
		return errors.New("--test-daemon needs explicit --config and --log-dir")
	}
	same := func(x, y string) bool {
		ax, err1 := filepath.Abs(x)
		ay, err2 := filepath.Abs(y)
		return err1 == nil && err2 == nil && filepath.Clean(ax) == filepath.Clean(ay)
	}
	if same(a.configPath, config.DefaultPath()) {
		return errors.New("--test-daemon refuses the installed agent's config file")
	}
	if same(a.logDir, collector.DefaultLogDir()) {
		return errors.New("--test-daemon refuses the installed agent's log directory (and so its state)")
	}
	return nil
}

// startResources runs the resource sampler, alerts and memory guard until
// ctx ends. The returned channel yields the loop's result after it has
// resumed every paused group.
func (a *app) startResources(ctx context.Context, d resourceDeps) (<-chan error, error) {
	// The budget is 30 MB RSS. The live heap is a few MB, but bursts (the
	// shape check's transcript scan, jetsam reports) leave freed memory
	// mapped; a soft limit makes the GC and scavenger give it back.
	debug.SetMemoryLimit(daemonMemLimit)
	r := resources.New()
	stateDir, stateFile, allowDir := statePaths(a.logDir)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(stateDir, 0o700); err != nil {
		return nil, err
	}
	tt := d.target
	max := int64(d.cfg.MaxLogMB * 1024 * 1024)
	errs := rateLimitedErrs(a.stderr)

	mode, _ := effectiveMode(d.cfg, stateDir, runtime.GOOS)
	gc := guardConfig(d.cfg, mode)
	m := guard.NewMachine(gc)
	sink := &resmon.Sink{Events: d.events, Guard: eventlog.NewWriter(filepath.Join(stateDir, "guard-events.jsonl"), max)}
	var sig guard.Signaller = guard.OSSignaller{Starts: guard.ReaderStart{R: r}, Self: os.Getpid()}
	loopR := resources.Full(r)
	if tt != nil {
		// The hard boundary for live tests: no signal leaves the spawned
		// job's group, whatever the classifier or the machine decide.
		sig = resmon.SpawnedOnly{Inner: sig, R: r, Target: *tt}
		loopR = testReader(r, stateDir)
	}
	exec := &guard.Executor{M: m, Sig: sig,
		Store: &guard.FileStore{Path: stateFile}, View: guard.ReaderView{R: r}, Events: sink, Notify: d.notifier}

	home, _ := os.UserHomeDir()
	var labeler *attrib.Labeler
	if home != "" {
		labeler = &attrib.Labeler{FS: attrib.DirReader{Root: filepath.Join(home, ".claude", "wals")}}
	}
	budgetDir := ""
	if home != "" {
		budgetDir = filepath.Join(home, ".agent-harness", "state", "run_capped")
	}
	interval := time.Duration(d.cfg.ResourcesEveryS) * time.Second
	if tt != nil {
		sink.Event(record.GuardTestTarget, map[string]any{"pgid": tt.PGID, "reason": "test daemon: every other group is alert-only"})
		if d.notifier != nil {
			d.notifier.Notify("guard-test-target", "netwatch test daemon", fmt.Sprintf("Guard limited to test group %d", tt.PGID))
		}
	}

	elig := &resmon.Elig{R: r, SelfPID: os.Getpid(), UID: os.Getuid(),
		NeverSignal: d.cfg.GuardNeverSignal, Versions: d.cfg.GuardClaudeVersions,
		AllowlistDir: allowDir, Labeler: labeler}
	if tt != nil {
		elig.TestJobPGID = tt.PGID
	}
	loop := resmon.New(resmon.Deps{
		R:          loopR,
		Classifier: elig,
		Danger:     &gc.Danger,
		Machine:    m,
		Exec:       exec,
		Alerts:     alerts.New(alertsConfig(d.cfg), d.notifier, recordSink{d.events}),
		Sampler:    sampler.New(r, 10),
		Resources:  eventlog.NewWriter(filepath.Join(a.logDir, "resources.jsonl"), max),
		Events:     sink,
		Notify:     d.notifier,
		Budget:     budget.Config{Dir: budgetDir, RunCappedPaths: d.cfg.RunCappedPaths},
		Watcher:    resmon.NewWatcher(ctx, r, errs),
		Mode: func() (guard.Mode, bool) {
			mode, _ := effectiveMode(d.cfg, stateDir, runtime.GOOS)
			return mode, true
		},
		JetsamDir:   diagDir(),
		Errs:        errs,
		Interval:    interval,
		SampleEvery: interval,
		HotAlways:   tt != nil && d.cfg.HotAlways,
		TestTarget:  tt,
	})
	done := make(chan error, 1)
	go func() { done <- loop.Run(ctx) }()
	go a.shapeChecks(ctx, d, stateDir, r, errs)
	return done, nil
}

// shapeChecks verifies each newly seen Claude Code version once, retrying
// an inconclusive result hourly up to 24 times (plan Amendment A4).
func (a *app) shapeChecks(ctx context.Context, d resourceDeps, stateDir string, r resources.Full, errs func(string, error)) {
	sched := map[string]*shapecheck.Schedule{}
	home, _ := os.UserHomeDir()
	for {
		now := time.Now()
		for _, v := range runningClaudeVersions() {
			s := sched[v]
			if s == nil {
				if len(sched) > 64 {
					sched = map[string]*shapecheck.Schedule{}
				}
				s = &shapecheck.Schedule{}
				sched[v] = s
			}
			if shapecheck.Allowed(stateDir, v) || !s.Due(now) {
				continue
			}
			kids := liveChildren(r, v)
			ws, ok := shapeWindowStart(kids)
			if !ok {
				// No tool-shell-shaped child to confirm right now: the same
				// inconclusive verdict Run would give, without reading
				// any transcript.
				s.Record(now, shapecheck.Inconclusive)
				continue
			}
			res, err := shapecheck.Run(shapecheck.Config{
				Version: v, StateDir: stateDir,
				SettingsPaths: shapecheck.DefaultSettingsPaths(home, nil),
				Children:      func() []shapecheck.Child { return kids },
				Calls: func(from, to time.Time) ([]transcript.Call, error) {
					if from.Before(ws) {
						from = ws
					}
					c, _, err := transcript.Scan(transcript.Config{WindowStart: from,
						MaxFiles: shapeMaxFiles, MaxFileBytes: shapeMaxFileBytes})
					return c, err
				},
				Events: d.events,
			}, now)
			if err != nil {
				errs("shape check", err)
			}
			s.Record(now, res.Verdict)
			// The scan is a burst of large, short-lived reads; return the
			// memory now rather than holding it until the next GC cycle.
			debug.FreeOSMemory()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Minute):
		}
	}
}

// rateLimitedErrs prints each kind of error at most once a minute, so a
// persistent failure cannot flood stderr.log.
func rateLimitedErrs(w interface{ Write([]byte) (int, error) }) func(string, error) {
	var mu sync.Mutex
	last := map[string]time.Time{}
	return func(what string, err error) {
		mu.Lock()
		defer mu.Unlock()
		if t, ok := last[what]; ok && time.Since(t) < time.Minute {
			return
		}
		if len(last) > 256 {
			last = map[string]time.Time{}
		}
		last[what] = time.Now()
		fmt.Fprintf(w, "netwatch: %s: %v\n", what, err)
	}
}

// guardInstallNote is printed by install: the guard mode in effect and the
// one-command opt-out (finding CR-10: kill is on by default on macOS).
func guardInstallNote(cfg *config.Config, logDir, goos string) string {
	stateDir, _, _ := statePaths(logDir)
	mode, src := effectiveMode(cfg, stateDir, goos)
	note := fmt.Sprintf("memory guard: mode %s (%s).", mode, src)
	switch mode {
	case guard.ModePauseKill:
		note += " When the host is about to run out of memory it pauses the Claude Code job causing it, and kills it only as a last resort."
	case guard.ModePause:
		note += " When the host is about to run out of memory it pauses the Claude Code job causing it; it never kills."
	}
	if mode == guard.ModePause || mode == guard.ModePauseKill {
		note += " Alerts only: netwatch guard alert"
	} else {
		note += " Enable pausing with: netwatch guard pause"
	}
	return note
}

// Shape-check transcript bounds for the daemon. The check matches calls to
// children alive now, so it reads only recently modified transcripts, and
// only their tails (the 30 MB RSS budget; an unbounded 24h scan cost about
// 22 MB on a busy machine).
const (
	shapeMaxFiles     = 50
	shapeMaxFileBytes = 1 << 20
	shapeSlack        = 5 * time.Second
)

// shapeWindowStart is just before the oldest tool-shell-shaped child
// (setsid, no tty) started. ok is false when there is none.
func shapeWindowStart(kids []shapecheck.Child) (time.Time, bool) {
	var ws time.Time
	for _, k := range kids {
		if !k.Shape.Setsid || !k.Shape.NoTTY || k.Start.IsZero() {
			continue
		}
		if ws.IsZero() || k.Start.Before(ws) {
			ws = k.Start
		}
	}
	if ws.IsZero() {
		return ws, false
	}
	return ws.Add(-shapeSlack), true
}
