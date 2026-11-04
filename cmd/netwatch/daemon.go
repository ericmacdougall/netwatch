package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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
	"github.com/ericmacdougall/netwatch/internal/sampler"
	"github.com/ericmacdougall/netwatch/internal/shapecheck"
	"github.com/ericmacdougall/netwatch/internal/transcript"
)

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

// testTarget validates a test daemon's target: it must parse and name a
// live process group whose leader started at the stated time.
func testTarget(cfg *config.Config, r resources.Full) (*resmon.TestTarget, error) {
	if cfg.GuardTestTarget == "" {
		return nil, errors.New("--test-daemon needs guard_test_target (PGID@START_UNIX_NANOS)")
	}
	pgid, ns, err := config.ParseTestTarget(cfg.GuardTestTarget)
	if err != nil {
		return nil, fmt.Errorf("guard_test_target: %w", err)
	}
	var p resources.Proc
	if err := r.Probe(pgid, &p); err != nil || p.PGID != pgid {
		return nil, fmt.Errorf("guard_test_target: pid %d is not a live group leader", pgid)
	}
	start := time.Unix(0, ns)
	if d := p.Start.Sub(start); d > 10*time.Millisecond || d < -10*time.Millisecond {
		return nil, fmt.Errorf("guard_test_target: pid %d started at %s, not %s", pgid, p.Start.UTC().Format(time.RFC3339Nano), start.UTC().Format(time.RFC3339Nano))
	}
	return &resmon.TestTarget{PGID: pgid, Start: p.Start}, nil
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
	m := guard.NewMachine(guardConfig(d.cfg, mode))
	sink := &resmon.Sink{Events: d.events, Guard: eventlog.NewWriter(filepath.Join(stateDir, "guard-events.jsonl"), max)}
	exec := &guard.Executor{M: m, Sig: guard.OSSignaller{Starts: guard.ReaderStart{R: r}, Self: os.Getpid()},
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

	loop := resmon.New(resmon.Deps{
		R: r,
		Classifier: &resmon.Elig{R: r, SelfPID: os.Getpid(), UID: os.Getuid(),
			NeverSignal: d.cfg.GuardNeverSignal, Versions: d.cfg.GuardClaudeVersions,
			AllowlistDir: allowDir, Labeler: labeler},
		Machine:   m,
		Exec:      exec,
		Alerts:    alerts.New(alertsConfig(d.cfg), d.notifier, recordSink{d.events}),
		Sampler:   sampler.New(r, 10),
		Resources: eventlog.NewWriter(filepath.Join(a.logDir, "resources.jsonl"), max),
		Events:    sink,
		Notify:    d.notifier,
		Budget:    budget.Config{Dir: budgetDir, RunCappedPaths: d.cfg.RunCappedPaths},
		Watcher:   resmon.NewWatcher(ctx, r, errs),
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
			v := v
			res, err := shapecheck.Run(shapecheck.Config{
				Version: v, StateDir: stateDir,
				SettingsPaths: shapecheck.DefaultSettingsPaths(home, nil),
				Children:      func() []shapecheck.Child { return liveChildren(r, v) },
				Calls: func(from, to time.Time) ([]transcript.Call, error) {
					c, _, err := transcript.Scan(transcript.Config{WindowStart: from})
					return c, err
				},
				Events: d.events,
			}, now)
			if err != nil {
				errs("shape check", err)
			}
			s.Record(now, res.Verdict)
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
