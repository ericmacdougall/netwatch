package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ericmacdougall/netwatch/internal/alerts"
	"github.com/ericmacdougall/netwatch/internal/attrib"
	"github.com/ericmacdougall/netwatch/internal/config"
	"github.com/ericmacdougall/netwatch/internal/eventlog"
	"github.com/ericmacdougall/netwatch/internal/guard"
	"github.com/ericmacdougall/netwatch/internal/guardmode"
	"github.com/ericmacdougall/netwatch/internal/record"
	"github.com/ericmacdougall/netwatch/internal/resources"
	"github.com/ericmacdougall/netwatch/internal/shapecheck"
	"github.com/ericmacdougall/netwatch/internal/transcript"
)

const gibBytes = 1 << 30

// statePaths returns the guard's state directory (<logDir>/state, 0700),
// its state file and the directory holding the kill-version allowlist.
func statePaths(logDir string) (stateDir, stateFile, allowlistDir string) {
	stateDir = filepath.Join(logDir, "state")
	return stateDir, filepath.Join(stateDir, "guard-state.json"), stateDir
}

// guardConfig maps the user config onto the guard and danger thresholds.
func guardConfig(cfg *config.Config, mode guard.Mode) guard.Config {
	gc := guard.DefaultConfig(mode)
	gc.Danger.MinShare = cfg.GuardMinShare
	gc.Danger.GroupRAMFrac = cfg.GuardGroupRAMFrac
	gc.Danger.HeadroomFrac = cfg.GuardHeadroomFrac
	gc.Danger.P1Horizon = time.Duration(cfg.GuardP1HorizonS) * time.Second
	gc.Danger.Clamp() // belt and braces: a hand-built Config is bounded too
	return gc
}

// daemonGuardConfig is the daemon's machine configuration. On macOS the
// kill stage is disabled outright, not only by the environment check:
// the README and `guard status` promise it never kills there.
func daemonGuardConfig(cfg *config.Config, mode guard.Mode, goos string) guard.Config {
	gc := guardConfig(cfg, mode)
	gc.NoKill = goos == "darwin"
	return gc
}

// alertsConfig maps the early-warning thresholds.
func alertsConfig(cfg *config.Config) alerts.Config {
	return alerts.Config{
		ProcBytes:     uint64(cfg.AlertProcGB * gibBytes),
		GrowthPerMin:  uint64(cfg.AlertGrowthGBPerMin * gibBytes),
		SwapBytes:     uint64(cfg.AlertSwapGB * gibBytes),
		ChromeHelpers: cfg.AlertChromeHelpers,
		Cooldown:      time.Duration(cfg.NotifyCooldownS) * time.Second,
	}
}

// modeSource says where the effective mode came from.
type modeSource string

const (
	srcFile    modeSource = "mode file"
	srcConfig  modeSource = "config"
	srcDefault modeSource = "platform default"
)

// effectiveMode is the mode file, else guard_mode, else the GOOS default.
// The daemon calls it every system poll.
func effectiveMode(cfg *config.Config, stateDir string, goos string) (guard.Mode, modeSource) {
	if m, ok := guardmode.Read(stateDir); ok {
		return m, srcFile
	}
	if cfg.GuardMode != "" && guardmode.Valid(cfg.GuardMode) {
		return guard.Mode(cfg.GuardMode), srcConfig
	}
	return guard.DefaultModeFor(goos), srcDefault
}

var sessionRe = regexp.MustCompile(`^[0-9A-Fa-f-]{8,64}$`)

// callerLabel is the attribution label for a mode change: the Claude Code
// session id when the caller runs inside one, otherwise "user".
func callerLabel() string {
	if id := os.Getenv("CLAUDE_CODE_SESSION_ID"); sessionRe.MatchString(id) {
		return "agent:" + id
	}
	return "user"
}

// resumeDeps supplies the process view and signaller for resume. Tests
// replace it with fakes that only know their own spawned processes.
var resumeDeps = func() (guard.ProcView, guard.Signaller) {
	rd := resources.New()
	return guard.ReaderView{R: rd}, guard.OSSignaller{Starts: guard.ReaderStart{R: rd}, Self: os.Getpid()}
}

// runningClaudeVersions lists the Claude Code versions currently running
// (replaced in tests).
var runningClaudeVersions = func() []string {
	ps, err := resources.New().Procs()
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	for _, p := range ps {
		if v, ok := attrib.ClaudeFromExe(p.Exe); ok {
			seen[v] = true
		}
	}
	var out []string
	for v := range seen {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

const optOut = "to turn the guard down: netwatch guard alert   (then: netwatch resume --all)"

// cmdGuard handles guard off|alert|pause|pause+kill|status|verify-shape.
func (a *app) cmdGuard(args []string) error {
	if len(args) == 0 {
		return usageError{errors.New("guard needs one of: off, alert, pause, pause+kill, status, verify-shape")}
	}
	sub, rest := args[0], args[1:]
	cfg := a.loadConfigOpts(false)
	stateDir, _, _ := statePaths(a.logDir)
	switch sub {
	case "status":
		if len(rest) > 0 {
			return usageError{fmt.Errorf("unexpected argument %q", rest[0])}
		}
		return a.guardStatus(cfg, stateDir, runtime.GOOS, runningClaudeVersions())
	case "verify-shape":
		return a.verifyShape(cfg, rest)
	case "simulate":
		return a.guardSimulate(stateDir, rest)
	}
	mode, err := guardmode.Parse(sub)
	if err != nil {
		return usageError{err}
	}
	if len(rest) > 0 {
		return usageError{fmt.Errorf("unexpected argument %q", rest[0])}
	}
	old, _ := effectiveMode(cfg, stateDir, runtime.GOOS)
	label := callerLabel()
	if err := guardmode.Write(stateDir, mode, label); err != nil {
		return fmt.Errorf("guard: cannot write the mode file: %w", err)
	}
	// Every change logs MODE_CHANGE with the caller's (redacted) label.
	ev, _ := a.paths()
	_ = eventlog.NewWriter(ev, int64(cfg.MaxLogMB*1024*1024)).Append(record.Event{
		TS: time.Now().Format(eventlog.TimeFormat), Event: record.ModeChange,
		Reason: fmt.Sprintf("guard mode %s -> %s by %s", old, mode, guardLabel(label)),
	})
	fmt.Fprintf(a.stdout, "guard mode: %s (was %s). The daemon applies it within one poll.\n", mode, old)
	if mode == guard.ModePauseKill && runtime.GOOS == "darwin" {
		fmt.Fprintln(a.stdout, macKillNote+"; this mode pauses only")
	}
	if mode == guard.ModePause || mode == guard.ModePauseKill {
		fmt.Fprintln(a.stdout, optOut)
	}
	if mode == guard.ModeOff || mode == guard.ModeAlert {
		fmt.Fprintln(a.stdout, "paused groups are resumed when the daemon sees the change; check with: netwatch guard status")
	}
	return nil
}

func guardLabel(l string) string {
	if len(l) > 80 {
		return l[:80]
	}
	return l
}

// statusLine is the one-line mode and thresholds summary.
func statusLine(cfg *config.Config, mode guard.Mode, src modeSource) string {
	gc := guardConfig(cfg, mode)
	return fmt.Sprintf("guard: mode=%s (%s) min_share=%g group_ram_fraction=%g headroom_frac=%g p1_horizon=%ds max_pause=%s kill_versions=%d",
		mode, src, gc.Danger.MinShare, gc.Danger.GroupRAMFrac, gc.Danger.HeadroomFrac,
		int(gc.Danger.P1Horizon/time.Second), gc.MaxPause, len(cfg.GuardClaudeVersions))
}

func (a *app) guardStatus(cfg *config.Config, stateDir, goos string, versions []string) error {
	mode, src := effectiveMode(cfg, stateDir, goos)
	fmt.Fprintln(a.stdout, statusLine(cfg, mode, src))
	if goos == "darwin" {
		fmt.Fprintln(a.stdout, macKillNote)
	}
	_, stateFile, allowDir := statePaths(a.logDir)
	st, err := (&guard.FileStore{Path: stateFile}).Load()
	switch {
	case errors.Is(err, guard.ErrMissing):
		fmt.Fprintln(a.stdout, "paused groups: none recorded")
	case err != nil:
		fmt.Fprintf(a.stdout, "paused groups: state file unusable (%v); resume refuses until it is repaired\n", err)
	default:
		keys := make([]string, 0, len(st.Groups))
		for k := range st.Groups {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if len(keys) == 0 {
			fmt.Fprintln(a.stdout, "paused groups: none")
		}
		for _, k := range keys {
			r := st.Groups[k]
			fmt.Fprintf(a.stdout, "paused pgid %d phase=%s since %s members=%d sticky=%v %s\n",
				r.PGID, r.Phase, r.PausedAt.Format(time.RFC3339), len(r.Members), r.Sticky, r.Cmd)
		}
	}
	if goos == "darwin" {
		return nil // per-version kill checks do not apply: see macKillNote
	}
	for _, v := range versions {
		fmt.Fprintln(a.stdout, killAvailability(cfg, allowDir, v))
	}
	return nil
}

// macKillNote is why the guard never kills on macOS. Kill requires every
// member of a job's group to show CLAUDECODE=1 in its own environment, and
// macOS does not let other processes read the environment of system
// binaries, which lead every tool-call job. The check is kept as is.
const macKillNote = "kill unavailable on macOS: environment of system binaries not readable"

// killAvailability says whether kill is available for a running version
// and why not.
func killAvailability(cfg *config.Config, allowDir, v string) string {
	for _, c := range cfg.GuardClaudeVersions {
		if c == v {
			return fmt.Sprintf("claude %s: kill available (listed in guard_claude_versions)", v)
		}
	}
	if shapecheck.Allowed(allowDir, v) {
		return fmt.Sprintf("claude %s: kill available (spawn shape verified)", v)
	}
	return fmt.Sprintf("claude %s: kill not available: Claude Code %s unverified (pause only); run: netwatch guard verify-shape", v, v)
}

// verifyShape runs the spawn-shape check once with the real inputs.
func (a *app) verifyShape(cfg *config.Config, args []string) error {
	if len(args) > 1 {
		return usageError{errors.New("verify-shape takes at most one VERSION")}
	}
	versions := runningClaudeVersions()
	if len(args) == 1 {
		versions = []string{args[0]}
	}
	if len(versions) == 0 {
		fmt.Fprintln(a.stdout, "verify-shape: no running Claude Code found; nothing to check (inconclusive)")
		return nil
	}
	stateDir, _, _ := statePaths(a.logDir)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	home, _ := os.UserHomeDir()
	evPath, _ := a.paths()
	rd := resources.New()
	now := time.Now()
	failed := false
	for _, v := range versions {
		res, err := shapecheck.Run(shapecheck.Config{
			Version: v, StateDir: stateDir,
			SettingsPaths: shapecheck.DefaultSettingsPaths(home, nil),
			Children:      func() []shapecheck.Child { return liveChildren(rd, v) },
			Calls: func(from, to time.Time) ([]transcript.Call, error) {
				c, _, err := transcript.Scan(transcript.Config{WindowStart: from})
				return c, err
			},
			Events: eventlog.NewWriter(evPath, int64(cfg.MaxLogMB*1024*1024)),
		}, now)
		fmt.Fprintf(a.stdout, "claude %s: %s: %s (children=%d confirmed=%d with_shape=%d hook_with_shape=%d mcp_with_shape=%d)\n",
			v, res.Verdict, res.Reason, res.Children, res.Confirmed, res.ConfirmedShape, res.HookWithShape, res.MCPWithShape)
		if err != nil {
			fmt.Fprintf(a.stderr, "netwatch: verify-shape %s: %v\n", v, err)
		}
		if res.Verdict == shapecheck.Fail {
			failed = true
		}
	}
	if failed {
		return errors.New("verify-shape: at least one version failed")
	}
	return nil
}

// liveChildren lists the children of running Claude Code processes of
// version v, with the observed spawn shape. argv stays in memory only for
// the check.
func liveChildren(rd resources.Full, v string) []shapecheck.Child {
	ps, err := rd.Procs()
	if err != nil {
		return nil
	}
	claude := map[int]bool{}
	for _, p := range ps {
		if ver, ok := attrib.ClaudeFromExe(p.Exe); ok && ver == v {
			claude[p.PID] = true
		}
	}
	var out []shapecheck.Child
	for _, p := range ps {
		if !claude[p.PPID] {
			continue
		}
		out = append(out, shapecheck.Child{PID: p.PID, Start: p.Start, Argv: rd.Args(p.PID),
			Shape: shapecheck.Shape{Setsid: p.SID == p.PID && p.PGID == p.PID, NoTTY: !p.HasTTY}})
	}
	return out
}

// cmdResume handles resume PGID|--all [--force] and the rollback gate
// resume --all --check [--force].
func (a *app) cmdResume(args []string) error {
	fs := a.flags("resume")
	all := fs.Bool("all", false, "resume every group netwatch paused")
	check := fs.Bool("check", false, "rollback gate: refuse while live paused groups remain (needs --all)")
	force := fs.Bool("force", false, "with --check: proceed anyway and list the stopped pids left behind")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return usageError{err}
	}
	pgid, err := validateResumeArgs(*all, *check, *force, fs.Args())
	if err != nil {
		return usageError{err}
	}
	_, stateFile, _ := statePaths(a.logDir)
	store := &guard.FileStore{Path: stateFile}
	view, sig := resumeDeps()
	if *check {
		rep, err := guard.RollbackGate(store, view, *force)
		if err != nil {
			if errors.Is(err, guard.ErrPausedRemain) {
				fmt.Fprintf(a.stdout, "live paused groups remain: %v\n", rep.Live)
			}
			return err
		}
		if len(rep.Live) == 0 {
			fmt.Fprintln(a.stdout, "no live paused groups: safe to swap the binary")
			return nil
		}
		fmt.Fprintf(a.stdout, "forced: leaving paused groups %v; stopped pids left behind: %v\n", rep.Live, rep.StoppedPIDs)
		return nil
	}
	req, unlock, err := resumeRequests(a.logDir)
	if err != nil {
		return err
	}
	defer unlock()
	rep, err := guard.ManualResumeLive(store, view, sig, time.Now(), pgid, *all, req)
	if req != nil && err == nil && len(rep.Resumed) > 0 {
		fmt.Fprintln(a.stdout, "a running netwatch holds these records; it drops them on its next poll and will not pause these groups again until the danger episode ends")
	}
	if len(rep.Pruned) > 0 {
		fmt.Fprintf(a.stdout, "pruned dead or reused groups: %v\n", rep.Pruned)
	}
	for _, s := range rep.Skipped {
		fmt.Fprintln(a.stderr, "netwatch: resume:", s)
	}
	if err != nil {
		return err
	}
	if len(rep.Resumed) == 0 {
		fmt.Fprintln(a.stdout, "nothing to resume")
		return nil
	}
	strs := make([]string, len(rep.Resumed))
	for i, p := range rep.Resumed {
		strs[i] = strconv.Itoa(p)
	}
	fmt.Fprintf(a.stdout, "resumed groups: %s\n", strings.Join(strs, " "))
	return nil
}

// validateResumeArgs checks the combination of flags and the optional PGID.
func validateResumeArgs(all, check, force bool, rest []string) (int, error) {
	if check && !all {
		return 0, errors.New("--check needs --all")
	}
	if force && !check {
		return 0, errors.New("--force only applies to --check")
	}
	if all {
		if len(rest) > 0 {
			return 0, errors.New("--all takes no PGID")
		}
		return 0, nil
	}
	if len(rest) != 1 {
		return 0, errors.New("resume needs PGID or --all")
	}
	n, err := strconv.Atoi(rest[0])
	if err != nil || n <= 1 {
		return 0, fmt.Errorf("bad PGID %q (want a number above 1)", rest[0])
	}
	return n, nil
}

// resumeAllForUninstall resumes every group netwatch paused. uninstall
// calls it before it removes the service. A missing state file means
// nothing was ever paused and is not an error; an unusable one is, so the
// caller can say why it could not resume.
func resumeAllForUninstall(logDir string) error {
	_, stateFile, _ := statePaths(logDir)
	view, sig := resumeDeps()
	req, unlock, err := resumeRequests(logDir)
	if err != nil {
		return err
	}
	defer unlock()
	_, err = guard.ManualResumeLive(&guard.FileStore{Path: stateFile}, view, sig, time.Now(), 0, true, req)
	if errors.Is(err, guard.ErrMissing) {
		return nil
	}
	return err
}

// loadConfigOpts is loadConfig with the test-daemon switch. A normal
// command never honours the test-only keys.
func (a *app) loadConfigOpts(testDaemon bool) *config.Config {
	cfg, warnings, err := config.LoadOpts(a.configPath, config.Options{TestDaemon: testDaemon})
	for _, w := range warnings {
		fmt.Fprintln(a.stderr, "netwatch:", w)
	}
	if err != nil {
		fmt.Fprintf(a.stderr, "netwatch: %v (%s); using defaults\n", err, a.configPath)
	}
	return &cfg
}

// errLockHeld means another netwatch holds a log directory's run lock.
var errLockHeld = errors.New("another netwatch is already running")

// resumeRequests decides how a manual resume reaches the guard state.
// With the run lock free no daemon runs: the CLI holds the lock (so none
// can start meanwhile), clears requests a stopped daemon never took, and
// updates the state file itself. With the lock held, the daemon owns the
// file and the CLI files a request per group for it (code-inspection F1:
// two writers lost each other's records). Any other lock error fails.
func resumeRequests(logDir string) (guard.ResumeRequests, func(), error) {
	stateDir, _, _ := statePaths(logDir)
	unlock, err := lockRun(filepath.Join(logDir, "run.lock"))
	switch {
	case err == nil:
		_ = guard.DirRequests{Dir: stateDir}.Clear()
		return nil, unlock, nil
	case errors.Is(err, errLockHeld):
		return guard.DirRequests{Dir: stateDir}, func() {}, nil
	}
	return nil, nil, fmt.Errorf("resume: cannot check for a running daemon: %w", err)
}
