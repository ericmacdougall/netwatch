//go:build !windows

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ericmacdougall/netwatch/internal/config"
	"github.com/ericmacdougall/netwatch/internal/guard"
	"github.com/ericmacdougall/netwatch/internal/guardmode"
)

func newTestApp(t *testing.T) (*app, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	dir := t.TempDir()
	os.Chmod(dir, 0o700)
	var out, errb bytes.Buffer
	return &app{logDir: dir, configPath: filepath.Join(dir, "none.json"), stdout: &out, stderr: &errb}, &out, &errb
}

func TestStatePaths(t *testing.T) {
	sd, sf, ad := statePaths("/var/log/nw")
	if sd != "/var/log/nw/state" || sf != "/var/log/nw/state/guard-state.json" || ad != sd {
		t.Fatalf("%q %q %q", sd, sf, ad)
	}
}

func TestGuardConfigMapsThresholds(t *testing.T) {
	cfg := config.Default()
	cfg.GuardMinShare, cfg.GuardGroupRAMFrac, cfg.GuardHeadroomFrac, cfg.GuardP1HorizonS = 0.1, 0.5, 0.2, 30
	gc := guardConfig(&cfg, guard.ModePause)
	if gc.Mode != guard.ModePause || gc.Danger.MinShare != 0.1 || gc.Danger.GroupRAMFrac != 0.5 ||
		gc.Danger.HeadroomFrac != 0.2 || gc.Danger.P1Horizon != 30*time.Second {
		t.Fatalf("%+v", gc.Danger)
	}
	// Hand-built out-of-bounds values are still clamped.
	bad := config.Default()
	bad.GuardMinShare, bad.GuardP1HorizonS = 7, 1
	gc = guardConfig(&bad, guard.ModeAlert)
	if gc.Danger.MinShare != 1.0 || gc.Danger.P1Horizon != 5*time.Second {
		t.Fatalf("not clamped: %+v", gc.Danger)
	}
}

func TestAlertsConfigMapsThresholds(t *testing.T) {
	cfg := config.Default()
	cfg.AlertProcGB, cfg.AlertGrowthGBPerMin, cfg.AlertSwapGB, cfg.AlertChromeHelpers, cfg.NotifyCooldownS = 4, 1.5, 6, 30, 120
	ac := alertsConfig(&cfg)
	if ac.ProcBytes != 4<<30 || ac.GrowthPerMin != 3<<29 || ac.SwapBytes != 6<<30 || ac.ChromeHelpers != 30 || ac.Cooldown != 2*time.Minute {
		t.Fatalf("%+v", ac)
	}
	d := alertsConfig(ptr(config.Default()))
	if d.ProcBytes != 8<<30 || d.GrowthPerMin != 2<<30 || d.SwapBytes != 10<<30 || d.ChromeHelpers != 60 {
		t.Fatalf("defaults: %+v", d)
	}
}

func ptr[T any](v T) *T { return &v }

func TestEffectiveModeGOOSDefaultsAndPrecedence(t *testing.T) {
	cfg := config.Default()
	dir := filepath.Join(t.TempDir(), "state")
	for goos, want := range map[string]guard.Mode{"darwin": guard.ModePauseKill, "linux": guard.ModeAlert, "windows": guard.ModeOff, "plan9": guard.ModeOff} {
		m, src := effectiveMode(&cfg, dir, goos)
		if m != want || src != srcDefault {
			t.Errorf("%s: %s %s, want %s", goos, m, src, want)
		}
	}
	cfg.GuardMode = "pause"
	if m, src := effectiveMode(&cfg, dir, "darwin"); m != guard.ModePause || src != srcConfig {
		t.Fatalf("config must beat the default: %s %s", m, src)
	}
	cfg.GuardMode = "garbage"
	if m, _ := effectiveMode(&cfg, dir, "linux"); m != guard.ModeAlert {
		t.Fatalf("an invalid configured mode must fall back to the default, got %s", m)
	}
	if err := guardmode.Write(dir, guard.ModeOff, "user"); err != nil {
		t.Fatal(err)
	}
	cfg.GuardMode = "pause"
	if m, src := effectiveMode(&cfg, dir, "darwin"); m != guard.ModeOff || src != srcFile {
		t.Fatalf("the mode file must beat config: %s %s", m, src)
	}
}

func TestStatusLineFormat(t *testing.T) {
	cfg := config.Default()
	cfg.GuardClaudeVersions = []string{"2.1.318"}
	got := statusLine(&cfg, guard.ModePauseKill, srcDefault)
	want := "guard: mode=pause+kill (platform default) min_share=0.25 group_ram_fraction=0.75 headroom_frac=0.08 p1_horizon=15s max_pause=30m0s kill_versions=1"
	if got != want {
		t.Fatalf("status line:\n got %q\nwant %q", got, want)
	}
	if strings.Contains(got, "\n") {
		t.Fatal("must be one line")
	}
}

func TestGuardModeChangeWritesFileEventAndPrintsOptOut(t *testing.T) {
	t.Setenv("CLAUDE_CODE_SESSION_ID", "")
	a, out, _ := newTestApp(t)
	if err := a.cmdGuard([]string{"pause+kill"}); err != nil {
		t.Fatal(err)
	}
	sd, _, _ := statePaths(a.logDir)
	rec, ok := guardmode.ReadRecord(sd)
	if !ok || rec.Mode != "pause+kill" || rec.By != "user" {
		t.Fatalf("%+v %v", rec, ok)
	}
	if !strings.Contains(out.String(), "netwatch guard alert") {
		t.Fatalf("the one-command opt-out must be printed: %q", out.String())
	}
	ev, _ := os.ReadFile(filepath.Join(a.logDir, "events.jsonl"))
	if !strings.Contains(string(ev), "MODE_CHANGE") || !strings.Contains(string(ev), "by user") {
		t.Fatalf("MODE_CHANGE not logged: %s", ev)
	}
	// Inside an agent session the label names the session.
	t.Setenv("CLAUDE_CODE_SESSION_ID", "0a1b2c3d-1111-2222-3333-444455556666")
	if err := a.cmdGuard([]string{"alert"}); err != nil {
		t.Fatal(err)
	}
	rec, _ = guardmode.ReadRecord(sd)
	if rec.Mode != "alert" || rec.By != "agent:0a1b2c3d-1111-2222-3333-444455556666" {
		t.Fatalf("%+v", rec)
	}
	// A hostile session id never reaches the label.
	t.Setenv("CLAUDE_CODE_SESSION_ID", "../../etc; rm")
	if callerLabel() != "user" {
		t.Fatal("a non-UUID session id must be ignored")
	}
}

func TestGuardRejectsBadArguments(t *testing.T) {
	a, _, _ := newTestApp(t)
	for _, args := range [][]string{nil, {"banana"}, {"pause", "extra"}, {"status", "x"}, {"PAUSE"}} {
		err := a.cmdGuard(args)
		var ue usageError
		if err == nil || !errors.As(err, &ue) {
			t.Errorf("%v: want a usage error, got %v", args, err)
		}
	}
	sd, _, _ := statePaths(a.logDir)
	if _, ok := guardmode.Read(sd); ok {
		t.Fatal("a rejected command must not write the mode file")
	}
}

// fakeProcs knows only the processes a test registered; it is both the
// ProcView and the Signaller, so no real process is ever touched.
type fakeProcs struct {
	alive   map[int]time.Time
	signals []struct {
		pid int
		sig syscall.Signal
	}
}

func (f *fakeProcs) Group(int) ([]guard.ProcInfo, error) { return nil, nil }
func (f *fakeProcs) Stopped() ([]guard.ProcInfo, error)  { return nil, nil }
func (f *fakeProcs) Alive(pid int, st time.Time) bool {
	s, ok := f.alive[pid]
	return ok && s.Equal(st)
}
func (f *fakeProcs) Signal(pid int, st time.Time, sig syscall.Signal) error {
	if !f.Alive(pid, st) {
		return guard.ErrStartMismatch
	}
	f.signals = append(f.signals, struct {
		pid int
		sig syscall.Signal
	}{pid, sig})
	return nil
}

var tt0 = time.Date(2026, 11, 4, 16, 0, 0, 0, time.UTC)

func withFake(t *testing.T, f *fakeProcs) {
	old := resumeDeps
	resumeDeps = func() (guard.ProcView, guard.Signaller) { return f, f }
	t.Cleanup(func() { resumeDeps = old })
	oldV := runningClaudeVersions
	runningClaudeVersions = func() []string { return nil }
	t.Cleanup(func() { runningClaudeVersions = oldV })
}

// saveRecorded stores a state with paused groups {pgid: member pids}.
func saveRecorded(t *testing.T, logDir string, groups map[int][]int) {
	t.Helper()
	st := guard.State{Groups: map[string]*guard.Record{}, LastResume: map[string]time.Time{}}
	for pg, pids := range groups {
		r := &guard.Record{PGID: pg, LeaderStart: tt0, Phase: guard.PhasePaused, PausedAt: tt0}
		for _, p := range pids {
			r.Members = append(r.Members, guard.RecMember{PID: p, Start: tt0, Sig: true})
		}
		st.Groups[r.Key()] = r
	}
	_, sf, _ := statePaths(logDir)
	if _, err := (&guard.FileStore{Path: sf}).Save(st); err != nil {
		t.Fatal(err)
	}
}

func TestResumeArgumentValidation(t *testing.T) {
	cases := []struct {
		name             string
		all, check, frce bool
		rest             []string
		pg               int
		ok               bool
	}{
		{"pgid", false, false, false, []string{"4242"}, 4242, true},
		{"all", true, false, false, nil, 0, true},
		{"check all", true, true, false, nil, 0, true},
		{"check all force", true, true, true, nil, 0, true},
		{"nothing", false, false, false, nil, 0, false},
		{"pgid and all", true, false, false, []string{"4242"}, 0, false},
		{"two pgids", false, false, false, []string{"1000", "2000"}, 0, false},
		{"pgid 1", false, false, false, []string{"1"}, 0, false},
		{"pgid 0", false, false, false, []string{"0"}, 0, false},
		{"negative", false, false, false, []string{"-5"}, 0, false},
		{"text", false, false, false, []string{"abc"}, 0, false},
		{"check without all", false, true, false, []string{"4242"}, 0, false},
		{"force without check", true, false, true, nil, 0, false},
	}
	for _, c := range cases {
		pg, err := validateResumeArgs(c.all, c.check, c.frce, c.rest)
		if (err == nil) != c.ok || (c.ok && pg != c.pg) {
			t.Errorf("%s: pg=%d err=%v", c.name, pg, err)
		}
	}
}

func TestResumeCommandResumesRecordedGroupsOnly(t *testing.T) {
	a, out, _ := newTestApp(t)
	f := &fakeProcs{alive: map[int]time.Time{100: tt0, 101: tt0, 200: tt0}}
	withFake(t, f)
	saveRecorded(t, a.logDir, map[int][]int{100: {100, 101}, 200: {200}})

	// A group netwatch did not stop is refused and nothing is signalled.
	err := a.cmdResume([]string{"999"})
	if !errors.Is(err, guard.ErrNotRecorded) || len(f.signals) != 0 {
		t.Fatalf("unrecorded: %v %v", err, f.signals)
	}
	if err := a.cmdResume([]string{"100"}); err != nil {
		t.Fatal(err)
	}
	for _, s := range f.signals {
		if s.sig != syscall.SIGCONT || s.pid == 200 {
			t.Fatalf("only SIGCONT to group 100: %+v", f.signals)
		}
	}
	if len(f.signals) != 2 || !strings.Contains(out.String(), "resumed groups: 100") {
		t.Fatalf("%v %q", f.signals, out.String())
	}
	f.signals = nil
	if err := a.cmdResume([]string{"--all"}); err != nil {
		t.Fatal(err)
	}
	if len(f.signals) != 1 || f.signals[0].pid != 200 {
		t.Fatalf("--all must resume what is left: %+v", f.signals)
	}
	// A usage error is reported as one.
	var ue usageError
	if err := a.cmdResume(nil); !errors.As(err, &ue) {
		t.Fatalf("no args: %v", err)
	}
}

func TestResumeFailsClosedOnUnusableState(t *testing.T) {
	a, _, _ := newTestApp(t)
	f := &fakeProcs{alive: map[int]time.Time{100: tt0}}
	withFake(t, f)
	sd, sf, _ := statePaths(a.logDir)
	if err := a.cmdResume([]string{"--all"}); !errors.Is(err, guard.ErrMissing) {
		t.Fatalf("missing state must refuse: %v", err)
	}
	os.MkdirAll(sd, 0o700)
	os.WriteFile(sf, []byte("{garbage"), 0o600)
	if err := a.cmdResume([]string{"--all"}); !errors.Is(err, guard.ErrCorrupt) {
		t.Fatalf("corrupt state must refuse: %v", err)
	}
	if len(f.signals) != 0 {
		t.Fatalf("no signal on unusable state: %v", f.signals)
	}
}

func TestRollbackGateCheck(t *testing.T) {
	a, out, _ := newTestApp(t)
	f := &fakeProcs{alive: map[int]time.Time{100: tt0, 101: tt0}}
	withFake(t, f)
	saveRecorded(t, a.logDir, map[int][]int{100: {100, 101}})
	err := a.cmdResume([]string{"--all", "--check"})
	if !errors.Is(err, guard.ErrPausedRemain) {
		t.Fatalf("must refuse while live paused groups remain: %v", err)
	}
	if len(f.signals) != 0 {
		t.Fatal("--check must never signal")
	}
	out.Reset()
	if err := a.cmdResume([]string{"--all", "--check", "--force"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "100 101") {
		t.Fatalf("--force must list the stopped pids: %q", out.String())
	}
	// After resume --all the gate passes.
	if err := a.cmdResume([]string{"--all"}); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := a.cmdResume([]string{"--all", "--check"}); err != nil || !strings.Contains(out.String(), "safe to swap") {
		t.Fatalf("gate must pass once nothing is paused: %v %q", err, out.String())
	}
}

func TestResumeAllForUninstall(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0o700)
	f := &fakeProcs{alive: map[int]time.Time{100: tt0, 101: tt0, 200: tt0}}
	withFake(t, f)

	// No state file: nothing was ever paused, so uninstall proceeds.
	if err := resumeAllForUninstall(dir); err != nil || len(f.signals) != 0 {
		t.Fatalf("missing state: %v %v", err, f.signals)
	}
	// Recorded groups are resumed before the service goes.
	saveRecorded(t, dir, map[int][]int{100: {100, 101}, 200: {200}})
	if err := resumeAllForUninstall(dir); err != nil {
		t.Fatal(err)
	}
	got := map[int]bool{}
	for _, s := range f.signals {
		if s.sig != syscall.SIGCONT {
			t.Fatalf("uninstall may only send SIGCONT: %+v", s)
		}
		got[s.pid] = true
	}
	if !got[100] || !got[101] || !got[200] {
		t.Fatalf("every recorded member must be continued: %v", got)
	}
	_, sf, _ := statePaths(dir)
	st, err := (&guard.FileStore{Path: sf}).Load()
	if err != nil || len(st.Groups) != 0 {
		t.Fatalf("the record must be cleared: %v %v", err, st.Groups)
	}
	// A dead or reused pid is pruned, never signalled.
	f2 := &fakeProcs{alive: map[int]time.Time{100: tt0.Add(time.Hour)}} // pid 100 was reused
	withFake(t, f2)
	saveRecorded(t, dir, map[int][]int{100: {100}})
	if err := resumeAllForUninstall(dir); err != nil || len(f2.signals) != 0 {
		t.Fatalf("a reused pid must not be signalled: %v %v", err, f2.signals)
	}
	// A corrupt state is an error (the caller says why), with no signal.
	os.WriteFile(sf, []byte("{x"), 0o600)
	if err := resumeAllForUninstall(dir); err == nil || len(f2.signals) != 0 {
		t.Fatalf("corrupt state must be reported: %v", err)
	}
}

func TestGuardStatusListsPausedGroupsAndKillAvailability(t *testing.T) {
	a, out, _ := newTestApp(t)
	withFake(t, &fakeProcs{})
	runningClaudeVersions = func() []string { return []string{"2.1.318", "9.9.9"} }
	saveRecorded(t, a.logDir, map[int][]int{4242: {4242}})
	sd, _, _ := statePaths(a.logDir)
	os.MkdirAll(sd, 0o700)
	if err := os.WriteFile(a.configPath, []byte(`{"guard_claude_versions":["2.1.318"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := a.cmdGuard([]string{"status"}); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	for _, want := range []string{"guard: mode=", "kill_versions=1", "paused pgid 4242", "claude 2.1.318: kill available", "claude 9.9.9: kill not available: Claude Code 9.9.9 unverified"} {
		if !strings.Contains(s, want) {
			t.Errorf("status output missing %q:\n%s", want, s)
		}
	}
}
