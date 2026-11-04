package procscan

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ericmacdougall/netwatch/internal/config"
)

var t0 = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func testConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := config.Default()
	cfg.OrphanMinAgeMin = 30
	if w := cfg.Compile(); len(w) != 0 {
		t.Fatal(w)
	}
	return &cfg
}

func proc(pid, ppid int, age time.Duration, cmd string) Process {
	return Process{PID: pid, PPID: ppid, Own: true, Age: age, Start: t0.Add(-age), Cmd: cmd}
}

func pids(ps []Process) []int {
	var out []int
	for _, p := range ps {
		out = append(out, p.PID)
	}
	return out
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// A macOS-like table: a terminal-owned node, an orphaned node, a young
// orphan, the normal Chrome app, an orphaned headless Chrome, an unwatched
// daemon and another user's orphan.
func darwinTable() []Process {
	other := proc(60, 1, 5*time.Hour, "/usr/local/bin/node /srv/other.js")
	other.Own = false
	return []Process{
		proc(1, 0, 9*time.Hour, "/sbin/launchd"),
		proc(10, 1, 9*time.Hour, "/usr/libexec/logd"),
		proc(20, 1, 8*time.Hour, "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal"),
		proc(21, 20, 8*time.Hour, "-zsh"),
		proc(22, 21, 2*time.Hour, "node /work/app/server.js"),
		proc(30, 1, 3*time.Hour, "node /work/old/dev-server.js"),
		proc(31, 1, 5*time.Minute, "node /work/just-started.js"),
		proc(40, 1, 6*time.Hour, "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
		proc(41, 1, 4*time.Hour, "/tmp/pw/chrome-headless-shell --headless --remote-debugging-port=0"),
		proc(50, 1, 7*time.Hour, "/usr/sbin/cupsd -l"),
		other,
	}
}

func TestOrphansDarwin(t *testing.T) {
	cfg := testConfig(t)
	got := pids(Orphans(cfg, darwinTable(), InitParent, 999))
	if want := []int{30, 41}; !equalInts(got, want) {
		t.Fatalf("orphans = %v, want %v", got, want)
	}
}

func TestOrphansExcludesSelfAndHonoursMinAgeZero(t *testing.T) {
	cfg := testConfig(t)
	cfg.OrphanMinAgeMin = 0
	got := pids(Orphans(cfg, darwinTable(), InitParent, 30))
	if want := []int{31, 41}; !equalInts(got, want) {
		t.Fatalf("orphans = %v, want %v", got, want)
	}
}

func TestOrphansLinuxSubreaper(t *testing.T) {
	cfg := testConfig(t)
	table := []Process{
		proc(1, 0, 9*time.Hour, "/sbin/init"),
		{PID: 900, PPID: 1, Own: true, Age: 9 * time.Hour, Name: "systemd", Cmd: "/usr/lib/systemd/systemd --user"},
		proc(901, 900, 2*time.Hour, "/usr/bin/node /home/u/x/vite.js"),
		proc(902, 905, 2*time.Hour, "/usr/bin/node /home/u/y.js"),
		{PID: 905, PPID: 900, Own: true, Age: 3 * time.Hour, Name: "bash", Cmd: "bash"},
		proc(903, 1, 2*time.Hour, "/usr/bin/Xvfb :99"),
	}
	got := pids(Orphans(cfg, table, InitOrSubreaper("systemd"), 1))
	if want := []int{901, 903}; !equalInts(got, want) {
		t.Fatalf("orphans = %v, want %v", got, want)
	}
}

func TestMissingParentWindows(t *testing.T) {
	cfg := testConfig(t)
	child := proc(100, 200, 2*time.Hour, "C:/nvm/node -e x")
	reused := proc(300, 400, 2*time.Hour, "C:/nvm/node b.js")
	alive := proc(500, 600, 2*time.Hour, "C:/nvm/node c.js")
	unknownStart := proc(700, 800, 2*time.Hour, "C:/nvm/node d.js")
	table := []Process{
		child, // parent 200 is gone
		reused,
		proc(400, 4, 10*time.Minute, "C:/Windows/notepad"), // started after 300: PID reused
		alive,
		proc(600, 4, 5*time.Hour, "C:/Windows/explorer"),
		unknownStart,
		{PID: 800, PPID: 4, Own: false, Cmd: "C:/Windows/System32/svchost"}, // start unknown
		proc(900, 0, 2*time.Hour, "C:/nvm/node system-child.js"),
	}
	got := pids(Orphans(cfg, table, MissingParent, 1))
	if want := []int{100, 300}; !equalInts(got, want) {
		t.Fatalf("orphans = %v, want %v", got, want)
	}
}

func TestRunawayCPUNeedsConsecutiveScansAndReportsOnce(t *testing.T) {
	cfg := testConfig(t)
	cfg.RunawayScans = 3
	r := NewRunawayTracker()
	hot := proc(10, 1, time.Hour, "node spin.js")
	hot.CPU = 99
	scan := func(p Process) []Runaway { return r.Scan(cfg, []Process{p}, 1) }
	for i := 0; i < 2; i++ {
		if got := scan(hot); len(got) != 0 {
			t.Fatalf("scan %d flagged too early: %v", i, got)
		}
	}
	got := scan(hot)
	if len(got) != 1 || got[0].Reason != "cpu" || got[0].PID != 10 {
		t.Fatalf("third hot scan should flag cpu, got %v", got)
	}
	if got := scan(hot); len(got) != 0 {
		t.Fatalf("should not re-report while still hot: %v", got)
	}
	cool := hot
	cool.CPU = 1
	scan(cool)
	scan(hot)
	scan(hot)
	if got := scan(hot); len(got) != 1 {
		t.Fatalf("should re-report after cooling down, got %v", got)
	}
}

func TestRunawayHotStreakBrokenResets(t *testing.T) {
	cfg := testConfig(t)
	r := NewRunawayTracker()
	p := proc(10, 1, time.Hour, "node spin.js")
	for i, cpu := range []float64{90, 90, 10, 90, 90} {
		p.CPU = cpu
		if got := r.Scan(cfg, []Process{p}, 1); len(got) != 0 {
			t.Fatalf("scan %d: broken streak must not flag: %v", i, got)
		}
	}
}

func TestRunawayRSSAndUnwatchedAndPIDReuse(t *testing.T) {
	cfg := testConfig(t)
	cfg.RunawayRSSMB = 1000
	r := NewRunawayTracker()
	big := proc(10, 1, time.Hour, "node big.js")
	big.RSSMB = 5000
	unwatched := proc(11, 1, time.Hour, "/usr/sbin/bigd")
	unwatched.RSSMB = 9000
	unwatched.CPU = 100
	got := r.Scan(cfg, []Process{big, unwatched}, 1)
	if len(got) != 1 || got[0].PID != 10 || got[0].Reason != "rss" {
		t.Fatalf("want rss runaway for pid 10 only, got %v", got)
	}
	if got := r.Scan(cfg, []Process{big}, 1); len(got) != 0 {
		t.Fatalf("rss reported twice: %v", got)
	}
	reused := big
	reused.Start = big.Start.Add(time.Hour) // same PID, new process
	if got := r.Scan(cfg, []Process{reused}, 1); len(got) != 1 {
		t.Fatalf("a new process on a reused PID should be reported, got %v", got)
	}
}

func TestVerifyForKill(t *testing.T) {
	cfg := testConfig(t)
	table := darwinTable()
	listed := Orphans(cfg, table, InitParent, 999)[0] // pid 30
	if err := VerifyForKill(cfg, listed, table, InitParent, 999); err != nil {
		t.Fatalf("unchanged orphan should verify: %v", err)
	}

	reused := darwinTable()
	for i := range reused {
		if reused[i].PID == 30 {
			reused[i].Start = reused[i].Start.Add(10 * time.Minute)
		}
	}
	if err := VerifyForKill(cfg, listed, reused, InitParent, 999); !errors.Is(err, ErrChanged) {
		t.Fatalf("PID reuse must be refused, got %v", err)
	}

	changedCmd := darwinTable()
	for i := range changedCmd {
		if changedCmd[i].PID == 30 {
			changedCmd[i].Cmd = "node something-else.js"
		}
	}
	if err := VerifyForKill(cfg, listed, changedCmd, InitParent, 999); !errors.Is(err, ErrChanged) {
		t.Fatalf("changed command must be refused, got %v", err)
	}

	adopted := darwinTable()
	for i := range adopted {
		if adopted[i].PID == 30 {
			adopted[i].PPID = 21
		}
	}
	if err := VerifyForKill(cfg, listed, adopted, InitParent, 999); err == nil {
		t.Fatal("a process that is no longer orphaned must be refused")
	}

	var gone []Process
	for _, p := range table {
		if p.PID != 30 {
			gone = append(gone, p)
		}
	}
	if err := VerifyForKill(cfg, listed, gone, InitParent, 999); err == nil || !strings.Contains(err.Error(), "exited") {
		t.Fatalf("exited process should be reported, got %v", err)
	}

	for _, pid := range []int{0, 1, 999} {
		bad := listed
		bad.PID = pid
		if err := VerifyForKill(cfg, bad, table, InitParent, 999); err == nil {
			t.Fatalf("pid %d must be refused", pid)
		}
	}

	noStart := listed
	noStart.Start = time.Time{}
	if err := VerifyForKill(cfg, noStart, table, InitParent, 999); err == nil {
		t.Fatal("unknown start time must be refused")
	}
}

func TestParseEtime(t *testing.T) {
	cases := map[string]time.Duration{
		"00:05":        5 * time.Second,
		"12:34":        12*time.Minute + 34*time.Second,
		"01:02:03":     time.Hour + 2*time.Minute + 3*time.Second,
		"3-04:05:06":   3*24*time.Hour + 4*time.Hour + 5*time.Minute + 6*time.Second,
		" 10-00:00:00": 10 * 24 * time.Hour,
	}
	for in, want := range cases {
		got, err := ParseEtime(in)
		if err != nil || got != want {
			t.Errorf("ParseEtime(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "5", "a:b", "1-2", "-1:00", "00:61", "1:2:3:4", "x-01:00"} {
		if _, err := ParseEtime(bad); err == nil {
			t.Errorf("ParseEtime(%q) should fail", bad)
		}
	}
}

func TestShortAndBaseName(t *testing.T) {
	if got := Short("héllo world", 5); got != "héllo…" {
		t.Fatalf("Short = %q", got)
	}
	if got := BaseName(Process{Cmd: "/usr/local/bin/node a.js"}); got != "node" {
		t.Fatalf("BaseName = %q", got)
	}
	if got := BaseName(Process{Cmd: `C:\nvm\node.exe a.js`}); got != "node.exe" {
		t.Fatalf("BaseName = %q", got)
	}
}

func TestRunawaySkipsOtherUsers(t *testing.T) {
	cfg := testConfig(t)
	r := NewRunawayTracker()
	p := proc(10, 1, time.Hour, "node big.js")
	p.RSSMB = cfg.RunawayRSSMB + 1
	p.Own = false
	if got := r.Scan(cfg, []Process{p}, 1); len(got) != 0 {
		t.Fatalf("another user's process was flagged: %v", got)
	}
	p.Own = true
	if got := r.Scan(cfg, []Process{p}, 1); len(got) != 1 {
		t.Fatalf("own process over the RSS ceiling not flagged: %v", got)
	}
}
