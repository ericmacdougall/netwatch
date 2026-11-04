package eligibility

import (
	"path"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ericmacdougall/netwatch/internal/budget"
	"github.com/ericmacdougall/netwatch/internal/guard"
	"github.com/ericmacdougall/netwatch/internal/resources"
	"github.com/ericmacdougall/netwatch/internal/tracker"
	"github.com/ericmacdougall/netwatch/internal/watcher"
)

const (
	me        = 501
	claudeExe = "/home/user/.local/share/claude/versions/2.1.318"
	claudeVer = "2.1.318"
)

var t0 = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

// world is a fake process table plus per-pid environments.
type world struct {
	procs []resources.Proc
	envs  map[int]map[string]string
	recs  []watcher.Record
	clock int
}

func newWorld() *world {
	w := &world{envs: map[int]map[string]string{}}
	w.add(1, 0, 1, 1, "/sbin/launchd", 0, false)
	w.add(100, 1, 100, 100, claudeExe, me, false) // Claude Code, under launchd
	w.add(50, 1, 50, 50, "/Applications/Cursor.app/Contents/MacOS/Cursor", me, false)
	return w
}

func (w *world) add(pid, ppid, pgid, sid int, exe string, uid int, tty bool) {
	w.clock++
	w.procs = append(w.procs, resources.Proc{PID: pid, PPID: ppid, PGID: pgid, SID: sid, UID: uid, Exe: exe,
		Name: path.Base(exe), HasTTY: tty, FootprintOK: true, Start: t0.Add(time.Duration(w.clock) * time.Second)})
}

func (w *world) proc(pid int) *resources.Proc {
	for i := range w.procs {
		if w.procs[i].PID == pid {
			return &w.procs[i]
		}
	}
	return nil
}

func (w *world) agentEnv(pid, claude int) {
	w.envs[pid] = map[string]string{"CLAUDECODE": "1", "CLAUDE_PID": strconv.Itoa(claude)}
}

// toolShell adds a bash child of Claude that is its own session and group
// leader, with a classified record and a proper environment.
func (w *world) toolShell(pid int) {
	w.add(pid, 100, pid, pid, "/bin/bash", me, false)
	w.agentEnv(pid, 100)
	w.recs = append(w.recs, watcher.Record{PID: pid, Start: w.proc(pid).Start, ClaudePID: 100,
		ClaudeStart: w.proc(100).Start, State: watcher.Classified, Exe: "/bin/bash", FirstSeen: t0})
}

func (w *world) run(allow ...string) Output {
	var reads []string
	out := Classify(Input{Procs: w.procs, Records: w.recs, SelfPID: 9999, UID: me, Allowlist: allow,
		Env: func(pid int, keys ...string) map[string]string {
			for _, k := range keys {
				if k != "CLAUDECODE" && k != "CLAUDE_PID" {
					panic("requested env key " + k)
				}
			}
			reads = append(reads, strconv.Itoa(pid))
			return w.envs[pid]
		}})
	return out
}

func group(o Output, pgid int) *tracker.GroupInfo {
	for i := range o.Groups {
		if o.Groups[i].PGID == pgid {
			return &o.Groups[i]
		}
	}
	return nil
}

func TestToolGroupIsEligibleAndKillable(t *testing.T) {
	w := newWorld()
	w.toolShell(200)
	w.add(201, 200, 200, 200, "/bin/sleep", me, false)
	w.agentEnv(201, 100)
	o := w.run(claudeVer)
	g := group(o, 200)
	if g == nil || g.Tier != guard.TierTool || !g.EnvOK || !g.Allowlisted || g.ClaudeVer != claudeVer || !g.FromWatcher {
		t.Fatalf("%+v", g)
	}
	if g.LeaderStart != w.proc(200).Start {
		t.Fatal("leader start must be the recorded child's start")
	}
}

// `&` and nohup jobs reparent to launchd but stay in the recorded group.
func TestReparentedBackgroundJobStaysEligible(t *testing.T) {
	w := newWorld()
	w.toolShell(200)
	w.procs = w.procs[:len(w.procs)-1] // the shell has exited ...
	w.add(210, 1, 200, 200, "/bin/sleep", me, false)
	w.agentEnv(210, 100) // ... leaving a job reparented to launchd
	w.recs[0].Start = t0.Add(-time.Hour)
	g := group(w.run(claudeVer), 200)
	if g == nil || g.Tier != guard.TierTool || !g.EnvOK {
		t.Fatalf("reparented job lost eligibility: %+v", g)
	}
}

func TestPendingChildNotEligible(t *testing.T) {
	w := newWorld()
	w.add(200, 100, 100, 100, claudeExe, me, false) // forked copy of Claude, pre-exec
	w.agentEnv(200, 100)
	w.recs = []watcher.Record{{PID: 200, Start: w.proc(200).Start, ClaudePID: 100, ClaudeStart: w.proc(100).Start, State: watcher.Pending, FirstSeen: t0}}
	o := w.run(claudeVer)
	if len(o.Groups) != 0 {
		t.Fatalf("pending child produced groups: %+v", o.Groups)
	}
}

func TestSetsidJobLandsInFallbackWithReason(t *testing.T) {
	w := newWorld()
	w.add(300, 1, 300, 300, "/bin/sleep", me, false) // setsid job: no record
	w.agentEnv(300, 100)
	o := w.run(claudeVer)
	g := group(o, 300)
	if g == nil || g.Tier != guard.TierFallback || g.EnvOK || g.Allowlisted {
		t.Fatalf("%+v", g)
	}
	if !strings.Contains(o.Reasons[300], "kill not available") || !strings.Contains(o.Reasons[300], "setsid") {
		t.Fatalf("reason %q", o.Reasons[300])
	}
}

func TestDroppedWatcherEventLandsInFallback(t *testing.T) {
	w := newWorld()
	w.add(200, 100, 200, 200, "/bin/bash", me, false) // a tool shell the watcher never recorded
	w.agentEnv(200, 100)
	g := group(w.run(claudeVer), 200)
	if g == nil || g.Tier != guard.TierFallback {
		t.Fatalf("%+v", g)
	}
}

func TestFallbackNeedsCLAUDECODEAndNoTTY(t *testing.T) {
	w := newWorld()
	w.add(300, 1, 300, 300, "/bin/sleep", me, false) // no env
	w.add(310, 1, 310, 310, "/bin/sleep", me, true)  // tty
	w.agentEnv(310, 100)
	w.add(320, 1, 320, 320, "/bin/sleep", me, false)
	w.envs[320] = map[string]string{"CLAUDECODE": "0"}
	if o := w.run(); len(o.Groups) != 0 {
		t.Fatalf("%+v", o.Groups)
	}
}

func TestMCPChildAndDescendantsExcluded(t *testing.T) {
	w := newWorld()
	w.add(400, 100, 400, 400, "/usr/local/bin/node", me, false) // MCP server
	w.agentEnv(400, 100)
	w.add(401, 400, 400, 400, "/usr/bin/python3", me, false) // its child
	w.agentEnv(401, 100)
	w.add(402, 401, 402, 402, "/bin/sleep", me, false) // grandchild in its own group
	w.agentEnv(402, 100)
	w.recs = []watcher.Record{{PID: 400, Start: w.proc(400).Start, ClaudePID: 100, ClaudeStart: w.proc(100).Start, State: watcher.Classified, Exe: "/usr/local/bin/node", FirstSeen: t0}}
	o := w.run(claudeVer)
	for _, pid := range []int{400, 401, 402} {
		if o.Rule[pid] != "mcp" {
			t.Errorf("pid %d rule %q", pid, o.Rule[pid])
		}
	}
	if len(o.Groups) != 0 {
		t.Fatalf("MCP tree became a group: %+v", o.Groups)
	}
	if o.OwnerOf(*w.proc(402)) != "excluded:mcp" {
		t.Fatalf("aggregate %q", o.OwnerOf(*w.proc(402)))
	}
}

func TestClaudeItselfExcluded(t *testing.T) {
	w := newWorld()
	w.add(110, 100, 110, 110, claudeExe, me, false) // nested claude -p
	w.agentEnv(110, 100)
	o := w.run(claudeVer)
	if o.Rule[100] != "claude" || o.Rule[110] != "claude" || len(o.Groups) != 0 {
		t.Fatalf("%v %+v", o.Rule, o.Groups)
	}
}

func TestExcludedMemberInsideEligibleGroupWithSubtree(t *testing.T) {
	w := newWorld()
	w.toolShell(200)
	w.add(201, 200, 200, 200, "/usr/bin/postgres", me, false)
	w.agentEnv(201, 100)
	w.add(202, 201, 200, 200, "/usr/bin/worker", me, false) // postgres child, same group
	w.agentEnv(202, 100)
	w.add(203, 200, 200, 200, "/bin/sleep", me, false)
	w.agentEnv(203, 100)
	o := w.run(claudeVer)
	if o.Rule[201] != "never:postgres" || o.Rule[202] != "never:postgres" || o.Rule[203] != "" || o.Rule[200] != "" {
		t.Fatalf("%v", o.Rule)
	}
	if g := group(o, 200); g == nil || g.Tier != guard.TierTool || !g.EnvOK {
		t.Fatalf("the rest of the group must stay eligible: %+v", g)
	}
	// The tracker hook agrees, including for a child born after the scan.
	if !o.Excluded(w.proc(202), "/usr/bin/worker") || o.Excluded(w.proc(203), "/bin/sleep") {
		t.Fatal("Excluded hook disagrees with the scan")
	}
	born := &resources.Proc{PID: 900, PPID: 202, PGID: 200, SID: 200, UID: me, Start: t0.Add(time.Hour)}
	if !o.Excluded(born, "/usr/bin/anything") {
		t.Fatal("new child of an excluded process must be excluded")
	}
	// But a new child of Claude itself (rule "claude" is not a subtree rule) is not.
	kid := &resources.Proc{PID: 901, PPID: 100, PGID: 901, SID: 901, UID: me, Start: t0.Add(time.Hour)}
	if o.Excluded(kid, "/bin/bash") {
		t.Fatal("a new tool shell under Claude must not be excluded")
	}
}

func TestEachNeverSignalName(t *testing.T) {
	names := []string{
		"/opt/homebrew/bin/qemu-system-aarch64", "/opt/homebrew/bin/limactl", "/opt/homebrew/bin/colima",
		"/opt/homebrew/bin/vfkit", "/usr/local/bin/docker", "/Applications/Docker.app/Contents/MacOS/com.docker.backend",
		"/Applications/VirtualBox.app/Contents/MacOS/VirtualBoxVM", "/usr/lib/postgresql/16/bin/postgres",
		"/usr/sbin/mysqld", "/usr/bin/redis-server", "/usr/bin/mongod",
	}
	for _, exe := range names {
		w := newWorld()
		w.toolShell(200)
		w.add(201, 200, 200, 200, exe, me, false)
		w.agentEnv(201, 100)
		o := w.run(claudeVer)
		if !strings.HasPrefix(o.Rule[201], "never:") {
			t.Errorf("%s not on the never-signal list (rule %q)", exe, o.Rule[201])
		}
		if !o.Excluded(w.proc(201), exe) {
			t.Errorf("hook does not exclude %s", exe)
		}
	}
	// Near misses are not excluded.
	for _, exe := range []string{"/usr/bin/postgres-client-helper", "/usr/bin/dockerfile-lint", "/bin/sleep", "/usr/bin/redis-cli"} {
		w := newWorld()
		w.toolShell(200)
		w.add(201, 200, 200, 200, exe, me, false)
		w.agentEnv(201, 100)
		if r := w.run(claudeVer).Rule[201]; r != "" {
			t.Errorf("%s wrongly excluded by %q", exe, r)
		}
	}
}

func TestNeverSignalListIsConfigurable(t *testing.T) {
	w := newWorld()
	w.toolShell(200)
	w.add(201, 200, 200, 200, "/usr/bin/myservice", me, false)
	w.agentEnv(201, 100)
	o := Classify(Input{Procs: w.procs, Records: w.recs, UID: me, NeverSignal: []string{"myservice"},
		Env: func(pid int, _ ...string) map[string]string { return w.envs[pid] }})
	if o.Rule[201] != "never:myservice" {
		t.Fatalf("%v", o.Rule)
	}
}

func TestTTYTmuxAndInteractiveShellsExcluded(t *testing.T) {
	w := newWorld()
	w.add(500, 50, 500, 500, "/bin/zsh", me, true) // terminal shell with a tty
	w.add(501, 500, 501, 500, "/bin/sleep", me, true)
	w.add(510, 1, 510, 510, "/opt/homebrew/bin/tmux", me, false)
	w.add(511, 510, 511, 511, "/bin/zsh", me, false)
	w.add(512, 511, 512, 512, "/bin/sleep", me, false)
	for _, p := range []int{500, 501, 511, 512} {
		w.agentEnv(p, 100)
	}
	w.add(520, 100, 520, 520, "/bin/zsh", me, false) // login shell
	w.agentEnv(520, 100)
	o := Classify(Input{Procs: w.procs, UID: me, Env: func(pid int, _ ...string) map[string]string { return w.envs[pid] },
		Args: func(pid int) []string {
			if pid == 520 {
				return []string{"-zsh"}
			}
			return []string{"zsh", "-c", "x"}
		}})
	want := map[int]string{500: "tty", 501: "tty", 510: "tmux", 511: "tmux", 512: "tmux", 520: "interactive_shell"}
	for pid, r := range want {
		if o.Rule[pid] != r {
			t.Errorf("pid %d rule %q, want %q", pid, o.Rule[pid], r)
		}
	}
	if len(o.Groups) != 0 {
		t.Fatalf("excluded processes formed groups: %+v", o.Groups)
	}
}

func TestOtherUIDAndPid1AggregateKeys(t *testing.T) {
	w := newWorld()
	w.add(600, 1, 600, 600, "/usr/sbin/mdnsd", 0, false)
	w.add(601, 1, 601, 601, "/usr/bin/other", 777, false)
	w.add(602, 1, 602, 602, "/Users/user/bin/orphan", me, false) // reparented, own uid
	w.add(603, 1, 603, 603, "", me, false)                       // exe unreadable
	w.add(604, 50, 604, 604, "/Applications/Cursor.app/Contents/Frameworks/Helper", me, false)
	o := w.run()
	keys := map[int]string{600: "uid:0", 601: "uid:777", 1: "excluded:pid1", 602: "exe:/Users/user/bin/orphan", 603: "other", 604: "Cursor"}
	for pid, want := range keys {
		if got := o.OwnerOf(*w.proc(pid)); got != want {
			t.Errorf("pid %d key %q, want %q", pid, got, want)
		}
	}
	for pid := range keys {
		if o.OwnerOf(*w.proc(pid)) == "launchd" {
			t.Errorf("pid 1 became an owner for %d", pid)
		}
	}
	// Coalition sits between owner app and exe.
	o2 := Classify(Input{Procs: w.procs, UID: me, Coalition: func(pid int) string {
		if pid == 602 {
			return "42"
		}
		return ""
	}})
	if got := o2.OwnerOf(*w.proc(602)); got != "coalition:42" {
		t.Fatalf("coalition key %q", got)
	}
}

// A Codex-shaped tree (its own app, node/rust helpers, its own shells) is
// never eligible, and is aggregated by owner app so it can still alert.
func TestCodexShapedTreeNeverEligible(t *testing.T) {
	w := newWorld()
	w.add(700, 1, 700, 700, "/Applications/Codex.app/Contents/MacOS/Codex", me, false)
	w.add(701, 700, 701, 701, "/Applications/Codex.app/Contents/Resources/codex", me, false)
	w.add(702, 701, 702, 702, "/bin/zsh", me, false) // looks like a tool shell
	w.add(703, 702, 702, 702, "/usr/bin/python3", me, false)
	w.add(704, 1, 704, 704, "/bin/sleep", me, false) // reparented orphan from a Codex shell
	for _, p := range []int{701, 702, 703, 704} {
		w.envs[p] = map[string]string{} // no CLAUDECODE
	}
	// Even a forged record for a Codex child gets no tool tier without Claude env.
	w.recs = []watcher.Record{{PID: 702, Start: w.proc(702).Start, ClaudePID: 701, ClaudeStart: w.proc(701).Start, State: watcher.Classified, Exe: "/bin/zsh", FirstSeen: t0}}
	o := w.run(claudeVer)
	for _, g := range o.Groups {
		if g.Tier == guard.TierFallback || (g.Tier == guard.TierTool && g.EnvOK) {
			t.Fatalf("Codex group is killable or fallback-eligible: %+v", g)
		}
	}
	if g := group(o, 702); g != nil && g.Allowlisted {
		t.Fatalf("a record whose parent is not Claude must not be allowlisted: %+v", g)
	}
	if k := o.OwnerOf(*w.proc(703)); k != "Codex" {
		t.Fatalf("aggregate %q", k)
	}
}

func TestScrubbedEnvIsPauseOnly(t *testing.T) {
	w := newWorld()
	w.toolShell(200)
	w.add(201, 200, 200, 200, "/bin/sleep", me, false)
	w.envs[201] = map[string]string{} // env -i
	g := group(w.run(claudeVer), 200)
	if g == nil || g.Tier != guard.TierTool || g.EnvOK {
		t.Fatalf("%+v", g)
	}
	if !strings.Contains(Classify(Input{Procs: w.procs, Records: w.recs, UID: me, Allowlist: []string{claudeVer},
		Env: func(pid int, _ ...string) map[string]string { return w.envs[pid] }}).Reasons[200], "kill not available") {
		t.Fatal("reason must say kill not available")
	}
	// A nil environment reader (unreadable) is the same.
	o := Classify(Input{Procs: w.procs, Records: w.recs, UID: me, Allowlist: []string{claudeVer}})
	if g := group(o, 200); g == nil || g.EnvOK {
		t.Fatalf("%+v", g)
	}
}

func TestClaudePIDMismatchIsPauseOnly(t *testing.T) {
	w := newWorld()
	w.toolShell(200)
	w.agentEnv(200, 4242) // CLAUDE_PID names another Claude
	g := group(w.run(claudeVer), 200)
	if g == nil || g.EnvOK || g.Tier != guard.TierTool {
		t.Fatalf("%+v", g)
	}
	w2 := newWorld()
	w2.toolShell(200)
	w2.envs[200]["CLAUDECODE"] = "true" // not "1"
	if g := group(w2.run(claudeVer), 200); g == nil || g.EnvOK {
		t.Fatalf("%+v", g)
	}
}

func TestVersionAllowlist(t *testing.T) {
	w := newWorld()
	w.toolShell(200)
	if g := group(w.run("2.0.0"), 200); g == nil || g.Allowlisted || g.ClaudeVer != claudeVer {
		t.Fatalf("outside the allowlist: %+v", g)
	}
	if g := group(w.run(), 200); g == nil || g.Allowlisted {
		t.Fatalf("empty allowlist: %+v", g)
	}
	if g := group(w.run("2.0.0", claudeVer), 200); g == nil || !g.Allowlisted {
		t.Fatalf("in the allowlist: %+v", g)
	}
	// Claude gone (or its pid reused): version unknown, never allowlisted.
	w.procs = append(w.procs[:1], w.procs[2:]...)
	for i := range w.procs {
		if w.procs[i].PID == 100 {
			t.Fatal("setup")
		}
	}
	if g := group(w.run(claudeVer), 200); g == nil || g.Allowlisted || g.ClaudeVer != "" {
		t.Fatalf("dead claude: %+v", g)
	}
}

func TestClaudePidReuseNotAllowlisted(t *testing.T) {
	w := newWorld()
	w.toolShell(200)
	w.recs[0].ClaudeStart = w.proc(100).Start.Add(-time.Hour) // recorded Claude is not the live pid 100
	if g := group(w.run(claudeVer), 200); g == nil || g.Allowlisted {
		t.Fatalf("%+v", g)
	}
}

func TestBudgetAttachedByPGID(t *testing.T) {
	w := newWorld()
	w.toolShell(200)
	w.toolShell(210)
	o := Classify(Input{Procs: w.procs, Records: w.recs, UID: me, Allowlist: []string{claudeVer},
		Env:     func(pid int, _ ...string) map[string]string { return w.envs[pid] },
		Budgets: []budget.Declared{{PGID: 210, MaxBytes: 4 << 30, MaxProcs: 8}}})
	if group(o, 200).Budget != nil {
		t.Fatal("budget leaked to another group")
	}
	if b := group(o, 210).Budget; b == nil || b.MaxBytes != 4<<30 || b.MaxProcs != 8 {
		t.Fatalf("%+v", b)
	}
}

func TestUnverifiedTier(t *testing.T) {
	w := newWorld()
	// The child exited before it was seen; its background job lives on.
	w.add(210, 1, 200, 200, "/bin/sleep", me, false)
	w.agentEnv(210, 100)
	w.recs = []watcher.Record{{PID: 200, ClaudePID: 100, ClaudeStart: w.proc(100).Start, State: watcher.Unverified, FirstSeen: t0.Add(10 * time.Second)}}
	o := w.run(claudeVer)
	g := group(o, 200)
	if g == nil || g.Tier != guard.TierUnverified || g.EnvOK || g.Allowlisted {
		t.Fatalf("%+v", g)
	}
	if !strings.Contains(o.Reasons[200], "kill not available") {
		t.Fatalf("reason %q", o.Reasons[200])
	}
	// Without CLAUDECODE it is nothing.
	delete(w.envs, 210)
	if g := group(w.run(claudeVer), 200); g != nil {
		t.Fatalf("%+v", g)
	}
}

// A retired record can never make a later process eligible: pgid == sid ==
// the old pid is not enough without a live record.
func TestRetiredPidNeverMakesLaterProcessEligible(t *testing.T) {
	w := newWorld()
	w.toolShell(200)
	book := watcher.NewBook(&bookSrc{w}, func() time.Time { return t0.Add(time.Hour) })
	book.Track(100, w.proc(100).Start, claudeExe)
	w.procs = w.procs[:len(w.procs)-1] // shell dies; nothing leads its group
	w.procs = append(w.procs, resources.Proc{})
	w.procs = w.procs[:len(w.procs)-1]
	// Re-add a classified record directly via OnFork on a live table.
	w2 := newWorld()
	w2.toolShell(200)
	now := t0.Add(time.Hour)
	b := watcher.NewBook(&bookSrc{w2}, func() time.Time { return now })
	b.Track(100, w2.proc(100).Start, claudeExe)
	b.OnFork(100)
	if len(b.Records()) != 1 {
		t.Fatalf("records %v", b.Records())
	}
	// The shell exits; a fresh scan retires the record.
	w2.procs = w2.procs[:len(w2.procs)-1]
	now = now.Add(30 * time.Second)
	if n := b.Retire(watcher.Scan{At: now, OK: true, Procs: w2.procs}); n != 1 {
		t.Fatalf("retired %d", n)
	}
	// Later a different process appears with pgid == sid == 200.
	w2.add(200, 1, 200, 200, "/bin/bash", me, false)
	w2.agentEnv(200, 100)
	o := Classify(Input{Procs: w2.procs, Records: b.Records(), UID: me, Allowlist: []string{claudeVer},
		Env: func(pid int, _ ...string) map[string]string { return w2.envs[pid] }})
	g := group(o, 200)
	if g != nil && g.Tier == guard.TierTool {
		t.Fatalf("a retired pid made a later process a tool group: %+v", g)
	}
	if g == nil || g.Tier != guard.TierFallback {
		t.Fatalf("expected at most the fallback tier, got %+v", g)
	}
}

type bookSrc struct{ w *world }

func (b *bookSrc) AppendChildren(dst []int, pid int) ([]int, error) {
	for _, p := range b.w.procs {
		if p.PPID == pid {
			dst = append(dst, p.PID)
		}
	}
	return dst, nil
}
func (b *bookSrc) Probe(pid int, p *resources.Proc) error {
	if q := b.w.proc(pid); q != nil {
		*p = *q
		return nil
	}
	return resources.ErrGone
}
func (b *bookSrc) ExePath(pid int) string {
	if q := b.w.proc(pid); q != nil {
		return q.Exe
	}
	return ""
}

func TestPIDReusedByAnotherProcessIsNotTheRecord(t *testing.T) {
	w := newWorld()
	w.toolShell(200)
	w.proc(200).Start = w.proc(200).Start.Add(time.Hour) // a different process now holds pid 200
	if g := group(w.run(claudeVer), 200); g != nil && g.Tier == guard.TierTool {
		t.Fatalf("%+v", g)
	}
}

func TestEnvReadsOnlyRequestedKeysAndOnlyCandidates(t *testing.T) {
	w := newWorld()
	w.toolShell(200)
	w.add(800, 1, 800, 800, "/usr/sbin/mdnsd", 0, false) // other uid: not a candidate
	w.add(801, 50, 801, 801, "/bin/zsh", me, true)       // tty: not a candidate
	asked := map[int]bool{}
	Classify(Input{Procs: w.procs, Records: w.recs, UID: me, Allowlist: []string{claudeVer},
		Env: func(pid int, keys ...string) map[string]string {
			asked[pid] = true
			if len(keys) != 2 || keys[0] != "CLAUDECODE" || keys[1] != "CLAUDE_PID" {
				t.Fatalf("keys %v", keys)
			}
			return w.envs[pid]
		}})
	if asked[800] || asked[801] || asked[1] || asked[100] || !asked[200] {
		t.Fatalf("env read for %v", asked)
	}
}

func TestOutputSortedAndDeterministic(t *testing.T) {
	w := newWorld()
	for _, p := range []int{230, 210, 220} {
		w.toolShell(p)
	}
	o := w.run(claudeVer)
	if len(o.Groups) != 3 || o.Groups[0].PGID != 210 || o.Groups[1].PGID != 220 || o.Groups[2].PGID != 230 {
		t.Fatalf("%+v", o.Groups)
	}
}

func TestPendingRecordNeverGivesAToolOrUnverifiedGroup(t *testing.T) {
	w := newWorld()
	w.add(200, 100, 200, 200, "/bin/bash", me, false) // exec already happened but Settle has not run
	w.agentEnv(200, 100)
	w.recs = []watcher.Record{{PID: 200, Start: w.proc(200).Start, ClaudePID: 100, ClaudeStart: w.proc(100).Start, State: watcher.Pending, FirstSeen: t0}}
	g := group(w.run(claudeVer), 200)
	if g == nil || g.Tier != guard.TierFallback {
		t.Fatalf("a pending record must not be a tool or unverified group: %+v", g)
	}
}

func TestMemberOlderThanRecordedChildIsNotInTheGroup(t *testing.T) {
	w := newWorld()
	w.toolShell(200)
	w.procs = w.procs[:len(w.procs)-1] // the leader is gone
	w.add(210, 1, 200, 200, "/bin/sleep", me, false)
	w.agentEnv(210, 100)
	w.recs[0].Start = w.proc(210).Start.Add(time.Hour) // the record is newer than the survivor
	if g := group(w.run(claudeVer), 200); g != nil && g.Tier == guard.TierTool {
		t.Fatalf("%+v", g)
	}
}

func TestRecordForNonShellIsNotAToolGroup(t *testing.T) {
	w := newWorld()
	w.add(200, 1, 200, 200, "/usr/bin/python3", me, false)
	w.agentEnv(200, 100)
	w.recs = []watcher.Record{{PID: 200, Start: w.proc(200).Start, ClaudePID: 100, ClaudeStart: w.proc(100).Start, State: watcher.Classified, Exe: "/usr/bin/python3", FirstSeen: t0}}
	if g := group(w.run(claudeVer), 200); g != nil && g.Tier == guard.TierTool {
		t.Fatalf("%+v", g)
	}
}
