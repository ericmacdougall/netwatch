// Package eligibility is the safety boundary: it decides which process
// groups may ever be signalled, and at what tier, from a full scan, the
// watcher's child records and per-candidate environment reads. Everything
// it does not positively identify is ineligible (alert only).
//
// The rules follow the guard spec's "Eligibility" and "Exclusions"
// sections and AC-2.
package eligibility

import (
	"path"
	"sort"
	"strings"
	"time"

	"github.com/ericmacdougall/netwatch/internal/attrib"
	"github.com/ericmacdougall/netwatch/internal/budget"
	"github.com/ericmacdougall/netwatch/internal/guard"
	"github.com/ericmacdougall/netwatch/internal/redact"
	"github.com/ericmacdougall/netwatch/internal/resources"
	"github.com/ericmacdougall/netwatch/internal/tracker"
	"github.com/ericmacdougall/netwatch/internal/watcher"
)

// DefaultNeverSignal are basename globs matched against the resolved
// executable path. A process whose exe matches is excluded with its whole
// subtree, whatever group it is in.
var DefaultNeverSignal = []string{
	"qemu*", "limactl", "colima", "vfkit", "docker", "com.docker.*",
	"VirtualBox*", "postgres", "mysqld", "redis-server", "mongod",
}

var shells = map[string]bool{"sh": true, "bash": true, "zsh": true}

// Env keys read for candidates. No other key is ever requested.
const (
	EnvClaudeCode = "CLAUDECODE"
	EnvClaudePID  = "CLAUDE_PID"
)

// Input is one classification pass.
type Input struct {
	Procs   []resources.Proc // the full scan (Exe, UID, PGID, SID, HasTTY filled)
	Records []watcher.Record // Book.Records()
	// Env returns only the requested keys of pid's environment.
	Env func(pid int, keys ...string) map[string]string
	// Args returns argv (optional; used to spot interactive/login shells
	// and to build a redacted command line).
	Args func(pid int) []string
	// NeverSignal adds to DefaultNeverSignal; it never replaces it, so a
	// config entry cannot unprotect a VM, container or database.
	NeverSignal []string
	// Allowlist is the set of Claude versions kill may apply to.
	Allowlist []string
	Budgets   []budget.Declared
	SelfPID   int // netwatch itself; it and its children are excluded
	// TestJobPGID is a test daemon's spawned job group (0: none). It is a
	// child of netwatch (and maybe of a terminal) but never part of an
	// inherited excluded subtree, so the job's footprint is counted. Its
	// own processes still get their own rules (tty, never-signal, uid).
	TestJobPGID int
	UID         int // our uid; other uids are excluded
	// Resolver caches owner-app lookups (optional).
	Resolver *attrib.Resolver
	// Coalition returns a macOS coalition id for pid (optional).
	Coalition func(pid int) string
	// Agent labels a group from its Claude pid and leader start
	// (optional, informational only).
	Agent func(claudePID int, start time.Time) string
}

// Output is the result of Classify.
type Output struct {
	Groups []tracker.GroupInfo
	// Reasons explains each group's tier in words, by pgid. Fallback and
	// unverified reasons say "kill not available".
	Reasons map[int]string
	// Excluded is the tracker's per-member exclusion hook.
	Excluded func(p *resources.Proc, exe string) bool
	// OwnerOf is the aggregate key for processes outside agent groups,
	// for tracker.SetScan.
	OwnerOf func(p resources.Proc) string
	// Rule maps an excluded pid to the rule that excluded it.
	Rule map[int]string
}

type rootRule struct {
	name    string
	subtree bool
}

type classifier struct {
	in     Input
	procs  map[int]*resources.Proc
	tbl    map[int]resources.Proc
	kids   map[int][]int
	never  []string
	rule   map[int]string // pid -> rule, after subtree propagation
	claude map[int]string // claude pid -> version
}

// Classify runs one pass.
func Classify(in Input) Output {
	c := &classifier{in: in, procs: make(map[int]*resources.Proc, len(in.Procs)), tbl: make(map[int]resources.Proc, len(in.Procs)),
		kids: map[int][]int{}, rule: map[int]string{}, claude: map[int]string{}}
	c.never = append(append([]string(nil), DefaultNeverSignal...), in.NeverSignal...)
	for i := range in.Procs {
		p := &in.Procs[i]
		c.procs[p.PID] = p
		c.tbl[p.PID] = *p
		c.kids[p.PPID] = append(c.kids[p.PPID], p.PID)
	}
	c.markExclusions()
	out := Output{Reasons: map[int]string{}, Rule: c.rule}
	c.groups(&out)
	out.Excluded = c.excludedFunc()
	out.OwnerOf = c.ownerFunc()
	return out
}

// neverMatch returns the matching never-signal pattern for an exe path.
func neverMatch(patterns []string, exe string) string {
	if exe == "" {
		return ""
	}
	base := path.Base(exe)
	for _, pat := range patterns {
		if ok, _ := path.Match(pat, base); ok {
			return pat
		}
	}
	// Docker Desktop ships helpers under a .app whose binaries have other names.
	if strings.Contains(exe, "/Docker.app/") {
		return "docker"
	}
	return ""
}

func isShell(exe string) bool { return shells[path.Base(exe)] }

func (c *classifier) markExclusions() {
	roots := map[int]rootRule{}
	add := func(pid int, name string, subtree bool) {
		if _, ok := roots[pid]; !ok {
			roots[pid] = rootRule{name, subtree}
		}
	}
	for _, p := range c.in.Procs {
		if v, ok := attrib.ClaudeFromExe(p.Exe); ok {
			c.claude[p.PID] = v
			add(p.PID, "claude", false)
		}
	}
	for i := range c.in.Procs {
		p := &c.in.Procs[i]
		switch {
		case p.PID == 1:
			add(p.PID, "pid1", false)
		case c.in.SelfPID != 0 && p.PID == c.in.SelfPID:
			add(p.PID, "netwatch", true)
		case p.UID != c.in.UID:
			add(p.PID, "uid", false) // other uids: excluded, aggregated as uid:N
		case p.HasTTY:
			add(p.PID, "tty", true)
		}
		if pat := neverMatch(c.never, p.Exe); pat != "" {
			add(p.PID, "never:"+pat, true)
		}
		switch path.Base(p.Exe) {
		case "tmux", "screen":
			add(p.PID, "tmux", true)
		}
		// A non-shell child of Claude (an MCP server) and its descendants.
		if _, parentIsClaude := c.claude[p.PPID]; parentIsClaude {
			if _, self := c.claude[p.PID]; !self && !isShell(p.Exe) {
				add(p.PID, "mcp", true)
			}
		}
		if isShell(p.Exe) && c.in.Args != nil && p.UID == c.in.UID {
			if a := c.in.Args(p.PID); interactive(a) {
				add(p.PID, "interactive_shell", true)
			}
		}
	}
	// Propagate subtree roots downward.
	for pid, r := range roots {
		if _, ok := c.rule[pid]; !ok {
			c.rule[pid] = r.name
		}
		if !r.subtree {
			continue
		}
		stack := []int{pid}
		seen := map[int]bool{pid: true}
		for len(stack) > 0 {
			cur := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			for _, k := range c.kids[cur] {
				if seen[k] || k == 1 {
					continue
				}
				// A Claude Code process starts a new classification: its
				// tool shells are judged by the Claude rules, not swallowed
				// by a terminal, tmux or shell ancestor's subtree. (Claude
				// started from a terminal has a tty ancestor; without this
				// stop every tool shell would be excluded.) The test job is
				// likewise never part of an inherited subtree.
				if _, isClaude := c.claude[k]; isClaude || c.testJob(k) {
					continue
				}
				seen[k] = true
				if _, ok := c.rule[k]; !ok {
					c.rule[k] = r.name
				}
				stack = append(stack, k)
			}
		}
	}
}

// testJob reports whether pid is in the test daemon's job group, which no
// inherited subtree rule (netwatch, tty, tmux) may swallow.
func (c *classifier) testJob(pid int) bool {
	if c.in.TestJobPGID == 0 {
		return false
	}
	p, ok := c.procs[pid]
	return ok && p.PGID == c.in.TestJobPGID
}

// interactive reports an interactive or login shell: argv[0] with a
// leading '-', or a -i / -l flag.
func interactive(argv []string) bool {
	if len(argv) == 0 {
		return false
	}
	if strings.HasPrefix(argv[0], "-") {
		return true
	}
	for _, a := range argv[1:] {
		if a == "-i" || a == "-l" || a == "--login" || a == "--interactive" {
			return true
		}
		if a == "-c" {
			break // flags after -c belong to the command
		}
	}
	return false
}

func (c *classifier) allowlisted(ver string) bool {
	if ver == "" {
		return false
	}
	for _, v := range c.in.Allowlist {
		if v == ver {
			return true
		}
	}
	return false
}

func (c *classifier) budgetFor(pgid int) *guard.Budget {
	for _, b := range c.in.Budgets {
		if b.PGID == pgid {
			return &guard.Budget{MaxBytes: b.MaxBytes, MaxProcs: b.MaxProcs}
		}
	}
	return nil
}

// members returns the non-excluded scan processes with pgid == sid == pgid
// that started no earlier than notBefore.
func (c *classifier) members(pgid int, notBefore time.Time) []*resources.Proc {
	var out []*resources.Proc
	for i := range c.in.Procs {
		p := &c.in.Procs[i]
		if p.PGID != pgid || p.SID != pgid {
			continue
		}
		if !notBefore.IsZero() && p.Start.Before(notBefore) {
			continue
		}
		if _, ex := c.rule[p.PID]; ex {
			continue
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	return out
}

func (c *classifier) env(pid int) map[string]string {
	if c.in.Env == nil {
		return nil
	}
	return c.in.Env(pid, EnvClaudeCode, EnvClaudePID)
}

// envOK checks the per-group environment: every non-excluded member must
// carry CLAUDECODE=1, and when claudePID is non-zero a matching CLAUDE_PID.
// An unreadable or scrubbed environment fails.
func (c *classifier) envOK(ms []*resources.Proc, claudePID int) bool {
	if len(ms) == 0 {
		return false
	}
	for _, m := range ms {
		e := c.env(m.PID)
		if e[EnvClaudeCode] != "1" {
			return false
		}
		if claudePID != 0 && e[EnvClaudePID] != itoa(claudePID) {
			return false
		}
	}
	return true
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// jobName names a group in events, alerts and notifications: the command
// names of its members, without arguments. A tool shell's command line is
// `zsh -c <the agent's command>` with paths under home, and AC-3 keeps
// both out of notifications. A group of shells only is "<shell> job".
func jobName(ms []*resources.Proc) string {
	var names []string
	seen := map[string]bool{}
	for _, m := range ms {
		n := path.Base(m.Name)
		if m.Exe != "" && isShell(m.Exe) || shells[n] || n == "" || n == "." || seen[n] {
			continue
		}
		seen[n] = true
		if names = append(names, n); len(names) == 3 {
			break
		}
	}
	if len(names) == 0 {
		n := "shell"
		if len(ms) > 0 && ms[0].Name != "" {
			n = path.Base(ms[0].Name)
		}
		return redact.Display(n + " job")
	}
	return redact.Display(strings.Join(names, ", "))
}

func (c *classifier) groups(out *Output) {
	taken := map[int]bool{} // pgids already classified

	recs := make([]watcher.Record, len(c.in.Records))
	copy(recs, c.in.Records)
	sort.Slice(recs, func(i, j int) bool { return recs[i].PID < recs[j].PID })

	for _, r := range recs {
		if taken[r.PID] {
			continue
		}
		switch r.State {
		case watcher.Classified:
			if !isShell(r.Exe) {
				continue // an MCP-like child is excluded, not a tool group
			}
			ms := c.members(r.PID, r.Start)
			if len(ms) == 0 {
				continue
			}
			if leader, ok := c.procs[r.PID]; ok && !leader.Start.Equal(r.Start) {
				continue // pid reused by another process: not this record
			}
			ver := ""
			if cp, ok := c.procs[r.ClaudePID]; ok && cp.Start.Equal(r.ClaudeStart) {
				ver = c.claude[r.ClaudePID]
			}
			g := tracker.GroupInfo{PGID: r.PID, LeaderStart: r.Start, Tier: guard.TierTool,
				ClaudeVer: ver, Allowlisted: c.allowlisted(ver), FromWatcher: true,
				EnvOK: c.envOK(ms, r.ClaudePID), Budget: c.budgetFor(r.PID), Cmd: jobName(ms)}
			if c.in.Agent != nil {
				g.Agent = c.in.Agent(r.ClaudePID, r.Start)
			}
			out.Groups = append(out.Groups, g)
			taken[r.PID] = true
			switch {
			case !g.EnvOK:
				out.Reasons[r.PID] = "tool shell, environment check failed (CLAUDECODE/CLAUDE_PID): pause only, kill not available"
			case !g.Allowlisted:
				out.Reasons[r.PID] = "tool shell, Claude version not allowlisted: pause only, kill not available"
			default:
				out.Reasons[r.PID] = "recorded tool-shell group"
			}
		case watcher.Unverified:
			ms := c.members(r.PID, r.FirstSeen.Add(-watcher.MinRetireAge))
			if len(ms) == 0 || !c.envOK(ms, 0) {
				continue
			}
			out.Groups = append(out.Groups, tracker.GroupInfo{PGID: r.PID, LeaderStart: leaderStart(c, r.PID, ms),
				Tier: guard.TierUnverified, FromWatcher: true, Budget: c.budgetFor(r.PID), Cmd: jobName(ms)})
			taken[r.PID] = true
			out.Reasons[r.PID] = "child exited before it was seen: pause only, kill not available"
		}
		// Pending: never eligible until exec completes.
	}

	// Fallback: CLAUDECODE=1, no tty, every exclusion passes. Env is read
	// only for own-uid, non-excluded, tty-less processes outside the
	// groups above.
	byPG := map[int][]*resources.Proc{}
	for i := range c.in.Procs {
		p := &c.in.Procs[i]
		if p.PID <= 1 || p.PGID <= 1 || p.HasTTY || p.UID != c.in.UID || taken[p.PGID] {
			continue
		}
		if _, ex := c.rule[p.PID]; ex {
			continue
		}
		if c.env(p.PID)[EnvClaudeCode] != "1" {
			continue
		}
		byPG[p.PGID] = append(byPG[p.PGID], p)
	}
	pgids := make([]int, 0, len(byPG))
	for pg := range byPG {
		pgids = append(pgids, pg)
	}
	sort.Ints(pgids)
	for _, pg := range pgids {
		ms := byPG[pg]
		sort.Slice(ms, func(i, j int) bool { return ms[i].PID < ms[j].PID })
		out.Groups = append(out.Groups, tracker.GroupInfo{PGID: pg, LeaderStart: leaderStart(c, pg, ms),
			Tier: guard.TierFallback, Budget: c.budgetFor(pg), Cmd: jobName(ms)})
		out.Reasons[pg] = "CLAUDECODE=1 without a recorded tool shell (setsid job or missed watcher event): pause only, kill not available"
	}
	sort.Slice(out.Groups, func(i, j int) bool { return out.Groups[i].PGID < out.Groups[j].PGID })
}

func leaderStart(c *classifier, pgid int, ms []*resources.Proc) time.Time {
	if l, ok := c.procs[pgid]; ok {
		return l.Start
	}
	best := ms[0].Start
	for _, m := range ms {
		if m.Start.Before(best) {
			best = m.Start
		}
	}
	return best
}

// excludedFunc builds the tracker hook. It answers from the scan's
// classification, and for processes born since the scan from their own
// attributes and their parent's exclusion.
func (c *classifier) excludedFunc() func(p *resources.Proc, exe string) bool {
	known := make(map[int]time.Time, len(c.rule))
	for pid := range c.rule {
		if p, ok := c.procs[pid]; ok {
			known[pid] = p.Start
		}
	}
	rule := c.rule
	never, uid, self, testPGID := c.never, c.in.UID, c.in.SelfPID, c.in.TestJobPGID
	return func(p *resources.Proc, exe string) bool {
		if s, ok := known[p.PID]; ok && s.Equal(p.Start) {
			return true
		}
		if p.PID == 1 || p.PID == self || p.HasTTY || p.UID != uid {
			return true
		}
		if neverMatch(never, exe) != "" || (exe != "" && func() bool { _, ok := attrib.ClaudeFromExe(exe); return ok }()) {
			return true
		}
		switch path.Base(exe) {
		case "tmux", "screen":
			return true
		}
		// A new child of an excluded process is part of its subtree.
		if testPGID != 0 && p.PGID == testPGID {
			return false
		}
		if s, ok := known[p.PPID]; ok {
			if q, ok2 := c.procs[p.PPID]; ok2 && q.Start.Equal(s) {
				switch rule[p.PPID] {
				case "claude", "pid1", "uid":
					return false // these exclude only the process itself
				}
				return true
			}
		}
		return false
	}
}

// ownerFunc builds the aggregate key for ineligible processes: excluded
// subtrees by rule, other uids by uid, then owner app, coalition, exe and
// "other". Pid 1 is never an owner.
func (c *classifier) ownerFunc() func(p resources.Proc) string {
	res := c.in.Resolver
	if res == nil {
		res = attrib.NewResolver(1024)
	}
	return func(p resources.Proc) string {
		if p.PID != 1 && p.UID != c.in.UID {
			return "uid:" + itoa(p.UID)
		}
		if r, ok := c.rule[p.PID]; ok && r != "uid" {
			return "excluded:" + r
		}
		if p.UID != c.in.UID {
			return "uid:" + itoa(p.UID)
		}
		if info := res.Classify(p, c.tbl); info.Owner != "" && info.Owner != "launchd" {
			return info.Owner
		}
		if c.in.Coalition != nil {
			if id := c.in.Coalition(p.PID); id != "" {
				return "coalition:" + id
			}
		}
		if p.Exe != "" {
			return "exe:" + p.Exe
		}
		return "other"
	}
}
