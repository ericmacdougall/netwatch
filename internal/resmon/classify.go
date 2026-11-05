package resmon

import (
	"sort"
	"strings"
	"time"

	"github.com/ericmacdougall/netwatch/internal/attrib"
	"github.com/ericmacdougall/netwatch/internal/budget"
	"github.com/ericmacdougall/netwatch/internal/eligibility"
	"github.com/ericmacdougall/netwatch/internal/resources"
	"github.com/ericmacdougall/netwatch/internal/sampler"
	"github.com/ericmacdougall/netwatch/internal/shapecheck"
	"github.com/ericmacdougall/netwatch/internal/watcher"
)

// Elig is the production Classifier: internal/eligibility plus the kill
// allowlist and agent labels.
type Elig struct {
	R           resources.Full
	SelfPID     int
	UID         int
	NeverSignal []string // nil: eligibility.DefaultNeverSignal
	// Versions are the Claude Code versions configured as kill-eligible
	// (guard_claude_versions). A version the shape check verified and
	// wrote to AllowlistDir is eligible too.
	Versions     []string
	AllowlistDir string
	Labeler      *attrib.Labeler // optional; labels are informational
	// TestJobPGID is the test daemon's spawned job group (0: none).
	TestJobPGID int
	// Home shortens recorded working directories to "~" (optional).
	Home string

	resolver *attrib.Resolver
	labels   map[labelKey]groupLabel
}

// ClaudeOwner is the owner_app of Claude Code and everything under it.
const ClaudeOwner = "Claude Code"

// groupLabel is a group's agent attribution, cached per group.
type groupLabel struct {
	label   attrib.Label
	session string
	tries   int // scans that looked for the session
}

// sessionTries bounds how many scans look for a group's session before
// "unknown" is cached (a job made only of macOS system binaries never
// shows one; its first child may appear a scan or two late).
const sessionTries = 3

type labelKey struct {
	pgid  int
	start time.Time
}

// maxLabels bounds the label cache; it is cleared when full.
const maxLabels = 1024

// Classify implements Classifier.
func (e *Elig) Classify(scan []resources.Proc, recs []watcher.Record, budgets map[int]budget.Declared) Classification {
	if e.resolver == nil {
		e.resolver = attrib.NewResolver(4096)
	}
	in := eligibility.Input{
		Procs: scan, Records: recs, Env: e.R.Env, Args: e.R.Args,
		NeverSignal: e.NeverSignal, Allowlist: e.allowlist(scan),
		Budgets: budgetList(budgets), SelfPID: e.SelfPID, UID: e.UID, Resolver: e.resolver,
		TestJobPGID: e.TestJobPGID,
	}
	out := eligibility.Classify(in)
	labels := e.label(out)

	var claude []resources.Proc
	for _, p := range scan {
		if _, ok := attrib.ClaudeFromExe(p.Exe); ok && p.UID == e.UID {
			claude = append(claude, p)
		}
	}
	return Classification{Groups: out.Groups, OwnerOf: out.OwnerOf, Excluded: out.Excluded, Claude: claude,
		Annotate: e.annotator(scan, labels), Who: e.whoFunc(scan, labels)}
}

// allowlist is the configured versions plus every running version the
// shape check has verified. The file is read once per version per scan.
func (e *Elig) allowlist(scan []resources.Proc) []string {
	set := map[string]bool{}
	for _, v := range e.Versions {
		set[v] = true
	}
	if e.AllowlistDir != "" {
		seen := map[string]bool{}
		for _, p := range scan {
			v, ok := attrib.ClaudeFromExe(p.Exe)
			if !ok || seen[v] {
				continue
			}
			seen[v] = true
			if shapecheck.Allowed(e.AllowlistDir, v) {
				set[v] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// label fills each group's Agent from the hook WAL, once per group: the
// session id comes from the leader's own environment (tool shells carry
// it; Claude itself does not). It returns the labels by pgid.
func (e *Elig) label(out eligibility.Output) map[int]groupLabel {
	if e.Labeler == nil {
		return nil
	}
	if e.labels == nil || len(e.labels) > maxLabels {
		e.labels = map[labelKey]groupLabel{}
	}
	byPGID := make(map[int]groupLabel, len(out.Groups))
	for i := range out.Groups {
		g := &out.Groups[i]
		k := labelKey{g.PGID, g.LeaderStart}
		gl, ok := e.labels[k]
		if !ok || (gl.session == "" && gl.tries < sessionTries) {
			gl.session = e.groupSession(g.PGID)
			if !sessionOK(gl.session) {
				gl.session = ""
			}
			gl.label = e.Labeler.Label(gl.session, g.LeaderStart)
			gl.tries++
			e.labels[k] = gl
		}
		if g.Agent == "" {
			g.Agent = gl.label.Agent
		}
		byPGID[g.PGID] = gl
	}
	return byPGID
}

// maxEnvMembers bounds the environment reads for one group's session.
const maxEnvMembers = 8

// groupSession reads the session id from the group leader's environment,
// then from other members. macOS hides the environment of Apple platform
// binaries (/bin/zsh, /bin/bash, /bin/sleep) from other processes, so a
// tool shell leader alone usually yields nothing there.
func (e *Elig) groupSession(pgid int) string {
	const key = "CLAUDE_CODE_SESSION_ID"
	if v := e.R.Env(pgid, key)[key]; v != "" {
		return v
	}
	members, err := e.R.GroupMembers(pgid)
	if err != nil {
		return ""
	}
	n := 0
	for _, pid := range members {
		if pid == pgid {
			continue
		}
		if n++; n > maxEnvMembers {
			break
		}
		if v := e.R.Env(pid, key)[key]; v != "" {
			return v
		}
	}
	return ""
}

// sessionOK accepts only an id-shaped session value for the record.
func sessionOK(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '-') {
			return false
		}
	}
	return true
}

// whoFunc gives a process's owner app and its group's agent label, for
// alert messages. The pid table is built on first use (alerts are rare).
func (e *Elig) whoFunc(scan []resources.Proc, labels map[int]groupLabel) func(resources.Proc) (string, string) {
	res := e.resolver
	var tbl map[int]resources.Proc
	return func(p resources.Proc) (string, string) {
		if tbl == nil {
			tbl = make(map[int]resources.Proc, len(scan))
			for _, q := range scan {
				tbl[q.PID] = q
			}
		}
		in := res.Classify(p, tbl)
		app := in.Owner
		if in.ClaudePID != 0 {
			app = ClaudeOwner
		}
		return app, labels[p.PGID].label.Agent
	}
}

// annotator fills sample rows from this scan: owner app and agent root
// from the resolver, session and agent label from the group's cached
// label, and cwd relative to the agent root's cwd (or with the home
// directory shortened to ~).
func (e *Elig) annotator(scan []resources.Proc, labels map[int]groupLabel) func([]sampler.Row) {
	res, rd, home := e.resolver, e.R, e.Home
	return func(rows []sampler.Row) {
		var tbl map[int]resources.Proc
		rootCwd := map[int]string{}
		for i := range rows {
			r := &rows[i]
			if tbl == nil {
				tbl = make(map[int]resources.Proc, len(scan))
				for _, p := range scan {
					tbl[p.PID] = p
				}
			}
			p, ok := tbl[r.PID]
			if !ok {
				continue
			}
			in := res.Classify(p, tbl)
			r.OwnerApp, r.AgentRoot = in.Owner, in.ClaudePID
			if in.ClaudePID != 0 {
				r.OwnerApp = ClaudeOwner // not the terminal Claude runs in
			}
			if gl, ok := labels[r.PGID]; ok {
				r.Session = gl.session
				if r.Agent == "" {
					r.Agent = gl.label.Agent
				}
				if r.Agent == gl.label.Agent {
					r.Confidence = gl.label.Level()
				}
			}
			root := ""
			if in.ClaudePID != 0 && in.ClaudePID != r.PID {
				c, seen := rootCwd[in.ClaudePID]
				if !seen && rd != nil {
					c = rd.Cwd(in.ClaudePID)
					rootCwd[in.ClaudePID] = c
				}
				root = c
			}
			r.Cwd = relCwd(r.Cwd, root, home)
		}
	}
}

// relCwd shows cwd relative to root ("." or "./sub") when it lies under
// it, else with home shortened to "~".
func relCwd(cwd, root, home string) string {
	if cwd == "" {
		return ""
	}
	if root != "" && root != "/" {
		if cwd == root {
			return "."
		}
		if strings.HasPrefix(cwd, root+"/") {
			return "./" + cwd[len(root)+1:]
		}
	}
	if home != "" && home != "/" {
		if cwd == home {
			return "~"
		}
		if strings.HasPrefix(cwd, home+"/") {
			return "~/" + cwd[len(home)+1:]
		}
	}
	return cwd
}

func budgetList(m map[int]budget.Declared) []budget.Declared {
	out := make([]budget.Declared, 0, len(m))
	for _, d := range m {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PGID < out[j].PGID })
	return out
}
