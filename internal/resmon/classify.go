package resmon

import (
	"sort"
	"time"

	"github.com/ericmacdougall/netwatch/internal/attrib"
	"github.com/ericmacdougall/netwatch/internal/budget"
	"github.com/ericmacdougall/netwatch/internal/eligibility"
	"github.com/ericmacdougall/netwatch/internal/resources"
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

	resolver *attrib.Resolver
	labels   map[labelKey]string
}

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
	e.label(out)

	var claude []resources.Proc
	for _, p := range scan {
		if _, ok := attrib.ClaudeFromExe(p.Exe); ok && p.UID == e.UID {
			claude = append(claude, p)
		}
	}
	return Classification{Groups: out.Groups, OwnerOf: out.OwnerOf, Excluded: out.Excluded, Claude: claude}
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
// it; Claude itself does not).
func (e *Elig) label(out eligibility.Output) {
	if e.Labeler == nil {
		return
	}
	if e.labels == nil || len(e.labels) > maxLabels {
		e.labels = map[labelKey]string{}
	}
	for i := range out.Groups {
		g := &out.Groups[i]
		if g.Agent != "" {
			continue
		}
		k := labelKey{g.PGID, g.LeaderStart}
		a, ok := e.labels[k]
		if !ok {
			env := e.R.Env(g.PGID, "CLAUDE_CODE_SESSION_ID")
			a = e.Labeler.Label(env["CLAUDE_CODE_SESSION_ID"], g.LeaderStart).Agent
			e.labels[k] = a
		}
		g.Agent = a
	}
}

func budgetList(m map[int]budget.Declared) []budget.Declared {
	out := make([]budget.Declared, 0, len(m))
	for _, d := range m {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PGID < out[j].PGID })
	return out
}
