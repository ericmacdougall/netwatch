// Package attrib decides which process is Claude Code, which app owns a
// process, and which agent (main or a subagent) started a tool shell.
//
// Only the first of those ever matters for eligibility, and even then only
// as one gate among several in the guard. The agent label is informational:
// it carries a confidence and never decides what may be signalled.
package attrib

import (
	"path"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ericmacdougall/netwatch/internal/redact"
	"github.com/ericmacdougall/netwatch/internal/resources"
)

var semver = regexp.MustCompile(`^\d+\.\d+\.\d+([-+][0-9A-Za-z.+-]+)?$`)

// ClaudeFromExe reports whether exe is a Claude Code binary and returns its
// version. The exe must be an absolute, clean path with a directory
// sequence the installers create:
//
//	.../claude/versions/<semver>[/...]   (the native installer)
//	.../claude-code/<semver>[/...]       (the copy a desktop app unpacks)
//
// A process name proves nothing: any program can set its comm to "2.1.318"
// (the native binary's own name is its version), so comm is only a hint.
func ClaudeFromExe(exe string) (version string, ok bool) {
	if exe == "" || !path.IsAbs(exe) || path.Clean(exe) != exe {
		return "", false
	}
	seg := strings.Split(exe[1:], "/")
	for i := 0; i < len(seg); i++ {
		if seg[i] == "claude" && i+2 < len(seg) && seg[i+1] == "versions" && semver.MatchString(seg[i+2]) {
			return seg[i+2], true
		}
		if seg[i] == "claude-code" && i+1 < len(seg) && semver.MatchString(seg[i+1]) {
			return seg[i+1], true
		}
	}
	return "", false
}

// CommHint reports whether the process name looks like Claude Code. It is
// useful for choosing which processes to look at first, never for deciding
// that one is Claude.
func CommHint(comm string) bool {
	return comm == "claude" || semver.MatchString(comm)
}

// Info is the identity of one process.
type Info struct {
	PID       int
	Start     time.Time
	Claude    bool   // exe path matches ClaudeFromExe
	Version   string // Claude version when Claude
	Hint      bool   // comm looks like Claude (informational)
	Owner     string // app that owns the process tree
	ClaudePID int    // nearest Claude ancestor (or self), 0 if none
}

type key struct {
	pid   int
	start int64
}

// Resolver classifies processes and caches the answer per (pid, start), so
// a reused pid is never mistaken for the process that had it before.
type Resolver struct {
	mu    sync.Mutex
	cap   int
	order []key // oldest first; small caps make a slice fine
	m     map[key]Info
}

// NewResolver returns a resolver holding at most capacity entries.
func NewResolver(capacity int) *Resolver {
	if capacity < 1 {
		capacity = 1
	}
	return &Resolver{cap: capacity, m: make(map[key]Info, capacity)}
}

// Classify returns the identity of p. tbl maps pid to process for the
// parent walk; it may be partial.
func (r *Resolver) Classify(p resources.Proc, tbl map[int]resources.Proc) Info {
	k := key{p.PID, p.Start.UnixNano()}
	r.mu.Lock()
	if in, ok := r.m[k]; ok {
		r.touch(k)
		r.mu.Unlock()
		return in
	}
	r.mu.Unlock()

	in := Info{PID: p.PID, Start: p.Start, Hint: CommHint(p.Name)}
	in.Version, in.Claude = ClaudeFromExe(p.Exe)
	in.Owner, in.ClaudePID = walk(p, tbl)
	if in.Claude {
		in.ClaudePID = p.PID
	}

	r.mu.Lock()
	r.m[k] = in
	r.order = append(r.order, k)
	for len(r.order) > r.cap {
		delete(r.m, r.order[0])
		r.order = r.order[1:]
	}
	r.mu.Unlock()
	return in
}

// touch moves k to the most recent end. Caller holds mu.
func (r *Resolver) touch(k key) {
	for i, o := range r.order {
		if o == k {
			copy(r.order[i:], r.order[i+1:])
			r.order[len(r.order)-1] = k
			return
		}
	}
}

// Len returns the number of cached entries.
func (r *Resolver) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.m)
}

// maxDepth bounds the parent walk against cycles and absurd chains.
const maxDepth = 64

// walk follows the parent chain from p up to (not including) pid 1. It
// returns the owning app and the nearest Claude ancestor.
func walk(p resources.Proc, tbl map[int]resources.Proc) (owner string, claudePID int) {
	seen := map[int]bool{p.PID: true}
	var top resources.Proc
	cur := p
	for depth := 0; depth < maxDepth; depth++ {
		par, ok := tbl[cur.PPID]
		if !ok || cur.PPID <= 1 || seen[par.PID] {
			break
		}
		seen[par.PID] = true
		if claudePID == 0 {
			if _, isC := ClaudeFromExe(par.Exe); isC {
				claudePID = par.PID
			}
		}
		if app := AppName(par.Exe); app != "" && owner == "" {
			owner = app
		}
		top = par
		cur = par
	}
	if owner == "" && top.PID != 0 {
		owner = baseName(top)
	}
	return owner, claudePID
}

func baseName(p resources.Proc) string {
	if p.Exe != "" {
		return path.Base(p.Exe)
	}
	return p.Name
}

// AppName returns "Foo" for an exe inside Foo.app (the outermost bundle),
// or "".
func AppName(exe string) string {
	for _, s := range strings.Split(exe, "/") {
		if strings.HasSuffix(s, ".app") && len(s) > 4 {
			return strings.TrimSuffix(s, ".app")
		}
	}
	return ""
}

// CommandLine joins argv and redacts it for display or storage, truncated
// to max runes. Callers must never store raw argv.
func CommandLine(argv []string, max int) string {
	s := redact.Display(strings.Join(argv, " "))
	if max > 0 {
		if r := []rune(s); len(r) > max {
			s = string(r[:max-1]) + "…"
		}
	}
	return s
}
