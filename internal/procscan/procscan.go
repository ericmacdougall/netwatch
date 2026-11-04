// Package procscan classifies a process table: which watched processes are
// orphaned, which are running away, and whether a process about to be
// signalled is still the one the user saw. Collectors fill the table; this
// package has no OS dependencies so it can be tested with fake tables.
package procscan

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ericmacdougall/netwatch/internal/config"
)

// Process is one row of a process table.
type Process struct {
	PID   int
	PPID  int
	Own   bool      // owned by the user running netwatch
	CPU   float64   // percent of one core
	RSSMB int       // resident memory in MiB
	Start time.Time // process start; zero if unknown
	Age   time.Duration
	Name  string // short executable name
	Cmd   string // full command line as reported by the OS (unredacted)
	// Match is the text patterns are matched against. It equals Cmd except
	// on Windows, where the executable path is normalised to forward
	// slashes without ".exe" so one pattern set works everywhere.
	Match string
}

// MatchText returns the string used for pattern matching.
func (p Process) MatchText() string {
	if p.Match != "" {
		return p.Match
	}
	return p.Cmd
}

// Table indexes processes by PID.
type Table map[int]Process

// Index builds a Table.
func Index(procs []Process) Table {
	t := make(Table, len(procs))
	for _, p := range procs {
		t[p.PID] = p
	}
	return t
}

// OrphanRule decides whether a process has lost its original parent. The
// rule differs per OS, so collectors provide one.
type OrphanRule func(p Process, table Table) bool

// InitParent is the macOS rule: the process was reparented to launchd (pid 1).
func InitParent(p Process, _ Table) bool { return p.PPID == 1 }

// InitOrSubreaper is the Linux rule: reparented to pid 1 or to a child
// subreaper such as "systemd --user", which adopts orphans of a login
// session. Subreapers are recognised by process name because Linux exposes
// the subreaper flag only to the process itself.
func InitOrSubreaper(subreapers ...string) OrphanRule {
	names := map[string]bool{}
	for _, n := range subreapers {
		names[n] = true
	}
	return func(p Process, table Table) bool {
		if p.PPID == 1 {
			return true
		}
		parent, ok := table[p.PPID]
		return ok && names[parent.Name]
	}
}

// MissingParent is the Windows rule. Windows never reparents, so a process
// is orphaned when its recorded parent PID no longer exists, or when that
// PID now belongs to a process that started after the child and therefore
// cannot be its creator (Windows reuses PIDs quickly).
func MissingParent(p Process, table Table) bool {
	if p.PPID == 0 || p.PPID == 4 { // idle and System have no creator to lose
		return false
	}
	parent, ok := table[p.PPID]
	if !ok {
		return true
	}
	if parent.Start.IsZero() || p.Start.IsZero() {
		return false // cannot prove reuse; assume the parent is genuine
	}
	return parent.Start.After(p.Start)
}

// Orphans returns watched, user-owned processes that the rule says lost
// their parent and that are older than the configured minimum age.
func Orphans(cfg *config.Config, procs []Process, rule OrphanRule, self int) []Process {
	table := Index(procs)
	minAge := time.Duration(cfg.OrphanMinAgeMin * float64(time.Minute))
	var out []Process
	for _, p := range procs {
		if p.PID == self || p.PID <= 1 || !p.Own {
			continue
		}
		text := p.MatchText()
		if !config.MatchAny(cfg.Watch, text) {
			continue
		}
		if !rule(p, table) || p.Age < minAge {
			continue
		}
		if config.MatchAny(cfg.Ignore, text) {
			continue
		}
		out = append(out, p)
	}
	return out
}

// identity distinguishes a process from a later one that reused its PID.
type identity struct {
	pid   int
	start time.Time
}

// RunawayTracker flags watched, user-owned processes that stay hot for several scans or
// exceed an RSS ceiling. Each process is reported at most once per reason
// until it cools down (CPU) or exits.
type RunawayTracker struct {
	hot      map[identity]int
	reported map[identity]map[string]bool
}

// Runaway is a flagged process and why.
type Runaway struct {
	Process
	Reason string // "cpu" or "rss"
}

// NewRunawayTracker returns an empty tracker.
func NewRunawayTracker() *RunawayTracker {
	return &RunawayTracker{hot: map[identity]int{}, reported: map[identity]map[string]bool{}}
}

// Scan updates state from one process table and returns new runaways.
func (r *RunawayTracker) Scan(cfg *config.Config, procs []Process, self int) []Runaway {
	var flagged []Runaway
	live := map[identity]bool{}
	for _, p := range procs {
		// Other users' processes are skipped: their command lines are not
		// ours to log, and we could not act on them anyway.
		if p.PID == self || !p.Own || !config.MatchAny(cfg.Watch, p.MatchText()) {
			continue
		}
		id := identity{p.PID, p.Start}
		live[id] = true
		if r.reported[id] == nil {
			r.reported[id] = map[string]bool{}
		}
		if p.CPU >= cfg.RunawayCPUPct {
			r.hot[id]++
		} else {
			delete(r.hot, id)
			delete(r.reported[id], "cpu")
		}
		var reason string
		switch {
		case r.hot[id] >= cfg.RunawayScans && !r.reported[id]["cpu"]:
			reason = "cpu"
		case p.RSSMB >= cfg.RunawayRSSMB && !r.reported[id]["rss"]:
			reason = "rss"
		}
		if reason != "" {
			r.reported[id][reason] = true
			flagged = append(flagged, Runaway{Process: p, Reason: reason})
		}
	}
	for id := range r.hot {
		if !live[id] {
			delete(r.hot, id)
		}
	}
	for id := range r.reported {
		if !live[id] {
			delete(r.reported, id)
		}
	}
	return flagged
}

// StartTolerance is how far two observations of a process start time may
// differ and still be the same process. Some sources (ps etime) only have
// one-second resolution and are sampled at slightly different instants.
const StartTolerance = 2 * time.Second

// ErrChanged means the PID no longer belongs to the process that was listed.
var ErrChanged = errors.New("process changed since it was listed")

// VerifyForKill re-checks a listed orphan against a fresh table taken just
// before signalling it. It refuses unless the PID still refers to the same
// process (same start time and command), that process is still owned by the
// user, still watched, and still orphaned. This is what keeps --kill from
// hitting a process that reused the PID.
func VerifyForKill(cfg *config.Config, listed Process, fresh []Process, rule OrphanRule, self int) error {
	if listed.PID <= 1 || listed.PID == self {
		return fmt.Errorf("pid %d: refusing to signal init or netwatch itself", listed.PID)
	}
	table := Index(fresh)
	cur, ok := table[listed.PID]
	if !ok {
		return fmt.Errorf("pid %d: already exited", listed.PID)
	}
	if cur.Cmd != listed.Cmd || !sameStart(cur.Start, listed.Start) {
		return fmt.Errorf("pid %d: %w", listed.PID, ErrChanged)
	}
	for _, p := range Orphans(cfg, fresh, rule, self) {
		if p.PID == listed.PID {
			return nil
		}
	}
	return fmt.Errorf("pid %d: no longer an orphaned watched process", listed.PID)
}

func sameStart(a, b time.Time) bool {
	if a.IsZero() || b.IsZero() {
		return false // without a start time identity cannot be proven
	}
	d := a.Sub(b)
	if d < 0 {
		d = -d
	}
	return d <= StartTolerance
}

// ParseEtime converts ps "etime" ([[dd-]hh:]mm:ss) into a duration.
func ParseEtime(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("empty etime")
	}
	var days int
	if i := strings.IndexByte(s, '-'); i >= 0 {
		d, err := strconv.Atoi(s[:i])
		if err != nil || d < 0 {
			return 0, fmt.Errorf("bad etime days %q", s)
		}
		days = d
		s = s[i+1:]
	}
	parts := strings.Split(s, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return 0, fmt.Errorf("bad etime %q", s)
	}
	nums := make([]int, 3)
	off := 3 - len(parts)
	for i, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return 0, fmt.Errorf("bad etime field %q", part)
		}
		nums[off+i] = n
	}
	h, m, sec := nums[0], nums[1], nums[2]
	if m > 59 || sec > 59 {
		return 0, fmt.Errorf("bad etime %q", s)
	}
	total := time.Duration(days)*24*time.Hour + time.Duration(h)*time.Hour +
		time.Duration(m)*time.Minute + time.Duration(sec)*time.Second
	return total, nil
}

// Short truncates a string to n runes with an ellipsis.
func Short(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// BaseName returns the executable's base name from a command line, for
// short notification text.
func BaseName(p Process) string {
	if p.Name != "" {
		return p.Name
	}
	first := p.Cmd
	if i := strings.IndexByte(first, ' '); i >= 0 {
		first = first[:i]
	}
	if i := strings.LastIndexAny(first, `/\`); i >= 0 {
		first = first[i+1:]
	}
	return first
}
