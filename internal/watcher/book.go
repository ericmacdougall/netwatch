// Package watcher records the children of Claude Code processes so the
// guard can tell a tool-shell process group from an unrelated one.
//
// A kqueue NOTE_FORK on each Claude pid (darwin) says only that a fork
// happened; the pid is found with a PPID_ONLY listing. Each child is kept
// as (pid, start, claude pid, claude start, state). A tool shell calls
// setsid after it is forked, so a record must outlive its pid until no
// process claims it as a group or session leader (CR-3), and it may only
// be retired on the evidence of a fresh, successful, full scan (CR-11).
package watcher

import (
	"sort"
	"sync"
	"time"

	"github.com/ericmacdougall/netwatch/internal/resources"
)

// State of a record.
type State int

// Record states.
const (
	// Pending: forked, exec not yet seen to complete. Never retired.
	Pending State = iota
	// Classified: the child runs a different executable than its parent.
	Classified
	// Unverified: the child exited (or was replaced) before exec was seen.
	// Groups it led are pause-only.
	Unverified
)

func (s State) String() string {
	switch s {
	case Pending:
		return "pending"
	case Classified:
		return "classified"
	case Unverified:
		return "unverified"
	}
	return "?"
}

// Record is one observed child of a Claude Code process.
type Record struct {
	PID         int
	Start       time.Time // zero when the child was gone before it was probed
	ClaudePID   int
	ClaudeStart time.Time
	State       State
	Exe         string // child executable once Classified
	FirstSeen   time.Time
	SetsidSeen  bool // the child was seen as its own session and group leader
}

// Limits.
const (
	MaxRecords = 4096
	MaxLife    = 24 * time.Hour
	// MinRetireAge is how old a record must be before it can be retired.
	MinRetireAge = 10 * time.Second
	// DefaultFresh is the longest a scan may be old and still count.
	DefaultFresh = 20 * time.Second
)

// Source is what the book needs from a process reader.
type Source interface {
	AppendChildren(dst []int, pid int) ([]int, error)
	Probe(pid int, p *resources.Proc) error
	ExePath(pid int) string
}

// Scan is one full process-table scan.
type Scan struct {
	At    time.Time
	OK    bool // false if the scan failed or was cut short
	Procs []resources.Proc
}

type claude struct {
	start time.Time
	exe   string
}

type recKey struct {
	pid   int
	start int64 // zero for unverified records
}

// Book holds the records.
type Book struct {
	src   Source
	now   func() time.Time
	fresh time.Duration

	mu      sync.Mutex
	claudes map[int]claude
	recs    map[recKey]*Record
	byPID   map[int]*Record // newest record per pid
	dropped uint64
	scratch []int
}

// NewBook returns an empty book. now may be nil (time.Now).
func NewBook(src Source, now func() time.Time) *Book {
	if now == nil {
		now = time.Now
	}
	return &Book{src: src, now: now, fresh: DefaultFresh,
		claudes: map[int]claude{}, recs: map[recKey]*Record{}, byPID: map[int]*Record{}}
}

// SetFresh sets how old a scan may be and still retire records.
func (b *Book) SetFresh(d time.Duration) { b.mu.Lock(); b.fresh = d; b.mu.Unlock() }

// Track registers a Claude process whose children are to be recorded.
// exe is its executable path, used to tell "forked, not yet exec'd" from
// "exec'd".
func (b *Book) Track(pid int, start time.Time, exe string) {
	b.mu.Lock()
	b.claudes[pid] = claude{start, exe}
	b.mu.Unlock()
}

// Untrack stops recording children of pid. Existing records stay: the
// children may outlive their parent.
func (b *Book) Untrack(pid int) {
	b.mu.Lock()
	delete(b.claudes, pid)
	b.mu.Unlock()
}

// Tracked returns the tracked Claude pids.
func (b *Book) Tracked() []int {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]int, 0, len(b.claudes))
	for p := range b.claudes {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// Dropped counts children that were not recorded because the book was
// full. An unrecorded child is never eligible, so this fails safe.
func (b *Book) Dropped() uint64 { b.mu.Lock(); defer b.mu.Unlock(); return b.dropped }

// Len returns the record count.
func (b *Book) Len() int { b.mu.Lock(); defer b.mu.Unlock(); return len(b.recs) }

// OnFork lists the children of a tracked Claude pid and records new ones.
// It returns how many records were added.
func (b *Book) OnFork(claudePID int) (int, error) {
	b.mu.Lock()
	c, ok := b.claudes[claudePID]
	b.mu.Unlock()
	if !ok {
		return 0, nil
	}
	kids, err := b.src.AppendChildren(b.takeScratch(), claudePID)
	defer b.putScratch(kids)
	if err != nil {
		return 0, err
	}
	added := 0
	now := b.now()
	for _, pid := range kids {
		var p resources.Proc
		perr := b.src.Probe(pid, &p)
		b.mu.Lock()
		if perr == nil && p.PPID != claudePID {
			b.mu.Unlock()
			continue // reparented between listing and probe
		}
		k := recKey{pid: pid}
		if perr == nil {
			k.start = p.Start.UnixNano()
		}
		if _, dup := b.recs[k]; dup {
			b.mu.Unlock()
			continue
		}
		if perr != nil {
			// Listed but gone before it could be probed. Remember the pid
			// only if no live record already uses it.
			if cur, ok := b.byPID[pid]; ok && cur.State != Unverified {
				b.mu.Unlock()
				continue
			}
		}
		if len(b.recs) >= MaxRecords {
			b.dropped++
			b.mu.Unlock()
			continue
		}
		r := &Record{PID: pid, ClaudePID: claudePID, ClaudeStart: c.start, FirstSeen: now}
		if perr == nil {
			r.Start = p.Start
		} else {
			r.State = Unverified
		}
		b.recs[k] = r
		b.byPID[pid] = r
		b.mu.Unlock()
		added++
	}
	b.Settle()
	return added, nil
}

// Sweep runs OnFork for every tracked Claude pid. Platforms without
// kqueue call it each poll instead.
func (b *Book) Sweep() {
	for _, pid := range b.Tracked() {
		b.OnFork(pid)
	}
}

func (b *Book) takeScratch() []int {
	b.mu.Lock()
	s := b.scratch[:0]
	b.scratch = nil
	b.mu.Unlock()
	return s
}

func (b *Book) putScratch(s []int) {
	b.mu.Lock()
	if cap(s) <= 4096 {
		b.scratch = s[:0]
	}
	b.mu.Unlock()
}

// Settle advances Pending records: a child that now runs a different
// executable than its Claude parent is Classified; one that is gone, or
// whose pid now has another start time, becomes Unverified. A record is
// classified only after exec completes, because between fork and exec the
// child is a copy of Claude itself.
func (b *Book) Settle() {
	b.mu.Lock()
	var pend []*Record
	for _, r := range b.recs {
		if r.State == Pending || (r.State == Classified && !r.SetsidSeen) {
			pend = append(pend, r)
		}
	}
	claudes := make(map[int]claude, len(b.claudes))
	for k, v := range b.claudes {
		claudes[k] = v
	}
	b.mu.Unlock()

	for _, r := range pend {
		var p resources.Proc
		err := b.src.Probe(r.PID, &p)
		gone := err != nil || !p.Start.Equal(r.Start)
		exe := ""
		if !gone && r.State == Pending {
			exe = b.src.ExePath(r.PID)
		}
		b.mu.Lock()
		switch {
		case gone && r.State == Pending:
			r.State = Unverified
		case gone:
			// A classified child that has exited keeps its state.
		case r.State == Pending:
			cexe := claudes[r.ClaudePID].exe
			if exe != "" && exe != cexe {
				r.State, r.Exe = Classified, exe
			}
		}
		if !gone && p.PGID == r.PID && p.SID == r.PID {
			r.SetsidSeen = true
		}
		b.mu.Unlock()
	}
}

// Lookup returns the newest record for pid.
func (b *Book) Lookup(pid int) (Record, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	r, ok := b.byPID[pid]
	if !ok {
		return Record{}, false
	}
	return *r, true
}

// LookupStart returns the record for (pid, start); an unverified record
// (unknown start) matches any start not earlier than its first sighting.
func (b *Book) LookupStart(pid int, start time.Time) (Record, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if r, ok := b.recs[recKey{pid, start.UnixNano()}]; ok {
		return *r, true
	}
	if r, ok := b.recs[recKey{pid: pid}]; ok && r.State == Unverified && !start.Before(r.FirstSeen.Add(-MinRetireAge)) {
		return *r, true
	}
	return Record{}, false
}

// Records returns a copy of all records ordered by pid.
func (b *Book) Records() []Record {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]Record, 0, len(b.recs))
	for _, r := range b.recs {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].PID != out[j].PID {
			return out[i].PID < out[j].PID
		}
		return out[i].Start.Before(out[j].Start)
	})
	return out
}

// Retire drops records that a fresh, successful full scan proves are done,
// and expires records past MaxLife. A record is retired only if all hold:
//
//   - the scan succeeded, covers the table and is no older than the
//     freshness bound, and was taken after the record was MinRetireAge old;
//   - the record is not Pending;
//   - its pid is dead (absent, or present with another start time);
//   - no process in the scan has sid == pid or pgid == pid.
//
// It returns the number retired. A failed or stale scan retires nothing.
func (b *Book) Retire(s Scan) int {
	now := b.now()
	b.mu.Lock()
	defer b.mu.Unlock()

	n := 0
	// Lifetime limit first: it is a bound, not evidence about the process.
	for k, r := range b.recs {
		if now.Sub(r.FirstSeen) > MaxLife {
			b.remove(k, r)
			n++
		}
	}
	if !s.OK || s.At.IsZero() || now.Sub(s.At) > b.fresh || s.At.After(now.Add(time.Second)) {
		return n
	}
	byPID := make(map[int]*resources.Proc, len(s.Procs))
	leader := make(map[int]bool, 64)
	for i := range s.Procs {
		p := &s.Procs[i]
		byPID[p.PID] = p
		leader[p.SID] = true
		leader[p.PGID] = true
	}
	for k, r := range b.recs {
		if r.State == Pending || s.At.Before(r.FirstSeen.Add(MinRetireAge)) {
			continue
		}
		if p, alive := byPID[r.PID]; alive && (r.Start.IsZero() || p.Start.Equal(r.Start)) {
			continue
		}
		if leader[r.PID] {
			continue
		}
		b.remove(k, r)
		n++
	}
	return n
}

func (b *Book) remove(k recKey, r *Record) {
	delete(b.recs, k)
	if b.byPID[r.PID] == r {
		delete(b.byPID, r.PID)
		// Another record may still use the pid (reuse); keep the newest.
		var best *Record
		for _, o := range b.recs {
			if o.PID == r.PID && (best == nil || o.FirstSeen.After(best.FirstSeen)) {
				best = o
			}
		}
		if best != nil {
			b.byPID[r.PID] = best
		}
	}
}
