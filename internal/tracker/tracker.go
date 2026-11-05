// Package tracker keeps 60s footprint rings for agent groups, ineligible
// aggregates and "unattributed", using PGRP_ONLY listings for the top 16
// groups (at most 64 members each) with preallocated buffers.
//
// The tracker does not decide which groups are agent groups: the caller
// (watcher records plus attrib) supplies them with SetGroups after each
// full scan. It only measures them, cheaply, between scans.
package tracker

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/ericmacdougall/netwatch/internal/guard"
	"github.com/ericmacdougall/netwatch/internal/resources"
)

// Window is the ring length in seconds.
const Window = 60

// Limits on one poll.
const (
	MaxGroups  = 16
	MaxMembers = 64
)

const (
	maxPoints  = 256  // hard cap on one ring regardless of poll rate
	maxExeKeys = 4096 // exe cache bound
)

// Source is the part of a reader the tracker uses.
type Source interface {
	resources.Prober
	resources.Lister
	resources.ExeResolver
}

// GroupInfo describes one agent-owned process group. The caller builds it
// from watcher records, attribution and the budget check.
type GroupInfo struct {
	PGID        int
	LeaderStart time.Time
	Tier        guard.Tier
	Agent       string
	Cmd         string // already redacted and short
	ClaudeVer   string
	Allowlisted bool
	EnvOK       bool
	Budget      *guard.Budget
	FromWatcher bool
}

// Config tunes the tracker. The zero value is valid.
type Config struct {
	Window     time.Duration // default 60s
	MaxGroups  int           // default MaxGroups
	MaxMembers int           // default MaxMembers
	// ExcludeSwap removes vm.swapusage from "used" (see Used). The default
	// includes it (Amendment A6): that overstates unattributed, which only
	// lowers an agent's share and so errs toward fewer kills.
	ExcludeSwap bool
	// Excluded reports a never-signal process (by comm or resolved exe).
	// Its whole subtree is excluded and not counted in the group size.
	Excluded func(p *resources.Proc, exe string) bool
}

// Stats counts events that matter for diagnosis and overhead.
type Stats struct {
	Polls, Truncated, Reused, Unreadable, Gone uint64
}

type ring struct {
	pts []guard.Point
}

func (r *ring) add(at time.Time, b uint64, window time.Duration) {
	if n := len(r.pts); n > 0 && !at.After(r.pts[n-1].At) {
		return // out-of-order or duplicate timestamp
	}
	r.pts = append(r.pts, guard.Point{At: at, Bytes: b})
	// Drop points older than the window, but keep the newest one that is
	// at or before the cutoff so the value 60s ago can be read.
	cut := at.Add(-window)
	i := 0
	for i+1 < len(r.pts) && !r.pts[i+1].At.After(cut) {
		i++
	}
	if i > 0 {
		r.pts = append(r.pts[:0], r.pts[i:]...)
	}
	if len(r.pts) > maxPoints {
		r.pts = append(r.pts[:0], r.pts[len(r.pts)-maxPoints:]...)
	}
}

func (r *ring) series() []guard.Point {
	out := make([]guard.Point, len(r.pts))
	copy(out, r.pts)
	return out
}

type groupState struct {
	info GroupInfo
	ring ring
	last uint64 // last footprint, for ranking
}

// Tracker produces guard terms. Methods are safe for concurrent use.
type Tracker struct {
	src Source
	cfg Config

	mu     sync.Mutex
	groups map[string]*groupState // key: pg:<pgid>:<leader start ns>
	inel   map[string]*ring
	inelV  map[string]uint64 // latest aggregate values, step-held between scans
	unattr ring
	exe    map[exeKey]string
	pids   []int
	stats  Stats
}

type exeKey struct {
	pid   int
	start int64
}

// New returns a tracker.
func New(src Source, cfg Config) *Tracker {
	if cfg.Window <= 0 {
		cfg.Window = Window * time.Second
	}
	if cfg.MaxGroups <= 0 {
		cfg.MaxGroups = MaxGroups
	}
	if cfg.MaxMembers <= 0 {
		cfg.MaxMembers = MaxMembers
	}
	return &Tracker{src: src, cfg: cfg, groups: map[string]*groupState{},
		inel: map[string]*ring{}, inelV: map[string]uint64{}, exe: map[exeKey]string{},
		pids: make([]int, 0, 4*MaxMembers)}
}

// GroupKey is the term key of a group.
func GroupKey(pgid int, leaderStart time.Time) string {
	return fmt.Sprintf("pg:%d:%d", pgid, leaderStart.UnixNano())
}

// SetGroups replaces the set of agent groups after a scan. A group that
// remains keeps its ring; one that is gone loses it.
func (t *Tracker) SetGroups(gs []GroupInfo) {
	t.mu.Lock()
	defer t.mu.Unlock()
	next := make(map[string]*groupState, len(gs))
	for _, g := range gs {
		k := GroupKey(g.PGID, g.LeaderStart)
		if old, ok := t.groups[k]; ok {
			old.info = g
			next[k] = old
			continue
		}
		next[k] = &groupState{info: g}
	}
	t.groups = next
}

// SetScan folds a full scan in: ineligible aggregates (every process that
// is not in an agent group, summed per owner) and the ranking seeds for
// groups. ownerOf names the owner app of a process. Aggregates are
// step-held until the next scan; the full scan is the only place the whole
// table is read.
func (t *Tracker) SetScan(procs []resources.Proc, ownerOf func(resources.Proc) string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	pgidOf := map[int]*groupState{}
	for _, g := range t.groups {
		pgidOf[g.info.PGID] = g
	}
	seed := map[*groupState]uint64{}
	agg := map[string]uint64{}
	for i := range procs {
		p := &procs[i]
		if !p.FootprintOK {
			continue
		}
		if g, ok := pgidOf[p.PGID]; ok && !p.Start.Before(g.info.LeaderStart) {
			seed[g] += p.Footprint
			continue
		}
		owner := "unknown"
		if ownerOf != nil {
			if o := ownerOf(*p); o != "" {
				owner = o
			}
		}
		agg["inel:"+owner] += p.Footprint
	}
	for g, v := range seed {
		g.last = v
	}
	t.inelV = agg
}

// Used is the memory the host is using that processes could account for,
// in the same logical units as phys_footprint: everything not in the
// reclaimable pool of Amendment A1 (free, speculative, purgeable,
// inactive), with compressed pages counted at their logical size, plus
// swap unless excludeSwap. Footprints of agent groups and ineligible
// processes are subtracted from it to give "unattributed".
func Used(s resources.System, excludeSwap bool) uint64 {
	ps := s.PageSize
	reclaim := (s.Free + s.Speculative + s.Purgeable + s.Inactive) * ps
	var used uint64
	if s.RAM > reclaim {
		used = s.RAM - reclaim
	}
	// The compressor's physical pages are inside used; footprints count
	// what they hold at logical size.
	logical := s.PagesCompressed * ps
	if logical > s.CompressorBytes {
		used += logical - s.CompressorBytes
	}
	if !excludeSwap {
		used += s.SwapUsed
	}
	return used
}

// Poll measures the top groups and returns every term. sys is the reading
// taken for this poll.
func (t *Tracker) Poll(now time.Time, sys resources.System) []guard.Term {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.stats.Polls++

	// Rank by last known footprint, groups never measured first.
	order := make([]*groupState, 0, len(t.groups))
	for _, g := range t.groups {
		order = append(order, g)
	}
	sort.Slice(order, func(i, j int) bool {
		a, b := order[i], order[j]
		if (a.last == 0) != (b.last == 0) {
			return a.last == 0
		}
		if a.last != b.last {
			return a.last > b.last
		}
		return a.info.PGID < b.info.PGID
	})
	if len(order) > t.cfg.MaxGroups {
		order = order[:t.cfg.MaxGroups]
	}

	// One pass lists every group where the platform has no group index.
	var batch map[int][]int
	if bl, ok := t.src.(resources.BatchLister); ok && len(order) > 1 {
		batch = make(map[int][]int, len(order))
		pgids := make([]int, len(order))
		for i, g := range order {
			pgids[i] = g.info.PGID
		}
		if bl.GroupsMembers(pgids, batch) != nil {
			batch = nil // fall back to per-group listings
		}
	}

	terms := make([]guard.Term, 0, len(order)+len(t.inelV)+1)
	var sum uint64
	for _, g := range order {
		var pre []int
		if batch != nil {
			pre = batch[g.info.PGID]
		}
		grp, reused := t.measure(g, now, pre, batch != nil)
		if reused {
			t.stats.Reused++
			delete(t.groups, GroupKey(g.info.PGID, g.info.LeaderStart))
			continue
		}
		g.last = grp.Footprint
		g.ring.add(now, grp.Footprint, t.cfg.Window)
		sum += grp.Footprint
		terms = append(terms, guard.Term{Key: GroupKey(g.info.PGID, g.info.LeaderStart), Group: grp, Series: g.ring.series()})
	}
	sort.Slice(terms, func(i, j int) bool { return terms[i].Key < terms[j].Key })

	keys := make([]string, 0, len(t.inelV))
	for k := range t.inelV {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := t.inelV[k]
		r := t.inel[k]
		if r == nil {
			r = &ring{}
			t.inel[k] = r
		}
		r.add(now, v, t.cfg.Window)
		sum += v
		terms = append(terms, guard.Term{Key: k, Series: r.series()})
	}
	for k := range t.inel { // forget aggregates that vanished from the scan
		if _, ok := t.inelV[k]; !ok {
			delete(t.inel, k)
		}
	}

	var un uint64
	if used := Used(sys, t.cfg.ExcludeSwap); used > sum {
		un = used - sum
	}
	t.unattr.add(now, un, t.cfg.Window)
	terms = append(terms, guard.Term{Key: "unattributed", Series: t.unattr.series()})
	return terms
}

// measure reads one group. reused is true if the group's leader pid now
// belongs to a different process, so the recorded group no longer exists.
func (t *Tracker) measure(g *groupState, now time.Time, pre []int, havePre bool) (grp *guard.Group, reused bool) {
	var pids []int
	var err error
	if havePre {
		sort.Ints(pre)
		pids = pre
	} else {
		pids, err = t.src.AppendGroupMembers(t.pids[:0], g.info.PGID)
		t.pids = pids[:0]
	}
	grp = &guard.Group{
		PGID: g.info.PGID, LeaderStart: g.info.LeaderStart, Tier: g.info.Tier,
		Agent: g.info.Agent, Cmd: g.info.Cmd, ClaudeVer: g.info.ClaudeVer,
		Allowlisted: g.info.Allowlisted, EnvOK: g.info.EnvOK, Budget: g.info.Budget,
		FromWatcher: g.info.FromWatcher,
	}
	if err != nil {
		return grp, false
	}
	if len(pids) > t.cfg.MaxMembers {
		t.stats.Truncated++
		pids = pids[:t.cfg.MaxMembers]
	}
	type seen struct {
		m  guard.Member
		pp int
		fp uint64
	}
	ms := make([]seen, 0, len(pids))
	var p resources.Proc
	for _, pid := range pids {
		if t.src.Probe(pid, &p) != nil {
			t.stats.Gone++
			continue
		}
		if pid == g.info.PGID && !p.Start.Equal(g.info.LeaderStart) {
			return grp, true // pid reuse: the recorded leader is gone
		}
		if p.Start.Before(g.info.LeaderStart) {
			continue // not a descendant of the recorded leader
		}
		if !p.FootprintOK {
			t.stats.Unreadable++
		}
		excl := false
		if t.cfg.Excluded != nil {
			excl = t.cfg.Excluded(&p, t.exePath(&p))
		}
		ms = append(ms, seen{guard.Member{PID: p.PID, Start: p.Start, Excluded: excl, Stopped: p.Stopped}, p.PPID, p.Footprint})
	}
	// Exclusion covers the whole subtree: propagate to a fixpoint.
	for changed := true; changed; {
		changed = false
		for i := range ms {
			if ms[i].m.Excluded {
				continue
			}
			for j := range ms {
				if ms[j].m.Excluded && ms[i].pp == ms[j].m.PID {
					ms[i].m.Excluded, changed = true, true
					break
				}
			}
		}
	}
	grp.Members = make([]guard.Member, 0, len(ms))
	for _, s := range ms {
		grp.Members = append(grp.Members, s.m)
		if !s.m.Excluded {
			grp.Footprint += s.fp
		}
	}
	return grp, false
}

func (t *Tracker) exePath(p *resources.Proc) string {
	k := exeKey{p.PID, p.Start.UnixNano()}
	if e, ok := t.exe[k]; ok {
		return e
	}
	if len(t.exe) >= maxExeKeys {
		t.exe = make(map[exeKey]string, maxExeKeys)
	}
	e := t.src.ExePath(p.PID)
	t.exe[k] = e
	return e
}

// Stats returns a copy of the counters.
func (t *Tracker) Stats() Stats {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.stats
}

// Share is the latest footprint of the term with the given key as a
// fraction of the sum of the latest footprints of all terms.
func Share(key string, terms []guard.Term) float64 {
	var sum, mine uint64
	for _, tm := range terms {
		if len(tm.Series) == 0 {
			continue
		}
		v := tm.Series[len(tm.Series)-1].Bytes
		sum += v
		if tm.Key == key {
			mine = v
		}
	}
	if sum == 0 {
		return 0
	}
	return float64(mine) / float64(sum)
}
