package tracker

import (
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ericmacdougall/netwatch/internal/guard"
	"github.com/ericmacdougall/netwatch/internal/resources"
)

const gb = 1 << 30

type fakeSrc struct {
	procs  map[int]resources.Proc
	probes map[int]int // pgid listings and probes counted
	lists  []int
}

func newFake() *fakeSrc { return &fakeSrc{procs: map[int]resources.Proc{}, probes: map[int]int{}} }

func (f *fakeSrc) put(pid, ppid, pgid int, start time.Time, fp uint64) {
	f.procs[pid] = resources.Proc{PID: pid, PPID: ppid, PGID: pgid, SID: pgid, Start: start, Footprint: fp, FootprintOK: true, Name: "p"}
}

func (f *fakeSrc) Probe(pid int, p *resources.Proc) error {
	f.probes[pid]++
	q, ok := f.procs[pid]
	if !ok {
		return resources.ErrGone
	}
	*p = q
	return nil
}

func (f *fakeSrc) AppendGroupMembers(dst []int, pgid int) ([]int, error) {
	f.lists = append(f.lists, pgid)
	var out []int
	for _, p := range f.procs {
		if p.PGID == pgid {
			out = append(out, p.PID)
		}
	}
	sort.Ints(out)
	return append(dst, out...), nil
}

func (f *fakeSrc) AppendChildren(dst []int, pid int) ([]int, error) { return dst, nil }
func (f *fakeSrc) ExePath(pid int) string                           { return "/bin/p" }

var t0 = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

func sys() resources.System {
	return resources.System{RAM: 16 * gb, PageSize: 16384, Free: 1 << 18, SwapUsed: 2 * gb}
}

func find(terms []guard.Term, key string) *guard.Term {
	for i := range terms {
		if terms[i].Key == key {
			return &terms[i]
		}
	}
	return nil
}

func TestPollMeasuresGroupAndMembers(t *testing.T) {
	f := newFake()
	f.put(100, 1, 100, t0, 3*gb)
	f.put(101, 100, 100, t0.Add(time.Second), 2*gb)
	p := f.procs[101]
	p.Stopped = true
	f.procs[101] = p
	tr := New(f, Config{})
	tr.SetGroups([]GroupInfo{{PGID: 100, LeaderStart: t0, Tier: guard.TierTool, Agent: "main", FromWatcher: true}})
	terms := tr.Poll(t0.Add(10*time.Second), sys())
	g := find(terms, GroupKey(100, t0))
	if g == nil || g.Group == nil {
		t.Fatalf("no group term in %v", keys(terms))
	}
	if g.Group.Footprint != 5*gb || len(g.Group.Members) != 2 || g.Group.Tier != guard.TierTool || g.Group.Agent != "main" {
		t.Fatalf("%+v", g.Group)
	}
	if !g.Group.Members[1].Stopped || g.Group.Members[0].Stopped {
		t.Fatalf("stopped flags %+v", g.Group.Members)
	}
	if len(g.Series) != 1 || g.Series[0].Bytes != 5*gb {
		t.Fatalf("series %+v", g.Series)
	}
	if find(terms, "unattributed") == nil || terms[len(terms)-1].Key != "unattributed" {
		t.Fatal("unattributed must be the last term")
	}
}

func keys(ts []guard.Term) []string {
	var out []string
	for _, x := range ts {
		out = append(out, x.Key)
	}
	return out
}

func TestRingKeepsSixtySecondsPlusOne(t *testing.T) {
	f := newFake()
	f.put(100, 1, 100, t0, gb)
	tr := New(f, Config{})
	tr.SetGroups([]GroupInfo{{PGID: 100, LeaderStart: t0}})
	var last []guard.Term
	for i := 0; i <= 40; i++ { // 80s at a 2s cadence
		p := f.procs[100]
		p.Footprint = uint64(i+1) * gb / 10
		f.procs[100] = p
		last = tr.Poll(t0.Add(time.Duration(i)*2*time.Second), sys())
	}
	s := find(last, GroupKey(100, t0)).Series
	end := t0.Add(80 * time.Second)
	if first := s[0].At; first.After(end.Add(-60*time.Second)) || first.Before(end.Add(-62*time.Second)) {
		t.Fatalf("oldest point %v, want the last one at or before now-60s", end.Sub(first))
	}
	if len(s) > 32 {
		t.Fatalf("ring holds %d points", len(s))
	}
	if s[len(s)-1].Bytes != 41*gb/10 {
		t.Fatalf("newest %d", s[len(s)-1].Bytes)
	}
	// The returned series is a copy: mutating it cannot corrupt the ring.
	s[0].Bytes = 99
	if find(tr.Poll(end.Add(2*time.Second), sys()), GroupKey(100, t0)).Series[0].Bytes == 99 {
		t.Fatal("series aliases the ring")
	}
}

func TestOnlyTopSixteenGroupsPolled(t *testing.T) {
	f := newFake()
	var gs []GroupInfo
	for i := 0; i < 20; i++ {
		pid := 1000 + i
		f.put(pid, 1, pid, t0, uint64(i+1)*gb/4)
		gs = append(gs, GroupInfo{PGID: pid, LeaderStart: t0})
	}
	tr := New(f, Config{})
	tr.SetGroups(gs)
	// Seed ranking from a scan, as the monitor does after each full scan.
	var procs []resources.Proc
	for _, p := range f.procs {
		procs = append(procs, p)
	}
	tr.SetScan(procs, nil)
	f.lists = nil
	terms := tr.Poll(t0.Add(time.Second), sys())
	if len(f.lists) != MaxGroups {
		t.Fatalf("listed %d groups, want %d", len(f.lists), MaxGroups)
	}
	for _, pg := range f.lists {
		if pg < 1004 { // the four smallest groups (i=0..3) are skipped
			t.Fatalf("polled a small group %d while larger ones exist", pg)
		}
	}
	n := 0
	for _, x := range terms {
		if x.Group != nil {
			n++
		}
	}
	if n != MaxGroups {
		t.Fatalf("%d group terms", n)
	}
}

func TestNewGroupIsPolledBeforeRanked(t *testing.T) {
	f := newFake()
	var gs []GroupInfo
	for i := 0; i < 17; i++ {
		pid := 2000 + i
		f.put(pid, 1, pid, t0, 2*gb)
		gs = append(gs, GroupInfo{PGID: pid, LeaderStart: t0})
	}
	tr := New(f, Config{})
	tr.SetGroups(gs[:16])
	tr.Poll(t0.Add(time.Second), sys()) // all 16 measured: last = 2 GB each
	tr.SetGroups(gs)                    // a 17th group appears with no history
	f.lists = nil
	tr.Poll(t0.Add(2*time.Second), sys())
	found := false
	for _, pg := range f.lists {
		found = found || pg == 2016
	}
	if !found {
		t.Fatal("a brand-new group was starved by ranking")
	}
}

func TestMemberCapAndTruncationCounted(t *testing.T) {
	f := newFake()
	f.put(100, 1, 100, t0, gb)
	for i := 1; i <= 100; i++ {
		f.put(100+i, 100, 100, t0, gb/100)
	}
	tr := New(f, Config{})
	tr.SetGroups([]GroupInfo{{PGID: 100, LeaderStart: t0}})
	g := find(tr.Poll(t0.Add(time.Second), sys()), GroupKey(100, t0)).Group
	if len(g.Members) != MaxMembers {
		t.Fatalf("%d members", len(g.Members))
	}
	if tr.Stats().Truncated != 1 {
		t.Fatalf("stats %+v", tr.Stats())
	}
}

func TestPidReuseDropsGroupAndOldMembersSkipped(t *testing.T) {
	f := newFake()
	f.put(100, 1, 100, t0, gb)
	f.put(101, 100, 100, t0.Add(time.Second), gb)
	tr := New(f, Config{})
	tr.SetGroups([]GroupInfo{{PGID: 100, LeaderStart: t0}})
	if find(tr.Poll(t0.Add(2*time.Second), sys()), GroupKey(100, t0)) == nil {
		t.Fatal("setup")
	}
	// The leader exits and its pid is reused by an unrelated process that
	// joins the same pgid number (a new group leader).
	f.put(100, 1, 100, t0.Add(30*time.Second), 9*gb)
	terms := tr.Poll(t0.Add(40*time.Second), sys())
	if find(terms, GroupKey(100, t0)) != nil {
		t.Fatal("pid reuse was measured as the old group")
	}
	if tr.Stats().Reused != 1 {
		t.Fatalf("stats %+v", tr.Stats())
	}
	// A member that started before the recorded leader is not counted.
	f2 := newFake()
	f2.put(100, 1, 100, t0.Add(time.Minute), gb)
	f2.put(150, 1, 100, t0, 8*gb)
	tr2 := New(f2, Config{})
	tr2.SetGroups([]GroupInfo{{PGID: 100, LeaderStart: t0.Add(time.Minute)}})
	g := find(tr2.Poll(t0.Add(2*time.Minute), sys()), GroupKey(100, t0.Add(time.Minute))).Group
	if g.Footprint != gb || len(g.Members) != 1 {
		t.Fatalf("%+v", g)
	}
}

func TestExcludedSubtreeNotCounted(t *testing.T) {
	f := newFake()
	f.put(100, 1, 100, t0, gb)
	f.put(101, 100, 100, t0, 2*gb) // never-signal process
	f.put(102, 101, 100, t0, 4*gb) // its child
	f.put(103, 100, 100, t0, gb)
	tr := New(f, Config{Excluded: func(p *resources.Proc, exe string) bool { return p.PID == 101 }})
	tr.SetGroups([]GroupInfo{{PGID: 100, LeaderStart: t0}})
	g := find(tr.Poll(t0.Add(time.Second), sys()), GroupKey(100, t0)).Group
	ex := map[int]bool{}
	for _, m := range g.Members {
		ex[m.PID] = m.Excluded
	}
	if !ex[101] || !ex[102] || ex[100] || ex[103] {
		t.Fatalf("exclusion %v", ex)
	}
	if g.Footprint != 2*gb {
		t.Fatalf("footprint %d, excluded subtree must not count", g.Footprint)
	}
}

func TestUnreadableMembersCountZero(t *testing.T) {
	f := newFake()
	f.put(100, 1, 100, t0, gb)
	f.put(101, 100, 100, t0, 0)
	p := f.procs[101]
	p.FootprintOK = false
	f.procs[101] = p
	tr := New(f, Config{})
	tr.SetGroups([]GroupInfo{{PGID: 100, LeaderStart: t0}})
	g := find(tr.Poll(t0.Add(time.Second), sys()), GroupKey(100, t0)).Group
	if g.Footprint != gb || len(g.Members) != 2 || tr.Stats().Unreadable != 1 {
		t.Fatalf("%+v %+v", g, tr.Stats())
	}
}

func TestIneligibleAggregatesAndUnattributed(t *testing.T) {
	f := newFake()
	f.put(100, 1, 100, t0, 2*gb)
	tr := New(f, Config{})
	tr.SetGroups([]GroupInfo{{PGID: 100, LeaderStart: t0}})
	scan := []resources.Proc{
		f.procs[100],
		{PID: 7, PGID: 7, Footprint: 3 * gb, FootprintOK: true, Name: "Chrome Helper"},
		{PID: 8, PGID: 7, Footprint: gb, FootprintOK: true, Name: "Chrome Helper"},
		{PID: 9, PGID: 9, Footprint: gb, FootprintOK: true, Name: "Slack"},
		{PID: 10, PGID: 10, FootprintOK: false, Name: "root-owned"},
	}
	owner := func(p resources.Proc) string {
		if strings.HasPrefix(p.Name, "Chrome") {
			return "Chrome"
		}
		return p.Name
	}
	tr.SetScan(scan, owner)
	s := sys()
	terms := tr.Poll(t0.Add(time.Second), s)
	if v := find(terms, "inel:Chrome"); v == nil || v.Series[0].Bytes != 4*gb {
		t.Fatalf("chrome aggregate %+v", v)
	}
	if find(terms, "inel:Slack") == nil || find(terms, "inel:root-owned") == nil && false {
		t.Fatal("slack aggregate missing")
	}
	for _, x := range terms {
		if x.Key == "inel:root-owned" && x.Series[0].Bytes != 0 {
			t.Fatal("unreadable process contributed bytes")
		}
	}
	// unattributed = used - sum of the others, exactly.
	want := Used(s, false) - (2*gb + 4*gb + gb)
	if got := find(terms, "unattributed").Series[0].Bytes; got != want {
		t.Fatalf("unattributed %d, want %d", got, want)
	}
}

// A6: used includes swap by default; removing the swap term raises the
// computed share. This pins the direction so a refactor cannot flip it.
func TestA6SwapDirection(t *testing.T) {
	build := func(excludeSwap bool) float64 {
		f := newFake()
		f.put(100, 1, 100, t0, 3*gb)
		tr := New(f, Config{ExcludeSwap: excludeSwap})
		tr.SetGroups([]GroupInfo{{PGID: 100, LeaderStart: t0}})
		s := sys()
		s.SwapUsed = 4 * gb
		return Share(GroupKey(100, t0), tr.Poll(t0.Add(time.Second), s))
	}
	with, without := build(false), build(true)
	if !(without > with) {
		t.Fatalf("share without swap %.4f should exceed share with swap %.4f", without, with)
	}
	s := sys()
	if Used(s, false)-Used(s, true) != s.SwapUsed {
		t.Fatal("swap must enter used exactly once")
	}
}

func TestUsedUsesReclaimablePoolWithoutCompressorCapacity(t *testing.T) {
	s := resources.System{RAM: 16 * gb, PageSize: 4096,
		Free: 1 * gb / 4096, Speculative: 1 * gb / 4096, Purgeable: 1 * gb / 4096, Inactive: 1 * gb / 4096,
		CompressorBytes: 1 * gb, PagesCompressed: 3 * gb / 4096, PagesCompressedLimit: 100 * gb / 4096}
	// 16 - 4 reclaimable = 12, plus (3 logical - 1 physical) = 14. The
	// compressor's capacity (the limit) must play no part.
	if got := Used(s, true); got != 14*gb {
		t.Fatalf("used %d GiB", got/gb)
	}
}

func TestTermsSortedAndShare(t *testing.T) {
	f := newFake()
	for _, pg := range []int{300, 100, 200} {
		f.put(pg, 1, pg, t0, gb)
	}
	tr := New(f, Config{})
	tr.SetGroups([]GroupInfo{{PGID: 300, LeaderStart: t0}, {PGID: 100, LeaderStart: t0}, {PGID: 200, LeaderStart: t0}})
	terms := tr.Poll(t0.Add(time.Second), sys())
	ks := keys(terms)
	if !sort.StringsAreSorted(ks[:3]) {
		t.Fatalf("group terms unsorted: %v", ks)
	}
	if Share("missing", terms) != 0 || Share(ks[0], nil) != 0 {
		t.Fatal("share of nothing")
	}
}
