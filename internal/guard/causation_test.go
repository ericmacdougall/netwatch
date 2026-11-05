package guard

import (
	"testing"
	"time"

	"github.com/ericmacdougall/netwatch/internal/resources"
)

// pathB drives a paused D4 group to a path-B-only kill setup.
func onlyPathB(r *rig) {
	r.m.cfg.DisablePathA = true
	r.m.cfg.DisableFast = true
}

func TestKillPathBImminentExhaustion(t *testing.T) {
	r := killRig(t, ModePauseKill)
	onlyPathB(r)
	r.comp = 960 // 96% of the compressor limit
	start := r.at.Add(2 * time.Second)
	for i := 0; i < 30; i++ {
		if _, ok := r.termAt(); ok {
			break
		}
		r.poll(2*time.Second, warn)
	}
	at, ok := r.termAt()
	must(t, ok, "path B must kill under 95%% held")
	must(t, at.Sub(start) == 20*time.Second, "path B holds 20s: SIGTERM at +%v", at.Sub(start))

	// Swap at 95% of swap plus free disk is the other trigger.
	s := killRig(t, ModePauseKill)
	onlyPathB(s)
	s.swap, s.disk = 19*gib, 1*gib
	s.run(30, 2*time.Second, warn)
	_, ok = s.termAt()
	must(t, ok, "path B on swap exhaustion")
}

func TestKillPathBNegatives(t *testing.T) {
	type tc struct {
		name string
		mut  func(r *rig)
		lvl  func(i int) resourcesLevel
	}
	cases := []tc{
		{"94% is below the bound", func(r *rig) { r.comp = 940 }, func(int) resourcesLevel { return warn }},
		{"normal pressure", func(r *rig) { r.comp = 960 }, func(int) resourcesLevel { return normal }},
		{"held only 15s", func(r *rig) {}, func(i int) resourcesLevel { return warn }},
	}
	for _, c := range cases {
		r := killRig(t, ModePauseKill)
		onlyPathB(r)
		c.mut(r)
		for i := 0; i < 40; i++ {
			if c.name == "held only 15s" {
				if i == 0 {
					r.comp = 960
				}
				if i == 7 {
					r.comp = 0 // drops after 14s
				}
			}
			r.poll(2*time.Second, c.lvl(i))
		}
		_, ok := r.termAt()
		must(t, !ok, "%s: must not kill", c.name)
	}
}

type resourcesLevel = resources.Level

func TestNEG21FlatHighLevelWithoutCausationNeverKills(t *testing.T) {
	// A group paused as the largest consumer, never D4, no growth: path B
	// is reached (96% held) but there is no causation.
	r := newRig(t, ModePauseKill)
	r.setMinShare(0.1)
	r.tool(100, 5*gib, 101)
	r.comp = 960
	r.run(10, 2*time.Second, crit)
	must(t, r.paused(100), "setup")
	r.run(120, 2*time.Second, crit)
	must(t, r.w.count(sigTERM) == 0, "no causation, no kill")
	// Variant: the pause itself makes compressor use rise. Still no kill.
	v := newRig(t, ModePauseKill)
	v.setMinShare(0.1)
	v.tool(100, 5*gib, 101)
	v.comp = 860
	v.run(10, 2*time.Second, crit)
	v.comp = 980
	v.run(120, 2*time.Second, crit)
	must(t, v.w.count(sigTERM) == 0, "rising level without causation must not kill")
}

func TestFastKillPathAndItsNegatives(t *testing.T) {
	fast := func(r *rig) { r.m.cfg.DisablePathA = true; r.m.cfg.DisablePathB = true }
	// Positive: paused, D4 latched, 95% on 2 polls <= 6s apart, pressure warn.
	r := killRig(t, ModePauseKill)
	fast(r)
	r.comp = 980
	r.poll(2*time.Second, warn)
	_, ok := r.termAt()
	must(t, !ok, "a single 95%% poll must not kill")
	r.poll(2*time.Second, warn)
	at, ok := r.termAt()
	must(t, ok && at.Equal(r.at), "the second 95%% poll kills at once")

	neg := map[string]func() *rig{
		"no D4 (largest-consumer pause only)": func() *rig {
			x := newRig(t, ModePauseKill)
			x.setMinShare(0.1)
			x.tool(100, 5*gib, 101)
			x.run(6, 2*time.Second, crit)
			fast(x)
			x.comp = 980
			return x
		},
		"gap over 6s between the polls": func() *rig {
			x := killRig(t, ModePauseKill)
			fast(x)
			x.comp = 980
			x.poll(2*time.Second, warn)
			x.poll(8*time.Second, warn)
			return x
		},
		"normal pressure": func() *rig {
			x := killRig(t, ModePauseKill)
			fast(x)
			x.comp = 980
			x.run(5, 2*time.Second, normal)
			return x
		},
		"pause mode": func() *rig {
			x := killRig(t, ModePause)
			fast(x)
			x.comp = 980
			x.run(5, 2*time.Second, warn)
			return x
		},
		"fallback tier": func() *rig {
			x := killRig(t, ModePauseKill)
			x.groups[100].tier = TierFallback
			fast(x)
			x.comp = 980
			x.run(5, 2*time.Second, warn)
			return x
		},
		"unallowlisted version": func() *rig {
			x := killRig(t, ModePauseKill)
			x.groups[100].allow = false
			fast(x)
			x.comp = 980
			x.run(5, 2*time.Second, warn)
			return x
		},
		"group is not paused": func() *rig {
			x := newRig(t, ModePauseKill)
			x.m.cfg.MaxPaused = 0 // nothing can be paused
			x.tool(100, 10*gib, 101)
			x.run(3, 2*time.Second, normal)
			for i := 0; i < 3; i++ {
				x.grow(100, gib)
				x.poll(2*time.Second, warn)
			}
			fast(x)
			x.comp = 980
			x.run(5, 2*time.Second, warn)
			return x
		},
		"95% never reached (94%)": func() *rig {
			x := killRig(t, ModePauseKill)
			fast(x)
			x.comp = 940
			x.run(5, 2*time.Second, warn)
			return x
		},
	}
	for name, mk := range neg {
		x := mk()
		must(t, x.w.count(sigTERM) == 0 && x.w.count(sigKILL) == 0, "%s: must not kill", name)
	}
}

// shareRig builds the growth-share scenario: group 100 starts at base,
// grows by g over 10 critical polls while unattributed grows by u.
func shareRig(t *testing.T, base, g, u uint64, minShare float64) *rig {
	r := newRig(t, ModePauseKill)
	r.setMinShare(minShare)
	r.tool(100, base, 101)
	r.unattr = gib
	r.run(31, 2*time.Second, normal) // 60s of flat readings before danger
	for i := 0; i < 10; i++ {
		r.grow(100, g/10)
		r.unattr += u / 10
		r.poll(2*time.Second, crit)
	}
	r.run(60, 2*time.Second, crit)
	return r
}

func killed(r *rig) bool { _, ok := r.termAt(); return ok }

func TestKillCausationShareProng(t *testing.T) {
	// Share 60% with unattributed in the denominator: kill.
	r := shareRig(t, 2*gib, 6*gib, 4*gib, 0.1)
	must(t, killed(r), "share 6/(6+4) = 60%% must kill")
	// NEG-20: the unattributed denominator is 8 GB: share 43%: no kill.
	n := shareRig(t, 2*gib, 6*gib, 8*gib, 0.1)
	must(t, !killed(n), "share 6/14 = 43%% must not kill")
	// An invisible 8 GB root consumer with a steady 5 GiB job: share ~0.
	e := shareRig(t, 5*gib, 0, 8*gib, 0.1)
	must(t, !killed(e), "NEG-20: steady job beside an invisible consumer must not be killed")
	// The prong values are asserted directly, not just the outcome.
	share, num, den := e.m.growthShare(buildView(e.lastSnap), keyOf(100, e.groups[100].start))
	must(t, num == 0 && den >= 7*gib && share == 0, "NEG-20 values: share=%v num=%d den=%d", share, num, den)
	// Broken variant: a denominator that leaves out unattributed would see
	// 0/0; with the group's own growth in the control the share would be
	// 100% where the real one is 43%.
	share, num, den = n.m.growthShare(buildView(n.lastSnap), keyOf(100, n.groups[100].start))
	must(t, share > 0.4 && share < 0.5 && num > 5*gib && den > 13*gib, "NEG-20 control values: %v %d %d", share, num, den)
}

func TestKillCausationFloorAndDenominator(t *testing.T) {
	// Below the min share floor (4 GiB at 0.25): paused (it grew 2 GB since
	// danger) with share 100%, but no kill at 3.5 GiB.
	f := shareRig(t, 512<<20, 3*gib, 0, 0.25)
	must(t, f.paused(100), "setup: the group is paused")
	must(t, !killed(f), "below the floor must not kill (footprint %d)", f.groups[100].fp)
	// Control: floor lowered to 0.2 (3.2 GiB) kills.
	c := shareRig(t, 512<<20, 3*gib, 0, 0.2)
	must(t, killed(c), "control: above a lower floor the same series kills")

	// NEG-17: a 0.6 GB rise has a denominator under 1 GB.
	d := shareRig(t, 2*gib, 600<<20, 0, 0.1)
	must(t, !killed(d), "NEG-17: denominator under 1 GB must not kill")
	// Control: a solo 3 GB rise has denominator 3 GB and share 100%.
	s := shareRig(t, 2*gib, 3*gib, 0, 0.1)
	must(t, killed(s), "NEG-17 control: solo 3 GB rise kills")
}

func TestPlateauedGroupOfAnySizeNeverKilled(t *testing.T) {
	for _, size := range []uint64{5 * gib, 10 * gib, 14 * gib} {
		r := shareRig(t, size, 0, 0, 0.1)
		must(t, !killed(r), "%d GiB plateau must never be killed", size/gib)
	}
	// NEG-19: the pressure comes from wired memory: unattributed grows.
	r := shareRig(t, 10*gib, 0, 6*gib, 0.25)
	must(t, !killed(r), "NEG-19: plateaued job under unattributed growth must not be killed")
}

func TestStaleScanBlocksShareProngButNotD4(t *testing.T) {
	mk := func(age time.Duration, d4 bool) *rig {
		var r *rig
		if d4 {
			r = killRig(t, ModePauseKill)
			r.scanAge = age
			r.run(60, 2*time.Second, crit)
			return r
		}
		r = newRig(t, ModePauseKill)
		r.setMinShare(0.1)
		r.scanAge = age
		r.tool(100, 2*gib, 101)
		r.unattr = gib
		r.run(31, 2*time.Second, normal)
		for i := 0; i < 10; i++ {
			r.grow(100, 6*gib/10)
			r.poll(2*time.Second, crit)
		}
		r.run(60, 2*time.Second, crit)
		return r
	}
	must(t, killed(mk(time.Second, false)), "control: a fresh scan lets the share prong kill")
	must(t, !killed(mk(30*time.Second, false)), "a scan older than 2 intervals must fail the share prong")
	must(t, killed(mk(30*time.Second, true)), "D4 does not need a fresh scan")
	// A failed scan (ScanOK false) is as stale as an old one.
	r := newRig(t, ModePauseKill)
	r.setMinShare(0.1)
	r.scanOK = false
	r.tool(100, 2*gib, 101)
	r.run(31, 2*time.Second, normal)
	for i := 0; i < 10; i++ {
		r.grow(100, 6*gib/10)
		r.poll(2*time.Second, crit)
	}
	r.run(60, 2*time.Second, crit)
	must(t, !killed(r), "a failed scan must fail the share prong")
}

func TestGrewTwoGBAloneAndP1AloneNeverKill(t *testing.T) {
	// NEG-15: Chrome +10 GB, a 3 GiB job +2.9 GiB, D1 held 120s: the job
	// may be paused, never killed (share under 50%).
	r := newRig(t, ModePauseKill)
	r.setMinShare(0.1)
	r.tool(100, 3*gib, 101)
	r.inel["chrome"] = 2 * gib
	r.unattr = gib
	r.run(31, 2*time.Second, normal)
	for i := 0; i < 10; i++ {
		r.grow(100, 300<<20)
		r.inel["chrome"] += gib
		r.poll(2*time.Second, crit)
	}
	r.run(60, 2*time.Second, crit)
	must(t, r.w.count(sigTERM) == 0 && r.w.count(sigKILL) == 0, "NEG-15: never killed")
	pauses := r.ev.named("GUARD_PAUSE")
	must(t, len(pauses) == 1, "the job may be paused once, got %d", len(pauses))
	must(t, containsStr(pauses[0].f["signals"].([]string), "cause=grew>=2GB since danger_since"), "the event must name the signals: %v", pauses[0].f["signals"])
	share, _, den := r.m.growthShare(buildView(r.lastSnap), keyOf(100, r.groups[100].start))
	must(t, share < 0.25 && den > 11*gib, "NEG-15 values: share=%v den=%d", share, den)

	// NEG-16: 60 Chrome helpers of 250 MB (one 14 GB aggregate) beside a
	// steady 3 GiB job: the job is not even causal.
	h := newRig(t, ModePauseKill)
	h.setMinShare(0.1)
	h.tool(100, 3*gib, 101)
	h.inel["chrome"] = 14 * gib
	h.run(3, 2*time.Second, normal)
	h.run(60, 2*time.Second, crit)
	must(t, len(h.w.log) == 0, "NEG-16: nothing signalled: %v", h.w.log)

	// NEG-18: 20 aggregates of 0.6 GB, each growing, beside a steady 4 GiB job.
	g := newRig(t, ModePauseKill)
	g.setMinShare(0.1)
	g.tool(100, 4*gib, 101)
	for i := 0; i < 20; i++ {
		g.inel[string(rune('a'+i))] = 300 << 20
	}
	g.run(31, 2*time.Second, normal)
	for i := 0; i < 10; i++ {
		for k := range g.inel {
			g.inel[k] += 30 << 20
		}
		g.poll(2*time.Second, crit)
	}
	g.run(60, 2*time.Second, crit)
	must(t, g.w.count(sigTERM) == 0, "NEG-18: the steady job must never be killed")
}

func containsStr(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func TestGrowthBeforeDetectionStillKillable(t *testing.T) {
	// The culprit grew before danger_since and then plateaued once paused
	// (2026-11-04): killable through its baseline share. The control, with
	// no growth before danger, is not.
	mk := func(pre uint64) *rig {
		r := newRig(t, ModePauseKill)
		r.setMinShare(0.1)
		r.tool(100, 2*gib, 101)
		r.unattr = gib
		r.run(25, 2*time.Second, normal) // flat for 50s
		for i := 0; i < 5; i++ {         // growth in the 10s before danger, at normal pressure
			r.grow(100, pre/5)
			r.poll(2*time.Second, normal)
		}
		r.run(80, 2*time.Second, crit)
		return r
	}
	must(t, killed(mk(6*gib)), "a culprit that grew before detection must be killable via the baseline share")
	must(t, !killed(mk(0)), "control: no growth before or during danger, no kill")
}

func TestBaselineRules(t *testing.T) {
	since := t0.Add(2 * time.Minute)
	base := since.Add(-time.Minute)
	pts := func(at time.Time, vals ...uint64) []Point {
		var p []Point
		for i, v := range vals {
			p = append(p, Point{At: at.Add(time.Duration(i) * 2 * time.Second), Bytes: v})
		}
		return p
	}
	// Culprit first seen after danger_since: its leader started after the
	// baseline, so it is 0 and its whole footprint is growth.
	born := &Term{Key: "pg:1", Group: &Group{LeaderStart: base.Add(30 * time.Second)}, Series: pts(since.Add(5*time.Second), 20*gib)}
	must(t, baselineFor(born, base, since) == 0, "a culprit born after the baseline starts at 0")
	// A big job first seen mid-episode (older than the baseline) uses its
	// first observed value, so it does not count as 100% growth.
	old := &Term{Key: "pg:2", Group: &Group{LeaderStart: base.Add(-time.Hour)}, Series: pts(since.Add(10*time.Second), 9*gib, 10*gib)}
	must(t, baselineFor(old, base, since) == 9*gib, "a big job first seen mid-episode takes its first observed value")
	// With a reading near the baseline, that reading is used.
	seen := &Term{Key: "pg:3", Group: &Group{LeaderStart: base.Add(-time.Hour)}, Series: pts(base.Add(-2*time.Second), 3*gib, 4*gib, 5*gib)}
	must(t, baselineFor(seen, base, since) == 4*gib, "the reading nearest the baseline instant: got %d", baselineFor(seen, base, since))
	// A member that started after the baseline, with no reading in window.
	mem := &Term{Key: "pg:4", Group: &Group{LeaderStart: base.Add(-time.Hour), Members: []Member{{PID: 1, Start: base.Add(-time.Hour)}, {PID: 9, Start: base.Add(time.Second)}}}, Series: pts(since.Add(4*time.Second), 7*gib)}
	must(t, baselineFor(mem, base, since) == 0, "a member born after the baseline gives 0")
	// An aggregate with no reading in the window uses its first value.
	agg := &Term{Key: "inel:x", Series: pts(since.Add(4*time.Second), 6*gib, 7*gib)}
	must(t, baselineFor(agg, base, since) == 6*gib, "an aggregate first seen mid-episode: first observed")
}

func TestChromeGrowthBeforeDangerCountsInDenominator(t *testing.T) {
	// NEG-15 variant: Chrome grows 10 GB in the 60s before danger_since
	// while the job grows 3 GB during danger: the share against the
	// shared baseline is small. Measuring from danger_since (the broken
	// variant) would give the job 100%.
	r := newRig(t, ModePauseKill)
	r.setMinShare(0.1)
	r.tool(100, 2*gib, 101)
	r.inel["chrome"] = 2 * gib
	r.unattr = gib
	r.run(25, 2*time.Second, normal)
	for i := 0; i < 5; i++ {
		r.inel["chrome"] += 2 * gib
		r.poll(2*time.Second, normal)
	}
	for i := 0; i < 10; i++ {
		r.grow(100, 300<<20)
		r.poll(2*time.Second, crit)
	}
	r.run(60, 2*time.Second, crit)
	must(t, !killed(r), "Chrome's pre-danger growth must dilute the share")
	v := buildView(r.lastSnap)
	share, _, _ := r.m.growthShare(v, keyOf(100, r.groups[100].start))
	// Broken variant: every term measured from danger_since.
	ep := r.m.State().Episode
	var num, den uint64
	for i := range v.terms {
		d := pos(fpOf(&v.terms[i]), ep.DangerBase[v.terms[i].Key])
		den += d
		if v.terms[i].Key == keyOf(100, r.groups[100].start) {
			num = d
		}
	}
	must(t, share < 0.5, "shared-baseline share=%v", share)
	must(t, float64(num)/float64(den) >= 0.5, "control: the danger_since baseline would give %v", float64(num)/float64(den))
}
