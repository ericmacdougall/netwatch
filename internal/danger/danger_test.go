package danger

import (
	"testing"
	"time"

	"github.com/ericmacdougall/netwatch/internal/resources"
)

const (
	gib = uint64(1) << 30
	ram = 16 * gib
	pg  = uint64(4096)
)

var t0 = time.Date(2026, 11, 4, 16, 0, 0, 0, time.UTC)

// sys builds a reading with the given headroom (bytes) and pressure.
func sys(at time.Time, head uint64, p resources.Level) resources.System {
	return resources.System{
		At: at, RAM: ram, PageSize: pg,
		Free: head / pg, Pressure: p,
		PagesCompressedLimit: 1000, SegmentLimit: 1000,
		DiskFree: 200 * gib,
	}
}

func ser(start time.Time, step time.Duration, vals ...uint64) []Point {
	out := make([]Point, len(vals))
	for i, v := range vals {
		out[i] = Point{At: start.Add(time.Duration(i) * step), Bytes: v}
	}
	return out
}

// CR-1: headroom has no compressor-capacity term. brokenHeadroom is the
// naive variant that adds unused compressor capacity; the AC-5 arithmetic
// (headroom < 0.95 x 16 GiB on a 16 GiB host) must fail against it.
func brokenHeadroom(s resources.System) uint64 {
	h := (s.Free + s.Speculative + s.Purgeable + s.Inactive) * s.PageSize
	if s.PagesCompressedLimit > s.PagesCompressed {
		h += (s.PagesCompressedLimit - s.PagesCompressed) * s.PageSize
	}
	return h // the naive variant also forgets the RAM clamp
}

func TestHeadroomNoCompressorTermAC5Arithmetic(t *testing.T) {
	s := resources.System{
		RAM: ram, PageSize: 4096,
		Free: 100000, Speculative: 5000, Purgeable: 20000, Inactive: 600000,
		PagesCompressed: 1000, PagesCompressedLimit: 6457536, // ~24.6 GiB of capacity
	}
	limit := ram / 100 * 95
	if got := Headroom(s); got >= limit {
		t.Fatalf("headroom %d must be under 0.95 x RAM (%d)", got, limit)
	}
	if want := (100000 + 5000 + 20000 + 600000) * uint64(4096); Headroom(s) != want {
		t.Fatalf("headroom = %d, want %d", Headroom(s), want)
	}
	// Failing control: the compressor-capacity variant breaks the arithmetic.
	if brokenHeadroom(s) < limit {
		t.Fatalf("control is vacuous: the broken variant also satisfies the bound")
	}
	// The clamp holds even for absurd page counts.
	s.Free = 1 << 40
	if Headroom(s) != ram {
		t.Fatalf("headroom not clamped to RAM")
	}
}

func TestD2Table(t *testing.T) {
	cases := []struct {
		name      string
		pc, lim   uint64
		seg, slim uint64
		want      bool
	}{
		{"pages 98% (2026-11-04)", 6328845, 6457536, 0, 0, true},
		{"pages exactly 85%", 85, 100, 0, 100, true},
		{"just under 85%", 849, 1000, 0, 1000, false},
		{"segments dominate", 10, 100, 90, 100, true},
		{"no limits supplied", 5, 0, 5, 0, false},
	}
	for _, c := range cases {
		s := resources.System{PagesCompressed: c.pc, PagesCompressedLimit: c.lim, Segments: c.seg, SegmentLimit: c.slim}
		if got := D2(Defaults(), s); got != c.want {
			t.Errorf("%s: D2=%v want %v (frac %.3f)", c.name, got, c.want, CompressorFrac(s))
		}
	}
}

func TestD3Table(t *testing.T) {
	cases := []struct {
		name       string
		swap, disk uint64
		want       bool
	}{
		{"85% exactly", 85, 15, true},
		{"just under", 84, 16, false},
		{"no swap no disk", 0, 0, false},
		{"plenty of disk", 10, 1000, false},
	}
	for _, c := range cases {
		s := resources.System{SwapUsed: c.swap, DiskFree: c.disk}
		if got := D3(Defaults(), s); got != c.want {
			t.Errorf("%s: D3=%v want %v", c.name, got, c.want)
		}
	}
}

func crit(n int, step time.Duration) []resources.System {
	var r []resources.System
	for i := 0; i < n; i++ {
		r = append(r, sys(t0.Add(time.Duration(i)*step), 5*gib, resources.LevelCritical))
	}
	return r
}

func TestD1Table(t *testing.T) {
	cfg := Defaults()
	fast := []GroupSeries{{PGID: 7, Series: ser(t0, 10*time.Second, 1*gib, 2*gib)}} // 6 GiB/min
	slow := []GroupSeries{{PGID: 7, Series: ser(t0, 10*time.Second, 1*gib, 1*gib+10<<20)}}
	cases := []struct {
		name string
		r    []resources.System
		d5   bool
		g    []GroupSeries
		want bool
	}{
		{"one critical poll alone", crit(1, 2*time.Second), false, nil, false},
		{"two critical polls", crit(2, 2*time.Second), false, nil, true},
		{"one critical + D5", crit(1, 2*time.Second), true, nil, true},
		{"one critical + fast growth", crit(1, 2*time.Second), false, fast, true},
		{"one critical + slow growth", crit(1, 2*time.Second), false, slow, false},
		{"critical then warn", append(crit(1, 2*time.Second), sys(t0.Add(2*time.Second), 5*gib, resources.LevelWarn)), false, nil, false},
		{"D5 with normal pressure is never sufficient", []resources.System{sys(t0, 5*gib, resources.LevelNormal)}, true, nil, false},
		{"warn then critical is one critical poll", []resources.System{sys(t0, gib, resources.LevelWarn), sys(t0.Add(2*time.Second), gib, resources.LevelCritical)}, false, nil, false},
	}
	for _, c := range cases {
		if got := D1(cfg, c.r, c.d5, c.g); got != c.want {
			t.Errorf("%s: D1=%v want %v", c.name, got, c.want)
		}
	}
}

func TestD4Table(t *testing.T) {
	cfg := Defaults()
	big := 13 * gib // above 0.75 x 16 = 12 GiB
	grow := ser(t0, 10*time.Second, big-3*gib, big)
	flat := ser(t0, 10*time.Second, big, big)
	smallGrow := ser(t0, 10*time.Second, 2*gib, 5*gib)
	cases := []struct {
		name string
		p    resources.Level
		g    []Point
		want bool
	}{
		{"big, growing, warn", resources.LevelWarn, grow, true},
		{"big, growing, critical", resources.LevelCritical, grow, true},
		{"big, growing, normal pressure", resources.LevelNormal, grow, false},
		{"big, plateaued, warn", resources.LevelWarn, flat, false},
		{"small, growing fast, warn", resources.LevelWarn, smallGrow, false},
	}
	for _, c := range cases {
		got := len(D4(cfg, sys(t0, 2*gib, c.p), []GroupSeries{{PGID: 9, Series: c.g}})) == 1
		if got != c.want {
			t.Errorf("%s: D4=%v want %v", c.name, got, c.want)
		}
	}
}

func TestP1AndCorroboration(t *testing.T) {
	cfg := Defaults()
	// 0.5 GB/s ramp, 5 GiB group (>= 0.25 x 16 = 4 GiB), headroom 3 GiB:
	// 0.5 x 15s = 7.5 GB >= 3 GiB, so P1 fires.
	g := []GroupSeries{{PGID: 5, Series: ser(t0, 2*time.Second, 4*gib, 5*gib)}}
	s := sys(t0.Add(2*time.Second), 3*gib, resources.LevelNormal)
	if len(P1(cfg, s, g)) != 1 {
		t.Fatalf("P1 should fire")
	}
	// Control: plenty of headroom, no P1.
	if len(P1(cfg, sys(t0, 12*gib, resources.LevelNormal), g)) != 0 {
		t.Fatalf("P1 fired with 12 GiB of headroom")
	}
	// Control: below the min-share floor.
	small := []GroupSeries{{PGID: 5, Series: ser(t0, 2*time.Second, 1*gib, 3*gib)}}
	if len(P1(cfg, s, small)) != 0 {
		t.Fatalf("P1 fired below the min share floor")
	}

	corr := []struct {
		name string
		mod  func(*resources.System)
		want bool
	}{
		{"normal pressure, 3 GiB headroom", func(*resources.System) {}, false},
		{"critical pressure", func(s *resources.System) { s.Pressure = resources.LevelCritical }, true},
		{"warn + headroom 1 GiB (< 1.28)", func(s *resources.System) { s.Pressure = resources.LevelWarn; s.Free = gib / pg }, true},
		{"warn + headroom 3 GiB", func(s *resources.System) { s.Pressure = resources.LevelWarn }, false},
		{"A7: low headroom alone, pressure normal", func(s *resources.System) { s.Free = gib / pg }, false},
		{"D2", func(s *resources.System) { s.PagesCompressed = 900 }, true},
		{"D3", func(s *resources.System) { s.SwapUsed = 90 * gib; s.DiskFree = 10 * gib }, true},
	}
	for _, c := range corr {
		x := s
		c.mod(&x)
		if got := P1Corroborated(cfg, x); got != c.want {
			t.Errorf("%s: corroborated=%v want %v", c.name, got, c.want)
		}
	}
}

// brokenCorroborate is the variant A7 replaced: headroom alone corroborates.
func brokenCorroborate(cfg Config, s resources.System) bool {
	return P1Corroborated(cfg, s) || float64(Headroom(s)) < cfg.HeadroomFrac*float64(s.RAM)
}

// NEG (A7): a low-headroom healthy series is never flagged.
func TestLowHeadroomHealthySeriesNeverFlagged(t *testing.T) {
	d := Detector{Cfg: Defaults()}
	flaggedBroken := false
	for i := 0; i < 120; i++ {
		at := t0.Add(time.Duration(i) * 2 * time.Second)
		s := sys(at, gib, resources.LevelNormal) // 1 GiB headroom (< 1.28 GiB), pressure normal
		fp := (4 + uint64(i)/20) * gib           // a growing 4+ GiB agent group
		g := []GroupSeries{{PGID: 3, Series: ser(at.Add(-2*time.Second), 2*time.Second, fp-200<<20, fp)}}
		sig := d.Observe(s, false, g)
		if sig.Danger {
			t.Fatalf("poll %d: healthy low-headroom host flagged as danger: %+v", i, sig)
		}
		if brokenCorroborate(d.Cfg, s) && sig.P1 {
			flaggedBroken = true
		}
	}
	if !flaggedBroken {
		t.Fatalf("control is vacuous: headroom-only variant never flags this series")
	}
}

func TestClear(t *testing.T) {
	cfg := Defaults()
	series := func(n int, mod func(i int, s *resources.System)) []resources.System {
		var r []resources.System
		for i := 0; i < n; i++ {
			s := sys(t0.Add(time.Duration(i)*5*time.Second), 5*gib, resources.LevelNormal)
			s.SwapUsed, s.CompressorBytes = 2*gib, 3*gib
			if mod != nil {
				mod(i, &s)
			}
			r = append(r, s)
		}
		return r
	}
	cases := []struct {
		name string
		r    []resources.System
		want bool
	}{
		{"35s normal and flat", series(8, nil), true},
		{"25s normal is not enough", series(6, nil), false},
		{"warn inside the hold restarts it", series(12, func(i int, s *resources.System) {
			if i == 5 {
				s.Pressure = resources.LevelWarn
			}
		}), false},
		{"swap rising", series(8, func(i int, s *resources.System) { s.SwapUsed += uint64(i) * 200 << 20 }), false},
		{"compressor rising", series(8, func(i int, s *resources.System) { s.CompressorBytes += uint64(i) * 200 << 20 }), false},
		{"swap falling is fine", series(8, func(i int, s *resources.System) { s.SwapUsed -= uint64(i) * 100 << 20 }), true},
		{"last reading critical", series(8, func(i int, s *resources.System) {
			if i == 7 {
				s.Pressure = resources.LevelCritical
			}
		}), false},
	}
	for _, c := range cases {
		if got := Clear(cfg, c.r); got != c.want {
			t.Errorf("%s: Clear=%v want %v", c.name, got, c.want)
		}
	}
	// Spec: level thresholds never prevent a clear. D2 high but stable at
	// normal pressure still clears.
	r := series(8, func(i int, s *resources.System) { s.PagesCompressed = 990 })
	if !Clear(cfg, r) {
		t.Errorf("a stable high compressor level must not block the clear")
	}
}

func TestDetectorClearHoldRestartsAfterCrash(t *testing.T) {
	run := func(d *Detector, from, n int) Signals {
		var sig Signals
		for i := from; i < from+n; i++ {
			sig = d.Observe(sys(t0.Add(time.Duration(i)*5*time.Second), 5*gib, resources.LevelNormal), false, nil)
		}
		return sig
	}
	d := &Detector{Cfg: Defaults()}
	if !run(d, 0, 8).Clear {
		t.Fatalf("clear expected after 35s of normal")
	}
	d2 := &Detector{Cfg: Defaults()} // the restarted daemon has no history
	if run(d2, 8, 3).Clear {
		t.Fatalf("clear must not hold right after a restart")
	}
	if !run(d2, 11, 5).Clear {
		t.Fatalf("clear expected 30s after the restart")
	}
}

func TestUsedIncludesSwapA6(t *testing.T) {
	s := resources.System{
		RAM: ram, PageSize: pg, Free: 1000, CompressorBytes: gib,
		PagesCompressed: (3 * gib) / pg, SwapUsed: 4 * gib,
	}
	with, without := Used(s, true), Used(s, false)
	if with != without+4*gib {
		t.Fatalf("swap must be in used by default: with=%d without=%d", with, without)
	}
	fp := 6 * gib
	// An agent group's share of "used": removing the swap term raises it.
	shareWith := float64(fp) / float64(with)
	shareWithout := float64(fp) / float64(without)
	if !(shareWithout > shareWith) {
		t.Fatalf("direction not pinned: %.3f vs %.3f", shareWithout, shareWith)
	}
	if Unattributed(s, 100*gib, true) != 0 {
		t.Fatalf("unattributed must clamp at 0")
	}
}

func TestDetectorDangerCombination(t *testing.T) {
	d := Detector{Cfg: Defaults()}
	// D4: 13 GiB, +3 GiB in 10s, warn.
	g := []GroupSeries{{PGID: 11, Series: ser(t0, 10*time.Second, 10*gib, 13*gib)}}
	sig := d.Observe(sys(t0.Add(10*time.Second), 2*gib, resources.LevelWarn), false, g)
	if !sig.Danger || len(sig.D4PGIDs) != 1 || sig.D4PGIDs[0] != 11 {
		t.Fatalf("expected D4 danger, got %+v", sig)
	}
	// Same series with normal pressure: no D4 and no danger.
	d = Detector{Cfg: Defaults()}
	sig = d.Observe(sys(t0.Add(10*time.Second), 2*gib, resources.LevelNormal), false, g)
	if sig.Danger {
		t.Fatalf("normal pressure must not be danger: %+v", sig)
	}
}

func TestClampBounds(t *testing.T) {
	c := Defaults()
	c.MinShare, c.GroupRAMFrac, c.HeadroomFrac, c.P1Horizon = 5, 0.01, 2, time.Hour
	w := c.Clamp()
	if len(w) != 4 || c.MinShare != 1.0 || c.GroupRAMFrac != 0.25 || c.HeadroomFrac != 0.95 || c.P1Horizon != 120*time.Second {
		t.Fatalf("clamp wrong: %v %+v", w, c)
	}
	d := Defaults()
	if len(d.Clamp()) != 0 {
		t.Fatalf("defaults must not warn")
	}
}
