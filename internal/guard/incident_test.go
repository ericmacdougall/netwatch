package guard

import (
	"testing"
	"time"
)

// The 2026-11-04 incident shape: a Python group in a tool shell ramps to
// about 65 GiB in about 11s on a 16 GiB host, the compressor reaches 98%
// and pressure goes critical. Readings are step-held between the 2s polls.
// The pressure and compressor times follow the first non-idle jetsam
// snapshot (16:06:53.6Z).
func incidentRig(t *testing.T, trackerOn bool, tweak func(*Config)) *rig {
	r := newRig(t, ModePauseKill)
	if tweak != nil {
		tweak(&r.cfg)
		r.m.cfg = r.cfg
	}
	day := time.Date(2026, 11, 4, 16, 6, 38, 0, time.UTC)
	r.at = day
	pyStart := time.Date(2026, 11, 4, 16, 6, 42, 0, time.UTC)
	added := false
	for r.at.Before(time.Date(2026, 11, 4, 16, 8, 20, 0, time.UTC)) {
		next := r.at.Add(2 * time.Second)
		sec := next.Sub(day).Seconds() + 38 // seconds past 16:06:00
		if trackerOn && !added && !next.Before(pyStart) {
			r.addGroup(gdef{pgid: 10934, start: pyStart, tier: TierTool, envOK: true, allow: true, cmd: "python3", ver: "2.1.318"}, 10935)
			r.w.procs[10935].ignoreTerm = true
			added = true
		}
		if added {
			f := (next.Sub(pyStart)).Seconds() / 11
			if f > 1 {
				f = 1
			}
			r.groups[10934].fp = uint64(f * float64(65*gib))
		}
		lvl := normal
		r.comp = 0
		r.d5 = false
		switch {
		case sec >= 54:
			lvl = crit
			r.comp = 980 // 98% of the compressor limit
			r.d5 = sec < 56
		case sec >= 46:
			lvl = warn
		}
		r.poll(2*time.Second, lvl)
	}
	return r
}

func hms(s string) time.Time {
	tt, err := time.Parse("15:04:05", s)
	if err != nil {
		panic(err)
	}
	return time.Date(2026, 11, 4, tt.Hour(), tt.Minute(), tt.Second(), 0, time.UTC)
}

func TestIncidentShapedSeriesPausesAndKillsOnEachPath(t *testing.T) {
	type path struct {
		name string
		cfg  func(*Config)
		lo   string // SIGTERM window
		hi   string
	}
	paths := []path{
		// Path A: 60s after the first critical poll (16:06:54).
		{"A", func(c *Config) { c.DisablePathB, c.DisableFast = true, true }, "16:07:53", "16:07:56"},
		// Path B: 20s after compressor >= 95% with pressure >= warn.
		{"B", func(c *Config) { c.DisablePathA, c.DisableFast = true, true }, "16:07:12", "16:07:16"},
		// A2 fast path: two polls at >= 95%: 16:06:54 and 16:06:56.
		{"fast", func(c *Config) { c.DisablePathA, c.DisablePathB = true, true }, "16:06:54", "16:06:58"},
	}
	for _, p := range paths {
		r := incidentRig(t, true, p.cfg)
		pause, ok := r.first(ActPause, 10934)
		must(t, ok, "path %s: must pause", p.name)
		must(t, !pause.Before(hms("16:06:42")) && !pause.After(hms("16:06:56")), "path %s: pause at %v outside [16:06:42, 16:06:56]", p.name, pause)
		term, ok := r.first(ActTerm, 10934)
		must(t, ok, "path %s: must send SIGTERM", p.name)
		must(t, !term.Before(hms(p.lo)) && !term.After(hms(p.hi)), "path %s: SIGTERM at %v, want [%s, %s]", p.name, term.Format("15:04:05"), p.lo, p.hi)
		kill, ok := r.first(ActKill, 10934)
		must(t, ok && kill.Sub(term) <= 6*time.Second, "path %s: SIGKILL within 5s of SIGTERM (+%v)", p.name, kill.Sub(term))
		must(t, r.w.noneAlive(), "path %s: nothing may survive", p.name)
		t.Logf("path %s: pause %s SIGTERM %s SIGKILL %s", p.name, pause.Format("15:04:05"), term.Format("15:04:05"), kill.Format("15:04:05"))
	}
	// All paths enabled: the fast path wins.
	r := incidentRig(t, true, nil)
	term, _ := r.first(ActTerm, 10934)
	must(t, !term.After(hms("16:06:58")), "with every path on SIGTERM at %v, want <= 16:06:58", term)

	// Control: with the tracker disabled (no group seen) nothing is paused.
	c := incidentRig(t, false, nil)
	_, ok := c.first(ActPause, 0)
	must(t, !ok && c.w.count(sigSTOP) == 0, "without the tracker there is no pause")
	_, ok = c.first(ActTerm, 0)
	must(t, !ok, "without the tracker there is no kill")
}

func TestIncidentGuardOffAndAlertTakeNoAction(t *testing.T) {
	for _, m := range []Mode{ModeOff, ModeAlert} {
		r := incidentRig(t, true, func(c *Config) { c.Mode = m })
		must(t, len(r.w.log) == 0, "mode %s: no signals", m)
	}
}
