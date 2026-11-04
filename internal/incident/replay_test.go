package incident

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ericmacdougall/netwatch/internal/jetsam"
	"github.com/ericmacdougall/netwatch/internal/resources"
)

const (
	jetsamFixture = "../jetsam/testdata/incident"
	logsFixture   = "testdata/logs"
)

func mt(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func collectFixture(t *testing.T) *Report {
	t.Helper()
	rep, err := Collect(Options{LogDir: logsFixture, JetsamDir: jetsamFixture, DiagDirs: []string{jetsamFixture}, Now: mt(t, "2026-11-04T17:00:00Z")})
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func checkByName(t *testing.T, cs []Check, prefix string) Check {
	t.Helper()
	for _, c := range cs {
		if strings.HasPrefix(c.Name, prefix) {
			return c
		}
	}
	t.Fatalf("no check starting %q in %+v", prefix, cs)
	return Check{}
}

func TestReplayAC6Bounds(t *testing.T) {
	rep := collectFixture(t)
	r := ReplayGuard(ReplayInputFrom(rep, ModePauseKill))
	if !r.Verified {
		var b bytes.Buffer
		r.Render(&b)
		t.Fatalf("replay not verified:\n%s", b.String())
	}
	obsA := rangeFor(r.Ranges, "observed (linear 0 to peak over 11s)", VariantPathA.Name)
	obsF := rangeFor(r.Ranges, "observed (linear 0 to peak over 11s)", VariantFast.Name)
	// Absolute bounds from the spec, on the incident's own times.
	if obsA.PauseMin.Before(mt(t, "2026-11-04T16:06:42Z")) || obsA.PauseMax.After(mt(t, "2026-11-04T16:06:56Z")) {
		t.Errorf("pause %s..%s outside [16:06:42Z, 16:06:56Z]", obsA.PauseMin, obsA.PauseMax)
	}
	if obsA.TermMin.Before(mt(t, "2026-11-04T16:07:53.6Z").Add(-50*time.Millisecond)) || obsA.TermMax.After(mt(t, "2026-11-04T16:07:56Z")) {
		t.Errorf("no-fast SIGTERM %s..%s outside [16:07:53.6Z, 16:07:56Z]", obsA.TermMin, obsA.TermMax)
	}
	if obsA.KillPath != "A" {
		t.Errorf("no-fast kill path %q", obsA.KillPath)
	}
	if obsF.TermMax.After(mt(t, "2026-11-04T16:06:58Z")) {
		t.Errorf("fast SIGTERM %s after 16:06:58Z", obsF.TermMax)
	}
	if obsF.KillPath != "A2-fast" {
		t.Errorf("fast kill path %q", obsF.KillPath)
	}
	if !r.Onset.Equal(mt(t, "2026-11-04T16:06:53.635Z")) {
		t.Errorf("onset %s", r.Onset)
	}
	if r.Culprit == nil || r.Culprit.PID != 10934 || r.Culprit.GiB < 64.9 || r.Culprit.GiB > 66 {
		t.Errorf("culprit %+v", r.Culprit)
	}
}

func TestReplayPrintsAssumptionsMarginsAndLimitation(t *testing.T) {
	rep := collectFixture(t)
	r := ReplayGuard(ReplayInputFrom(rep, ModePauseKill))
	var b bytes.Buffer
	r.Render(&b)
	out := b.String()
	for _, want := range []string{
		"step-held", "D4 is latched", "first non-idle jetsam snapshot",
		"first jetsam report write", "last jetsam report write", "host reset (ResetCounter-2026-11-04-163509.diag)",
		"cannot prove real lead time", "path A only", "A2 fast path",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q", want)
		}
	}
	// Both margins exist and are not asserted: the snapshot margin is
	// negative (jetsam first) for the fast path, as A2 warns.
	var snap, write *Margin
	for i := range r.Margins {
		m := &r.Margins[i]
		if strings.HasPrefix(m.Action, "SIGTERM, with fast path") {
			switch m.Label {
			case "first non-idle jetsam snapshot":
				snap = m
			case "first jetsam report write":
				write = m
			}
		}
	}
	if snap == nil || write == nil {
		t.Fatalf("margins missing: %+v", r.Margins)
	}
	if snap.Margin >= 0 {
		t.Errorf("fast path cannot beat the first snapshot; margin %s", snap.Margin)
	}
	js, err := r.JSON()
	if err != nil || !json.Valid(js) {
		t.Fatalf("json: %v", err)
	}
}

func TestReplayControls(t *testing.T) {
	rep := collectFixture(t)
	in := ReplayInputFrom(rep, ModePauseKill)

	t.Run("controls inside the report pass", func(t *testing.T) {
		r := ReplayGuard(in)
		for _, c := range r.Controls {
			if c.Status != "pass" {
				t.Errorf("control %+v", c)
			}
		}
		if len(r.Controls) < 2 {
			t.Fatalf("controls missing: %+v", r.Controls)
		}
	})
	t.Run("guard off takes no action", func(t *testing.T) {
		off := in
		off.Mode = ModeOff
		r := ReplayGuard(off)
		if rg := rangeFor(r.Ranges, "observed (linear 0 to peak over 11s)", VariantFast.Name); !rg.PauseMin.IsZero() || rg.Killed {
			t.Errorf("action in off mode: %+v", rg)
		}
		if r.Verified {
			t.Error("a replay with no action must not verify")
		}
	})
	t.Run("pause mode never kills", func(t *testing.T) {
		p := in
		p.Mode = ModePause
		r := ReplayGuard(p)
		if rg := rangeFor(r.Ranges, "observed (linear 0 to peak over 11s)", VariantFast.Name); rg.PauseMin.IsZero() || rg.Killed {
			t.Errorf("pause mode: %+v", rg)
		}
	})
	t.Run("tracker disabled breaks the pause bound", func(t *testing.T) {
		d := in
		d.NewDecider = func(m Mode, v Variant, _ bool) Decider { return NewReplayRules(m, v, true) }
		r := ReplayGuard(d)
		if c := checkByName(t, r.Checks, "pause for the observed ramp"); c.Status == "pass" {
			t.Errorf("pause bound passed without the tracker: %+v", c)
		}
	})
	t.Run("unknown attribution is not eligible", func(t *testing.T) {
		u := in
		u.AgentLabel = ""
		r := ReplayGuard(u)
		if r.Verified {
			t.Error("verified without attribution")
		}
		if !strings.Contains(strings.Join(r.Notes, "|"), "attribution unknown, not eligible") {
			t.Errorf("notes %v", r.Notes)
		}
		if rg := rangeFor(r.Ranges, "observed (linear 0 to peak over 11s)", VariantFast.Name); !rg.PauseMin.IsZero() {
			t.Errorf("paused an unattributed group: %+v", rg)
		}
	})
	t.Run("missing evidence is not verified", func(t *testing.T) {
		r := ReplayGuard(ReplayInput{})
		if r.Verified || len(r.Checks) == 0 || r.Checks[0].Status != "not verified" {
			t.Errorf("%+v", r)
		}
		if !strings.Contains(strings.Join(r.Notes, "|"), "not verified") {
			t.Errorf("notes %v", r.Notes)
		}
	})
}

// A step ramp has no D4 (no growth after the step), so it is paused by D1
// and killed on the share prong; the fast path never applies.
func TestReplayStepRampNoFastPath(t *testing.T) {
	r := ReplayGuard(ReplayInputFrom(collectFixture(t), ModePauseKill))
	rg := rangeFor(r.Ranges, "step (20 GiB in 1s)", VariantFast.Name)
	if rg.PauseMin.IsZero() || !rg.Killed {
		t.Fatalf("step ramp: %+v", rg)
	}
	if rg.KillPath == "A2-fast" {
		t.Error("fast path requires D4, which a plateaued step does not latch")
	}
}

// ---- A2 fast-path rules, each against its naive variant ----

func at(sec float64) time.Time {
	return time.Date(2026, 11, 4, 16, 0, 0, 0, time.UTC).Add(time.Duration(sec * float64(time.Second)))
}

func rd(sec float64, bytes uint64, growth float64, p resources.Level, comp float64) Reading {
	return Reading{At: at(sec), RAM: 16 * gib, GroupBytes: bytes, GrowthPerMin: growth, GrowthSinceBaseline: bytes,
		Pressure: p, CompressorFrac: comp, Eligible: true}
}

func kills(as []Action) bool {
	for _, a := range as {
		if a.Kind == ActSigterm {
			return true
		}
	}
	return false
}

func feed(d *ReplayRules, rs ...Reading) (killed bool, path string) {
	for _, r := range rs {
		for _, a := range d.Poll(r) {
			if a.Kind == ActSigterm {
				return true, a.Path
			}
		}
	}
	return false, ""
}

const big = 20 * gib

func TestFastPathRules(t *testing.T) {
	grow := float64(10 * gib)
	warn, crit := resources.LevelWarn, resources.LevelCritical
	newFast := func(m Mode) *ReplayRules { return NewReplayRules(m, VariantFast, false) }
	// Control: D4 latched and paused, 95%+ on two consecutive polls kills.
	t.Run("control kills", func(t *testing.T) {
		k, path := feed(newFast(ModePauseKill), rd(0, big, grow, warn, 0.98), rd(2, big, grow, warn, 0.98))
		if !k || path != "A2-fast" {
			t.Fatalf("killed=%v path=%q", k, path)
		}
	})
	cases := []struct {
		name string
		mode Mode
		rs   []Reading
	}{
		{"95% without D4", ModePauseKill, []Reading{
			rd(0, big, 0, crit, 0.98), rd(2, big, 0, crit, 0.98), rd(4, big, 0, crit, 0.98)}},
		{"single 95% poll", ModePauseKill, []Reading{rd(0, big, grow, warn, 0.98)}},
		{"gap over 6s between the two polls", ModePauseKill, []Reading{
			rd(0, big, grow, warn, 0.98), rd(7, big, grow, warn, 0.98)}},
		{"compressor below 95% on the second poll", ModePauseKill, []Reading{
			rd(0, big, grow, warn, 0.98), rd(2, big, grow, warn, 0.90)}},
		{"normal pressure", ModePauseKill, []Reading{
			rd(0, big, grow, resources.LevelNormal, 0.98), rd(2, big, grow, resources.LevelNormal, 0.98)}},
		{"pause mode", ModePause, []Reading{
			rd(0, big, grow, warn, 0.98), rd(2, big, grow, warn, 0.98)}},
		{"ineligible group", ModePauseKill, []Reading{
			withEligible(rd(0, big, grow, warn, 0.98), false), withEligible(rd(2, big, grow, warn, 0.98), false)}},
		{"footprint under min share", ModePauseKill, []Reading{
			rd(0, 2*gib, grow, warn, 0.98), rd(2, 2*gib, grow, warn, 0.98)}},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			// Variant has no path A or B hold that could fire in 2 polls.
			if k, path := feed(newFast(c.mode), c.rs...); k {
				t.Fatalf("killed via %s", path)
			}
		})
	}
	t.Run("not yet paused: fast path needs a paused group", func(t *testing.T) {
		d := newFast(ModePauseKill)
		// Not causal (footprint under min share) so never paused, hence no kill
		// even though compressor is hot and D4-like growth is present.
		if k, _ := feed(d, rd(0, 3*gib, grow, warn, 0.98), rd(2, 3*gib, grow, warn, 0.98), rd(4, 3*gib, grow, warn, 0.98)); k {
			t.Fatal("killed an unpaused group")
		}
	})
}

func withEligible(r Reading, e bool) Reading { r.Eligible = e; return r }

func TestPathARules(t *testing.T) {
	crit := resources.LevelCritical
	run := func(rs []Reading) bool {
		k, _ := feed(NewReplayRules(ModePauseKill, VariantPathA, false), rs...)
		return k
	}
	var steady []Reading
	for i := 0; i <= 30; i++ {
		steady = append(steady, rd(float64(2*i), big, float64(10*gib), crit, 0.5))
	}
	if !run(steady) {
		t.Fatal("control: 31 critical polls over 60s must kill")
	}
	t.Run("a normal poll restarts the window", func(t *testing.T) {
		rs := append([]Reading(nil), steady...)
		rs[20] = rd(40, big, float64(10*gib), resources.LevelNormal, 0.5)
		if run(rs) {
			t.Error("killed across a normal poll")
		}
	})
	t.Run("a gap over 6s restarts the window", func(t *testing.T) {
		rs := append([]Reading(nil), steady[:15]...)
		for i := 15; i <= 30; i++ {
			rs = append(rs, rd(float64(2*i)+8, big, float64(10*gib), crit, 0.5))
		}
		if run(rs) {
			t.Error("killed across a stall")
		}
	})
	t.Run("too few polls", func(t *testing.T) {
		var rs []Reading
		for i := 0; i <= 12; i++ {
			rs = append(rs, rd(float64(5*i+1), big, float64(10*gib), crit, 0.5)) // 5s cadence: 13 polls in 60s
		}
		if run(rs) {
			t.Error("killed with fewer than 25 polls")
		}
	})
	t.Run("plateaued group without D4 or growth share is never killed", func(t *testing.T) {
		var rs []Reading
		for i := 0; i <= 40; i++ {
			r := rd(float64(2*i), big, 0, crit, 0.5)
			r.GrowthSinceBaseline = 0
			rs = append(rs, r)
		}
		if run(rs) {
			t.Error("killed a plateaued group")
		}
	})
}

// Seam: the replay can be driven by any Decider.
type neverDecider struct{ polls int }

func (n *neverDecider) Poll(Reading) []Action { n.polls++; return nil }

func TestDeciderSeam(t *testing.T) {
	nd := &neverDecider{}
	in := ReplayInputFrom(collectFixture(t), ModePauseKill)
	in.NewDecider = func(Mode, Variant, bool) Decider { return nd }
	r := ReplayGuard(in)
	if nd.polls == 0 {
		t.Fatal("injected decider was never polled")
	}
	if r.Verified {
		t.Error("a decider that never acts must not verify")
	}
}

// Optional: the real evidence copies, never committed.
func TestRealEvidenceReplayIfPresent(t *testing.T) {
	dir := os.Getenv("JETSAM_EVIDENCE_DIR")
	if dir == "" {
		t.Skip("JETSAM_EVIDENCE_DIR not set")
	}
	rep, err := Collect(Options{JetsamDir: dir, DiagDirs: []string{dir}, Now: mt(t, "2026-11-04T17:00:00Z")})
	if err != nil {
		t.Fatal(err)
	}
	in := ReplayInputFrom(rep, ModePauseKill)
	in.AgentLabel = "agent-from-evidence-test" // attribution needs transcripts, which this test does not read
	r := ReplayGuard(in)
	var b bytes.Buffer
	r.Render(&b)
	t.Log("\n" + b.String())
	if !r.Verified {
		t.Fatal("real evidence replay not verified")
	}
	_ = jetsam.TicksPerSecond
	_ = filepath.Join
}
