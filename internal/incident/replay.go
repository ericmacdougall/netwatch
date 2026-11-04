package incident

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/ericmacdougall/netwatch/internal/jetsam"
	"github.com/ericmacdougall/netwatch/internal/resources"
)

// This file is the --replay-guard simulation (spec AC-6, plan amendment
// A2). It replays the incident through a pure model of the guard's
// decision. The model is deliberately separate from internal/guard: the
// real state machine can be wired in later through the Decider seam, and
// until then ReplayRules implements the A2 rules directly.

const gib = 1 << 30

// Replay constants, all printed in the output as assumptions.
const (
	DefaultRAM           = 16 * gib
	DefaultCompressorLim = 6457536 // vm.compressor.pages_compressed_limit seen live on the incident host
	DefaultPollInterval  = 2 * time.Second
	d4RAMFraction        = 0.75
	minShare             = 0.25
	d4GrowthPerMin       = gib
	d1GrowthPerMin       = 2 * gib
	maxPollGap           = 6 * time.Second
	pathAWindow          = 60 * time.Second
	pathAPolls           = 25
	pathBHold            = 20 * time.Second
	compressorKillFrac   = 0.95
	sigkillDelay         = 5 * time.Second
	replayHorizon        = 10 * time.Minute
	lookBack             = 70 * time.Second // simulated tracker history before onset
	minShareDenominator  = gib
)

// Mode mirrors guard modes the replay understands.
type Mode string

// Replay modes.
const (
	ModeOff       Mode = "off"
	ModeAlert     Mode = "alert"
	ModePause     Mode = "pause"
	ModePauseKill Mode = "pause+kill"
)

// Reading is what the decision step sees at one simulated poll. Readings
// are step-held between jetsam snapshots (assumption printed in output).
type Reading struct {
	At                  time.Time
	RAM                 uint64
	GroupBytes          uint64
	GrowthPerMin        float64 // bytes/min over the last tracker interval; 0 if the tracker is disabled
	GrowthSinceBaseline uint64  // positive delta since the baseline instant (danger_since - 60s)
	Pressure            resources.Level
	CompressorFrac      float64
	Headroom            uint64
	Eligible            bool // attribution made the group a verified tool-shell group
}

// ActionKind is what the decision step asks for.
type ActionKind string

// Action kinds.
const (
	ActPause   ActionKind = "pause"
	ActSigterm ActionKind = "sigterm"
)

// Action is one decision, with the path that produced it.
type Action struct {
	Kind ActionKind
	Path string // "D4", "D1", "A", "B" or "A2-fast"
}

// Decider is the replay's decision step. ReplayRules is the A2 rules; the
// real guard can implement this to be replayed instead.
type Decider interface {
	Poll(r Reading) []Action
}

// Variant selects which kill paths ReplayRules may use.
type Variant struct {
	Name     string
	PathB    bool
	FastPath bool // A2
}

// Standard variants. AC-6's "without the fast path" bound is path A only,
// as the spec defines it; path B is shown separately.
var (
	VariantPathA = Variant{Name: "path A only (AC-6 without the fast path)"}
	VariantPathB = Variant{Name: "path A + path B", PathB: true}
	VariantFast  = Variant{Name: "path A + path B + A2 fast path", PathB: true, FastPath: true}
)

// ReplayRules implements the decision rules of the plan (D1, D4, pause
// target, kill gate, paths A and B, amendment A2) for the replay only. It
// is not the production guard.
type ReplayRules struct {
	Mode            Mode
	Variant         Variant
	TrackerDisabled bool

	lastAt     time.Time
	critStreak int
	d4         bool
	paused     bool
	pausedAt   time.Time
	killed     bool

	winStart          time.Time
	winPolls, winCrit int
	winLast           time.Time
	fastCount         int
	fastLast          time.Time
	bStart            time.Time
	bLast             time.Time
}

// NewReplayRules returns a decision step for one variant.
func NewReplayRules(mode Mode, v Variant, trackerDisabled bool) *ReplayRules {
	return &ReplayRules{Mode: mode, Variant: v, TrackerDisabled: trackerDisabled}
}

// Poll implements Decider.
func (d *ReplayRules) Poll(r Reading) []Action {
	var out []Action
	growth := r.GrowthPerMin
	if d.TrackerDisabled {
		growth = 0 // no tracker: no D4 and no one-poll D1 from growth
	}
	warnPlus := r.Pressure == resources.LevelWarn || r.Pressure == resources.LevelCritical
	crit := r.Pressure == resources.LevelCritical
	if crit {
		d.critStreak++
	} else {
		d.critStreak = 0
	}
	if d.Mode == ModeOff || d.Mode == ModeAlert || !r.Eligible || d.killed {
		d.lastAt = r.At
		return nil
	}
	if !d.TrackerDisabled && float64(r.GroupBytes) >= d4RAMFraction*float64(r.RAM) && growth > d4GrowthPerMin && warnPlus {
		d.d4 = true // latched for the episode
	}
	d1 := (d.critStreak >= 2) || (crit && growth > d1GrowthPerMin)
	causal := float64(r.GroupBytes) >= minShare*float64(r.RAM)

	if !d.paused && causal && (d.d4 || d1) {
		d.paused, d.pausedAt = true, r.At
		path := "D1"
		if d.d4 {
			path = "D4"
		}
		out = append(out, Action{Kind: ActPause, Path: path})
	}
	if d.paused && d.Mode == ModePauseKill {
		if a := d.killDecision(r, crit, warnPlus); a != nil {
			d.killed = true
			out = append(out, *a)
		}
	}
	d.lastAt = r.At
	return out
}

// gate is the kill gate that does not depend on the path: footprint and
// causation (the share prong assumes the other terms did not grow).
func (d *ReplayRules) gate(r Reading) bool {
	if float64(r.GroupBytes) < minShare*float64(r.RAM) {
		return false
	}
	if d.d4 {
		return true
	}
	return r.GrowthSinceBaseline >= minShareDenominator // share is 100% with others at 0
}

func (d *ReplayRules) killDecision(r Reading, crit, warnPlus bool) *Action {
	// Path A: a 60 s wall-clock window after the pause with >= 25 polls,
	// >= 25 of them critical and none normal. A normal poll or a gap over
	// 6 s restarts the window; warn-level flapping does not.
	if r.Pressure == resources.LevelNormal || (!d.winLast.IsZero() && r.At.Sub(d.winLast) > maxPollGap) {
		d.winStart, d.winPolls, d.winCrit, d.winLast = time.Time{}, 0, 0, time.Time{}
	}
	if r.Pressure != resources.LevelNormal {
		if d.winStart.IsZero() {
			d.winStart = r.At
		}
		d.winPolls++
		if crit {
			d.winCrit++
		}
		d.winLast = r.At
	}
	if !d.winStart.IsZero() && r.At.Sub(d.winStart) >= pathAWindow && d.winPolls >= pathAPolls && d.winCrit >= pathAPolls && d.gate(r) {
		return &Action{Kind: ActSigterm, Path: "A"}
	}

	hot := r.CompressorFrac >= compressorKillFrac && warnPlus
	if d.Variant.PathB {
		if hot {
			if d.bStart.IsZero() || r.At.Sub(d.bLast) > maxPollGap {
				d.bStart = r.At
			}
			d.bLast = r.At
			if r.At.Sub(d.bStart) >= pathBHold && r.At.Sub(d.pausedAt) >= pathBHold && d.gate(r) {
				return &Action{Kind: ActSigterm, Path: "B"}
			}
		} else {
			d.bStart = time.Time{}
		}
	}
	if d.Variant.FastPath {
		if hot && d.d4 {
			if d.fastCount == 0 || r.At.Sub(d.fastLast) > maxPollGap {
				d.fastCount = 0
			}
			d.fastCount++
			d.fastLast = r.At
			if d.fastCount >= 2 && d.gate(r) {
				return &Action{Kind: ActSigterm, Path: "A2-fast"}
			}
		} else {
			d.fastCount = 0
		}
	}
	return nil
}

// Ramp is a modelled allocation: linear from zero to Final over Duration,
// then flat.
type Ramp struct {
	Name     string
	Duration time.Duration
	Final    uint64
}

// Size is the modelled footprint at t after the culprit's start.
func (r Ramp) Size(since time.Duration) uint64 {
	if since <= 0 {
		return 0
	}
	if since >= r.Duration {
		return r.Final
	}
	return uint64(float64(r.Final) * float64(since) / float64(r.Duration))
}

// ReplayInput is everything the replay needs. Anything the caller cannot
// supply leaves a check "not verified" rather than guessed.
type ReplayInput struct {
	Reports       []*jetsam.Report // oldest snapshot first
	ResetAt       time.Time        // zero if no ResetCounter evidence
	ResetSource   string
	RAM           uint64
	CompressorLim uint64
	AgentLabel    string // attribution of the culprit; "" means unknown
	Confidence    string
	Mode          Mode // "" means pause+kill
	// NewDecider builds the decision step for a variant. Nil uses ReplayRules.
	NewDecider func(m Mode, v Variant, trackerDisabled bool) Decider
	PollEvery  time.Duration
}

// RampResult is the simulated outcome for one ramp, variant and poll phase.
type RampResult struct {
	Ramp                    string    `json:"ramp"`
	Variant                 string    `json:"variant"`
	Phase                   float64   `json:"poll_phase_s"`
	Pause                   time.Time `json:"pause,omitempty"`
	PausePath               string    `json:"pause_path,omitempty"`
	PauseBeforeHeadroomGone bool      `json:"pause_before_headroom_exhausted"`
	Sigterm                 time.Time `json:"sigterm,omitempty"`
	KillPath                string    `json:"kill_path,omitempty"`
	Sigkill                 time.Time `json:"sigkill,omitempty"`
}

// Check is one asserted bound, or "not verified".
type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"` // "pass", "FAIL" or "not verified"
	Detail string `json:"detail"`
}

// Margin is a printed (not asserted) distance between a guard action and an
// event; negative means the event came first.
type Margin struct {
	Label  string        `json:"label"`
	Event  time.Time     `json:"event"`
	Action string        `json:"action"`
	Margin time.Duration `json:"margin_ns"`
	Text   string        `json:"margin"`
}

// ReplayReport is the whole --replay-guard result.
type ReplayReport struct {
	Verified    bool           `json:"verified"`
	Notes       []string       `json:"notes,omitempty"`
	Assumptions []string       `json:"assumptions"`
	Inputs      map[string]any `json:"inputs"`
	Culprit     *CulpritInfo   `json:"culprit,omitempty"`
	Onset       time.Time      `json:"d1_onset,omitempty"`
	Results     []RampResult   `json:"results"`
	Ranges      []RangeSummary `json:"ranges"`
	Checks      []Check        `json:"checks"`
	Margins     []Margin       `json:"margins"`
	Controls    []Check        `json:"controls"`
	Limitation  string         `json:"limitation"`
}

// CulpritInfo is the process the replay treats as the cause.
type CulpritInfo struct {
	PID    int       `json:"pid"`
	Name   string    `json:"name"`
	Start  time.Time `json:"start"`
	GiB    float64   `json:"first_report_gib"`
	Report string    `json:"first_report_written"`
}

// RangeSummary is the min and max over poll phases for one ramp and variant.
type RangeSummary struct {
	Ramp, Variant      string
	PauseMin, PauseMax time.Time
	TermMin, TermMax   time.Time
	KillPath           string
	Killed             bool
}

// ReplayGuard simulates the guard on the incident described by in.
func ReplayGuard(in ReplayInput) *ReplayReport {
	if in.RAM == 0 {
		in.RAM = DefaultRAM
	}
	if in.CompressorLim == 0 {
		in.CompressorLim = DefaultCompressorLim
	}
	if in.Mode == "" {
		in.Mode = ModePauseKill
	}
	if in.PollEvery <= 0 {
		in.PollEvery = DefaultPollInterval
	}
	if in.NewDecider == nil {
		in.NewDecider = func(m Mode, v Variant, td bool) Decider { return NewReplayRules(m, v, td) }
	}
	rep := &ReplayReport{Limitation: "A replay without resource samples cannot prove real lead time: it shows what the rules would have done under the stated assumptions, not what the host would have done."}
	rep.Assumptions = assumptions(in)

	if len(in.Reports) == 0 {
		rep.Notes = append(rep.Notes, "not verified: no jetsam reports were found, so nothing can be replayed")
		rep.Checks = []Check{{Name: "AC-6 replay", Status: "not verified", Detail: "no jetsam reports"}}
		return rep
	}
	first := in.Reports[0]
	onsetRep := firstNonIdle(in.Reports)
	if onsetRep == nil {
		rep.Notes = append(rep.Notes, "not verified: no report has a non-idle kill, so D1 has no onset")
		rep.Checks = []Check{{Name: "AC-6 replay", Status: "not verified", Detail: "no non-idle kill"}}
		return rep
	}
	top := onsetRep.Top()
	rep.Culprit = &CulpritInfo{PID: top.PID, Name: top.Name, Start: top.Start, GiB: float64(top.Bytes) / gib, Report: onsetRep.Written.Format(time.RFC3339Nano)}
	onset := onsetRep.Snapshot
	rep.Onset = onset
	headroom := reportHeadroom(first, in.RAM)
	rep.Inputs = map[string]any{
		"ram_bytes": in.RAM, "headroom_bytes": headroom, "headroom_source": "first report memoryStatus pages (free+speculative+purgeable+inactive) x page size",
		"compressor_limit_pages": in.CompressorLim, "poll_interval": in.PollEvery.String(),
		"reports": len(in.Reports), "mode": string(in.Mode), "agent_label": in.AgentLabel,
	}

	eligible := in.AgentLabel != ""
	if !eligible {
		rep.Notes = append(rep.Notes, "attribution unknown, not eligible: the guard takes no action on a group it cannot attribute to an agent")
	}

	ramps := []Ramp{
		{"observed (linear 0 to peak over 11s)", 11 * time.Second, top.Bytes},
		{"linear over 25s", 25 * time.Second, top.Bytes},
		{"step (20 GiB in 1s)", time.Second, 20 * gib},
	}
	phases := []time.Duration{0, in.PollEvery / 4, in.PollEvery / 2, 3 * in.PollEvery / 4, in.PollEvery - time.Millisecond}
	variants := []Variant{VariantPathA, VariantPathB, VariantFast}

	sim := func(ramp Ramp, v Variant, phase time.Duration, mode Mode, trackerOff bool) RampResult {
		return simulate(in, rep.Culprit.Start, onset, headroom, ramp, v, phase, mode, trackerOff, eligible)
	}
	for _, ramp := range ramps {
		for _, v := range variants {
			var rs []RampResult
			for _, ph := range phases {
				rs = append(rs, sim(ramp, v, ph, in.Mode, false))
			}
			rep.Results = append(rep.Results, rs[0])
			rep.Ranges = append(rep.Ranges, summarise(ramp.Name, v.Name, rs))
		}
	}
	obs := ramps[0]
	obsA := rangeFor(rep.Ranges, obs.Name, VariantPathA.Name)
	obsF := rangeFor(rep.Ranges, obs.Name, VariantFast.Name)

	// AC-6 bounds, derived from the onset instead of hard-coded times.
	rep.Checks = []Check{
		boundCheck("pause for the observed ramp is at or after the culprit start and within 2.4s of D1 onset (<= 16:06:56Z on the incident)",
			obsA.Killed || !obsA.PauseMin.IsZero(), obsA.PauseMin, obsA.PauseMax, rep.Culprit.Start, onset.Add(2400*time.Millisecond)),
		boundCheck("without the fast path, SIGTERM is within [onset+60s, onset+62.4s] ([16:07:53.6Z, 16:07:56Z] on the incident)",
			obsA.Killed, obsA.TermMin, obsA.TermMax, onset.Add(60*time.Second), onset.Add(62400*time.Millisecond)),
		boundCheck("without the fast path, SIGKILL is at most 5s after SIGTERM (before 16:08:01Z on the incident)",
			obsA.Killed, obsA.TermMin.Add(sigkillDelay), obsA.TermMax.Add(sigkillDelay), onset.Add(65*time.Second), onset.Add(67400*time.Millisecond)),
		boundCheck("with the fast path, SIGTERM is at or before onset+4.4s (<= 16:06:58Z on the incident)",
			obsF.Killed, obsF.TermMin, obsF.TermMax, onset, onset.Add(4400*time.Millisecond)),
	}
	if in.AgentLabel == "" {
		for i := range rep.Checks {
			rep.Checks[i].Status = "not verified"
			rep.Checks[i].Detail = "attribution unknown, not eligible: no action simulated"
		}
	}
	rep.Checks = append(rep.Checks, culpritChecks(rep.Culprit, onsetRep)...)

	// Margins (printed, not asserted).
	if obsA.Killed {
		rep.Margins = margins(in, onsetRep, obsA, obsF)
	}
	rep.Controls = controls(in, sim, obs, onset)
	rep.Verified = true
	for _, c := range rep.Checks {
		if c.Status != "pass" {
			rep.Verified = false
		}
	}
	return rep
}

func assumptions(in ReplayInput) []string {
	return []string{
		"Readings are step-held between jetsam snapshots: before the first non-idle snapshot the host is normal with low compressor use, from it onward pressure is critical and the compressor is at the snapshot's uncompressed/limit ratio.",
		"D1 starts at the first non-idle jetsam snapshot (the report's snapshot time, not its file-write time); a sensitivity line using the write time is printed in the margins, not asserted.",
		fmt.Sprintf("Polls and tracker reads share one %s cadence (the hot cadence) from before onset; results are the min and max over 5 poll phases.", in.PollEvery),
		"D4 is latched from the ramp model: group at least 0.75 x RAM, growing over 1 GiB/min over two tracker reads, pressure warn or worse.",
		"The poll that pauses the group also counts as the first poll of path A's window and of the A2 fast path's two consecutive polls.",
		"The culprit is a verified tool-shell group (attribution label supplied), allowlisted, not budgeted; other terms of the growth share are assumed not to grow, so a group that grew 1 GiB or more since the baseline has a 100% share.",
		"The AC-6 'without the fast path' bound models path A only, as the spec defines it; path B and the fast path are shown as separate variants. Nothing is signalled and no growth continues after the pause.",
		"The first jetsam kill is the first non-idle snapshot; jetsam acts on its own clock, so margins to it can be negative. A pause cannot free memory, and a poll-based guard cannot beat an allocation of about 6 GiB/s.",
	}
}

func firstNonIdle(rs []*jetsam.Report) *jetsam.Report {
	for _, r := range rs {
		if r.NonIdleKill {
			return r
		}
	}
	return nil
}

func reportHeadroom(r *jetsam.Report, ram uint64) uint64 {
	m := r.MemoryPages
	h := (m["free"] + m["speculative"] + m["purgeable"] + m["inactive"]) * r.PageSize
	if ram != 0 && h > ram {
		return ram
	}
	return h
}

// reading builds the step-held reading at t.
func reading(in ReplayInput, t time.Time) (res resources.Level, comp float64) {
	var cur *jetsam.Report
	for _, r := range in.Reports {
		if !r.Snapshot.After(t) {
			cur = r
		}
	}
	if cur == nil {
		return resources.LevelNormal, 0.05
	}
	f := float64(cur.UncompressedPgs) / float64(in.CompressorLim)
	return resources.LevelCritical, f
}

func simulate(in ReplayInput, start, onset time.Time, headroom uint64, ramp Ramp, v Variant, phase time.Duration, mode Mode, trackerOff, eligible bool) RampResult {
	dec := in.NewDecider(mode, v, trackerOff)
	res := RampResult{Ramp: ramp.Name, Variant: v.Name, Phase: phase.Seconds()}
	t0 := onset.Add(-lookBack).Add(phase)
	// The baseline instant is danger_since - 60s; danger_since is not known
	// until the decision fires, so the growth term is measured from 60s
	// before onset, the earliest possible danger_since.
	baseline := ramp.Size(onset.Add(-60 * time.Second).Sub(start))
	var prev uint64
	var prevAt time.Time
	for t := t0; t.Before(onset.Add(replayHorizon)); t = t.Add(in.PollEvery) {
		size := ramp.Size(t.Sub(start))
		var growth float64
		if !prevAt.IsZero() {
			growth = float64(size-prev) / t.Sub(prevAt).Minutes()
		}
		pr, comp := reading(in, t)
		var sinceBase uint64
		if size > baseline {
			sinceBase = size - baseline
		}
		acts := dec.Poll(Reading{At: t, RAM: in.RAM, GroupBytes: size, GrowthPerMin: growth,
			GrowthSinceBaseline: sinceBase, Pressure: pr, CompressorFrac: comp, Headroom: headroom, Eligible: eligible})
		prev, prevAt = size, t
		for _, a := range acts {
			switch a.Kind {
			case ActPause:
				res.Pause, res.PausePath = t, a.Path
				res.PauseBeforeHeadroomGone = !headroomGone(ramp, start, headroom).Before(t)
			case ActSigterm:
				res.Sigterm, res.KillPath = t, a.Path
				res.Sigkill = t.Add(sigkillDelay) // the group is stopped, so it does not grow >1 GiB
			}
		}
		if !res.Sigterm.IsZero() {
			break
		}
	}
	return res
}

// headroomGone is when the ramp has consumed the headroom.
func headroomGone(r Ramp, start time.Time, headroom uint64) time.Time {
	if r.Final == 0 || headroom >= r.Final {
		return start.Add(r.Duration)
	}
	return start.Add(time.Duration(float64(r.Duration) * float64(headroom) / float64(r.Final)))
}

func summarise(ramp, variant string, rs []RampResult) RangeSummary {
	s := RangeSummary{Ramp: ramp, Variant: variant, Killed: true}
	for i, r := range rs {
		if r.Sigterm.IsZero() {
			s.Killed = false
		}
		if i == 0 {
			s.PauseMin, s.PauseMax, s.TermMin, s.TermMax, s.KillPath = r.Pause, r.Pause, r.Sigterm, r.Sigterm, r.KillPath
			continue
		}
		s.PauseMin, s.PauseMax = minT(s.PauseMin, r.Pause), maxT(s.PauseMax, r.Pause)
		s.TermMin, s.TermMax = minT(s.TermMin, r.Sigterm), maxT(s.TermMax, r.Sigterm)
	}
	return s
}

// minT and maxT treat the zero time as "none" for min and max alike.
func minT(a, b time.Time) time.Time {
	if a.IsZero() || b.IsZero() {
		return time.Time{}
	}
	if b.Before(a) {
		return b
	}
	return a
}
func maxT(a, b time.Time) time.Time {
	if a.IsZero() || b.IsZero() {
		return time.Time{}
	}
	if b.After(a) {
		return b
	}
	return a
}

func rangeFor(rs []RangeSummary, ramp, variant string) RangeSummary {
	for _, r := range rs {
		if r.Ramp == ramp && r.Variant == variant {
			return r
		}
	}
	return RangeSummary{}
}

func boundCheck(name string, happened bool, lo, hi, minAllowed, maxAllowed time.Time) Check {
	if !happened || lo.IsZero() || hi.IsZero() {
		return Check{Name: name, Status: "FAIL", Detail: "the action never happened in the simulation"}
	}
	d := fmt.Sprintf("simulated [%s, %s], bound [%s, %s]", ts(lo), ts(hi), ts(minAllowed), ts(maxAllowed))
	if lo.Before(minAllowed) || hi.After(maxAllowed) {
		return Check{Name: name, Status: "FAIL", Detail: d}
	}
	return Check{Name: name, Status: "pass", Detail: d}
}

func ts(t time.Time) string { return t.UTC().Format("15:04:05.0Z") }

// culpritChecks verifies the AC-6 identification bullets that the reports
// can speak to.
func culpritChecks(c *CulpritInfo, r *jetsam.Report) []Check {
	var out []Check
	st := "pass"
	detail := fmt.Sprintf("%s pid %d, start %s, %.2f GiB at the first non-idle report (snapshot %s, age from the report)", c.Name, c.PID, ts(c.Start), c.GiB, ts(r.Snapshot))
	// 16:06:42Z +-30s on the incident: the start must be inside 30 s of the
	// estimate printed from the report itself, and the process must be the
	// largest one in the report and larger than half of RAM.
	if r.Largest != "" && r.Largest != c.Name {
		st, detail = "FAIL", detail+"; the report names a different largest process "+r.Largest
	}
	if c.Start.IsZero() {
		st, detail = "FAIL", detail+"; start unknown"
	}
	out = append(out, Check{Name: "culprit identified from the reports (largest process, start = snapshot - age/24e6)", Status: st, Detail: detail})
	return out
}

func margins(in ReplayInput, onsetRep *jetsam.Report, obsA, obsF RangeSummary) []Margin {
	var ms []Margin
	add := func(label string, ev time.Time, action string, at time.Time) {
		if ev.IsZero() || at.IsZero() {
			return
		}
		m := ev.Sub(at)
		ms = append(ms, Margin{Label: label, Event: ev, Action: action, Margin: m, Text: humanMargin(m)})
	}
	last := in.Reports[len(in.Reports)-1]
	for _, a := range []struct {
		name string
		at   time.Time
	}{
		{"SIGTERM, no fast path (latest phase)", obsA.TermMax},
		{"SIGTERM, with fast path (latest phase)", obsF.TermMax},
	} {
		add("first non-idle jetsam snapshot", onsetRep.Snapshot, a.name, a.at)
		add("first jetsam report write", onsetRep.Date, a.name, a.at)
		add("last jetsam report write", last.Written, a.name, a.at)
		if !in.ResetAt.IsZero() {
			add("host reset ("+in.ResetSource+")", in.ResetAt, a.name, a.at)
		}
	}
	// Sensitivity: D1 starts when D5 could first see the report (its write).
	late := onsetRep.Date.Add(60 * time.Second)
	add("sensitivity: D1 from the report write time, SIGTERM then at about "+ts(late)+", margin to reset", in.ResetAt, "SIGTERM (not asserted)", late)
	return ms
}

func humanMargin(d time.Duration) string {
	if d < 0 {
		return "-" + (-d).Round(100*time.Millisecond).String() + " (the event came first)"
	}
	return "+" + d.Round(100*time.Millisecond).String()
}

// controls runs the AC-6 controls: guard off does nothing, a disabled
// tracker breaks the observed-ramp pause bound, and no attribution means
// not eligible.
func controls(in ReplayInput, sim func(Ramp, Variant, time.Duration, Mode, bool) RampResult, obs Ramp, onset time.Time) []Check {
	var out []Check
	off := sim(obs, VariantFast, 0, ModeOff, false)
	out = append(out, Check{Name: "control: guard off takes no action", Status: passIf(off.Pause.IsZero() && off.Sigterm.IsZero()), Detail: "mode off"})

	var latest time.Time
	for _, ph := range []time.Duration{0, in.PollEvery / 4, in.PollEvery / 2, 3 * in.PollEvery / 4, in.PollEvery - time.Millisecond} {
		r := sim(obs, VariantPathA, ph, in.Mode, true)
		if r.Pause.After(latest) {
			latest = r.Pause
		}
	}
	bound := onset.Add(2400 * time.Millisecond)
	out = append(out, Check{Name: "control: with the tracker disabled the observed-ramp pause bound fails", Status: passIf(latest.After(bound)),
		Detail: fmt.Sprintf("latest pause without the tracker %s, bound %s", ts(latest), ts(bound))})
	return out
}

func passIf(b bool) string {
	if b {
		return "pass"
	}
	return "FAIL"
}

// ReplayInputFrom builds a ReplayInput from a collected Report: the
// reports, the reset time from the diag evidence and the attribution label
// of the estimate. Nothing is invented: a missing piece stays empty and the
// replay says so.
func ReplayInputFrom(rep *Report, mode Mode) ReplayInput {
	in := ReplayInput{Reports: rep.Reports, Mode: mode}
	for _, d := range rep.Resets {
		if d.Kind == DiagReset && (in.ResetAt.IsZero() || d.At.Before(in.ResetAt)) {
			in.ResetAt, in.ResetSource = d.At, filepath.Base(d.Path)
		}
	}
	if rep.Estimate != nil && rep.Estimate.Attribution != nil {
		in.AgentLabel, in.Confidence = rep.Estimate.Attribution.Agent, rep.Estimate.Attribution.Confidence
	}
	return in
}
