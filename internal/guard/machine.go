package guard

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/ericmacdougall/netwatch/internal/redact"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ericmacdougall/netwatch/internal/resources"
)

// Machine is the pure guard state machine. Step takes a Snapshot and
// returns the Actions to perform; it does no I/O and reads no clock, so it
// is deterministic. The Executor applies the actions and persists State.
// A Machine is safe for use from several goroutines, but the monitor is
// expected to drive Step from one guard loop.
type Machine struct {
	mu         sync.Mutex
	cfg        Config
	st         State
	restoredAt time.Time
	warnedSelf bool
	lastErr    string
	dirty      bool
}

// NewMachine returns a machine with empty state.
func NewMachine(cfg Config) *Machine {
	return &Machine{cfg: cfg, st: newState()}
}

// SetMode changes the mode; the next Step applies it.
func (m *Machine) SetMode(mode Mode) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg.Mode = mode
}

// Mode returns the current mode.
func (m *Machine) Mode() Mode {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg.Mode
}

// State returns a deep copy of the persistable state.
func (m *Machine) State() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.st.Clone()
}

// Dirty reports, and clears, whether state changed since the last call.
func (m *Machine) Dirty() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	d := m.dirty
	m.dirty = false
	return d
}

// LastError is the reason the last Step took no action, "" if none.
func (m *Machine) LastError() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastErr
}

// gview is one agent group in the current snapshot.
type gview struct {
	T   *Term
	G   *Group
	Key string
	FP  uint64
}

type aggView struct {
	Key string
	FP  uint64
}

type view struct {
	terms  []Term
	groups []*gview // eligible-or-not groups with a Group, Tier != TierNone
	byKey  map[string]*gview
	byPGID map[int]*gview
	inel   []aggView // ineligible aggregates (never unattributed)
}

func fpOf(t *Term) uint64 {
	if n := len(t.Series); n > 0 {
		return t.Series[n-1].Bytes
	}
	if t.Group != nil {
		return t.Group.Footprint
	}
	return 0
}

func buildView(s Snapshot) *view {
	v := &view{terms: s.Terms, byKey: map[string]*gview{}, byPGID: map[int]*gview{}}
	for i := range v.terms {
		t := &v.terms[i]
		fp := fpOf(t)
		if t.Group == nil {
			if t.Key != "unattributed" {
				v.inel = append(v.inel, aggView{t.Key, fp})
			}
			continue
		}
		if t.Group.Tier == TierNone {
			// A Codex-shaped (or otherwise ineligible) group is an
			// aggregate: alerts only, never signalled.
			v.inel = append(v.inel, aggView{t.Key, fp})
			continue
		}
		key := keyOf(t.Group.PGID, t.Group.LeaderStart)
		gv := &gview{T: t, G: t.Group, Key: key, FP: fp}
		v.groups = append(v.groups, gv)
		v.byKey[key] = gv
		v.byPGID[t.Group.PGID] = gv
	}
	return v
}

func (v *view) largestInel() aggView {
	var b aggView
	for _, a := range v.inel {
		if a.FP > b.FP {
			b = a
		}
	}
	return b
}

func withinBudget(g *Group, fp uint64) bool {
	return g.Budget != nil && fp <= g.Budget.MaxBytes
}

func exclHash(g *Group) string {
	var parts []string
	for _, mem := range g.Members {
		if mem.Excluded {
			parts = append(parts, fmt.Sprintf("%d:%d", mem.PID, mem.Start.UnixNano()))
		}
	}
	sort.Strings(parts)
	h := sha256.Sum256([]byte(strings.Join(parts, ",")))
	return hex.EncodeToString(h[:8])
}

func factsOf(g *Group, fp uint64) Facts {
	f := Facts{Tier: g.Tier, EnvOK: g.EnvOK, Allowlisted: g.Allowlisted, ClaudeVer: g.ClaudeVer, ExclHash: exclHash(g)}
	if g.Budget != nil {
		f.BudgetMax = g.Budget.MaxBytes
		f.BudgetWithin = fp <= g.Budget.MaxBytes
	}
	return f
}

// killable is the static part of the kill gate: the group must be a
// verified tool shell with the right environment, an allowlisted Claude
// version, and not inside a declared budget.
func killable(f Facts) bool {
	return f.Tier == TierTool && f.EnvOK && f.Allowlisted && !f.BudgetWithin
}

// signalNames lists the danger signals that are active this poll.
func signalNames(s Snapshot) []string {
	var n []string
	g := s.Signals
	if g.D1 {
		n = append(n, "D1")
	}
	if g.D2 {
		n = append(n, "D2")
	}
	if g.D3 {
		n = append(n, "D3")
	}
	if len(g.D4PGIDs) > 0 {
		n = append(n, "D4")
	}
	if g.P1 {
		if g.P1Corroborated {
			n = append(n, "P1")
		} else {
			n = append(n, "P1(uncorroborated)")
		}
	}
	if g.D5 {
		n = append(n, "D5")
	}
	if s.Sys.Pressure == resources.LevelCritical {
		n = append(n, "pressure=critical")
	} else if s.Sys.Pressure == resources.LevelWarn {
		n = append(n, "pressure=warn")
	}
	return n
}

// Step advances the machine by one poll.
func (m *Machine) Step(s Snapshot) []Action {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s.Sys.RAM == 0 || s.At.IsZero() {
		// A failed read means no new pause or kill; the monitor logs the
		// error. The pause time limits still apply, so a group is never held
		// past them just because readings keep failing.
		m.lastErr = "system reading unavailable: guard takes no new action"
		if s.At.IsZero() {
			return nil
		}
		blind := Snapshot{At: s.At} // pressure unknown: never "still critical"
		acts := m.maxPause(blind, buildView(blind))
		if len(acts) > 0 {
			m.dirty = true
		}
		return acts
	}
	m.lastErr = ""
	now := s.At
	v := buildView(s)
	var acts []Action

	m.updateTrackers(s)
	m.dropDead(s, v)

	if m.cfg.Mode == ModeOff {
		return m.resumeAll(now, "mode off", v)
	}
	if !m.cfg.Mode.canPause() { // alert: nothing may stay paused
		acts = append(acts, m.resumeAll(now, "mode "+string(m.cfg.Mode), v)...)
	}

	// Episode lifecycle.
	if m.st.Episode == nil && s.Signals.Danger {
		acts = append(acts, m.startEpisode(s, v)...)
	}
	if ep := m.st.Episode; ep != nil {
		if s.Signals.Danger {
			ep.Cleared = false
		}
		m.ensureBaselines(s, v)
		m.latch(s, v)
		acts = append(acts, m.unprotected(s, v)...)
	}

	pauseOK := m.cfg.Mode.canPause() && s.SelfTest == nil
	if m.cfg.Mode.canPause() && s.SelfTest != nil && !m.warnedSelf {
		m.warnedSelf = true
		acts = append(acts, Action{Kind: ActAlert, Reason: "start-up self-test failed, pause and kill disabled: " + s.SelfTest.Error()})
	}
	if !m.cfg.Mode.canPause() {
		m.endEpisodeIfDone(s)
		return acts
	}

	acts = append(acts, m.maxPause(s, v)...)
	acts = append(acts, m.clearStep(s, v)...)
	if pauseOK && m.st.Episode != nil && s.Signals.Danger && !s.Signals.Clear {
		acts = append(acts, m.pauseStep(s, v)...)
	}
	m.updatePathA(s)
	acts = append(acts, m.membersStep(s, v)...)
	acts = append(acts, m.termProgress(s, v)...)
	if pauseOK && m.killAllowed() {
		acts = append(acts, m.killStep(s, v)...)
	}
	m.endEpisodeIfDone(s)
	if len(acts) > 0 {
		m.dirty = true
	}
	return acts
}

func (m *Machine) endEpisodeIfDone(s Snapshot) {
	if m.st.Episode != nil && s.Signals.Clear && !s.Signals.Danger && len(m.st.Groups) == 0 {
		m.st.Episode = nil
		m.dirty = true
	}
	// Forget old resume times so the state stays small.
	for k, t := range m.st.LastResume {
		if s.At.Sub(t) > 2*m.cfg.StickyWindow {
			delete(m.st.LastResume, k)
		}
	}
}

// updateTrackers maintains the counters for path B and the A2 fast path.
func (m *Machine) updateTrackers(s Snapshot) {
	tr := &m.st.Trk
	now := s.At
	gap := !tr.LastPollAt.IsZero() && now.Sub(tr.LastPollAt) > m.cfg.PathAGap
	tr.LastPollAt = now
	warnPlus := s.Sys.Pressure == resources.LevelWarn || s.Sys.Pressure == resources.LevelCritical
	comp := s.Signals.CompressorFrac
	if comp == 0 { // callers that only filled Sys
		comp = compFrac(s.Sys)
	}
	swap := s.Signals.SwapFrac

	// Path B condition: compressor or swap at 95% with pressure >= warn.
	if warnPlus && (comp >= m.cfg.PathBFrac || swap >= m.cfg.PathBFrac) {
		if tr.CondSince.IsZero() || gap {
			tr.CondSince = now
		}
		tr.CondLast = now
	} else {
		tr.CondSince = time.Time{}
	}
	// Fast path: compressor at 95% on consecutive polls, each gap <= 6s.
	if warnPlus && comp >= m.cfg.PathBFrac {
		if tr.CompPolls > 0 && !gap {
			tr.CompPolls++
		} else {
			tr.CompPolls = 1
		}
		tr.CompLast = now
	} else {
		tr.CompPolls = 0
	}
}

func compFrac(s resources.System) float64 {
	var a, b float64
	if s.PagesCompressedLimit > 0 {
		a = float64(s.PagesCompressed) / float64(s.PagesCompressedLimit)
	}
	if s.SegmentLimit > 0 {
		b = float64(s.Segments) / float64(s.SegmentLimit)
	}
	if b > a {
		return b
	}
	return a
}

// updatePathA counts polls for each paused group's sustained-critical
// window. The window starts at the first critical poll after the pause; a
// normal poll or a gap over PathAGap restarts it; warn polls do not.
func (m *Machine) updatePathA(s Snapshot) {
	now := s.At
	for _, r := range m.st.Groups {
		if r.Phase != PhasePaused {
			continue
		}
		a := &r.PathA
		if !a.Last.IsZero() && now.Sub(a.Last) > m.cfg.PathAGap {
			*a = PathA{}
		}
		if s.Sys.Pressure == resources.LevelNormal {
			*a = PathA{}
			continue
		}
		crit := s.Sys.Pressure == resources.LevelCritical
		if a.Start.IsZero() {
			if !crit {
				continue
			}
			a.Start = now
		}
		a.Pts = append(a.Pts, PathAPt{At: now, Crit: crit})
		// Only the trailing window counts: too few polls in 60s (a stall,
		// a slow cadence) means no kill.
		cut := 0
		for cut < len(a.Pts) && now.Sub(a.Pts[cut].At) > m.cfg.PathAWindow {
			cut++
		}
		a.Pts = a.Pts[cut:]
		a.Last = now
	}
}

func (m *Machine) dropDead(s Snapshot, v *view) {
	if s.Alive == nil {
		return
	}
	for k, r := range m.st.Groups {
		if _, ok := v.byKey[k]; ok {
			r.Missing = 0
			continue
		}
		alive := false
		for _, mem := range r.Members {
			if s.Alive(mem.PID, mem.Start) {
				alive = true
				break
			}
		}
		if !alive && s.Alive(r.PGID, r.LeaderStart) {
			alive = true
		}
		if !alive {
			delete(m.st.Groups, k)
			m.dirty = true
		}
	}
}

// resumeAll resumes every recorded group (mode change, uninstall, restart
// rules). Records are removed; the executor signals before it saves.
func (m *Machine) resumeAll(now time.Time, why string, v *view) []Action {
	var acts []Action
	for _, r := range m.st.sortedRecords() {
		acts = append(acts, m.resumeAction(r, why))
		m.st.LastResume[r.Key()] = now
		delete(m.st.Groups, r.Key())
		m.dirty = true
	}
	return acts
}

func (m *Machine) resumeAction(r *Record, why string) Action {
	var mem []Member
	for _, x := range r.Members {
		mem = append(mem, Member{PID: x.PID, Start: x.Start})
	}
	return Action{Kind: ActResume, PGID: r.PGID, Start: r.LeaderStart, Reason: why, Members: mem, Cmd: r.Cmd, Agent: r.Agent}
}

// startEpisode opens an episode and raises the first alert.
func (m *Machine) startEpisode(s Snapshot, v *view) []Action {
	since := s.At
	ep := &Episode{
		ID:         fmt.Sprintf("ep-%d", since.UnixNano()),
		Since:      since,
		BaselineAt: since.Add(-time.Minute),
		Baselines:  map[string]uint64{}, DangerBase: map[string]uint64{},
		D4: map[string]bool{}, P1: map[string]bool{},
		Resumed: map[string]bool{}, Unprotected: map[string]bool{},
	}
	m.st.Episode = ep
	m.dirty = true
	var cands []string
	for _, g := range v.groups {
		cands = append(cands, fmt.Sprintf("pgid %d %s", g.G.PGID, g.G.Cmd))
	}
	return []Action{{
		Kind: ActAlert, DangerSince: since, Signals: signalNames(s),
		Reason: "danger: " + strings.Join(signalNames(s), ",") + "; candidates: " + strings.Join(cands, "; "),
	}}
}

// latch records D4 and corroborated P1 for the rest of the episode.
func (m *Machine) latch(s Snapshot, v *view) {
	ep := m.st.Episode
	for _, pg := range s.Signals.D4PGIDs {
		if g := v.byPGID[pg]; g != nil && !ep.D4[g.Key] {
			ep.D4[g.Key] = true
			m.dirty = true
		}
	}
	if s.Signals.P1Corroborated {
		for _, pg := range s.Signals.P1PGIDs {
			if g := v.byPGID[pg]; g != nil && !ep.P1[g.Key] {
				ep.P1[g.Key] = true
				m.dirty = true
			}
		}
	}
}

// unprotected raises HOST_AT_RISK_UNPROTECTED once per episode and
// aggregate when the largest consumer is one we may not signal.
func (m *Machine) unprotected(s Snapshot, v *view) []Action {
	ep := m.st.Episode
	if !s.Signals.Danger {
		return nil
	}
	big := v.largestInel()
	floor := uint64(m.cfg.Danger.MinShare * float64(s.Sys.RAM))
	if big.Key == "" || big.FP < floor || ep.Unprotected[big.Key] {
		return nil
	}
	var mx uint64
	for _, g := range v.groups {
		if g.FP > mx {
			mx = g.FP
		}
	}
	if big.FP < mx {
		return nil
	}
	ep.Unprotected[big.Key] = true
	m.dirty = true
	return []Action{{Kind: ActUnprotected, Footprint: big.FP, Signals: signalNames(s), DangerSince: ep.Since,
		Reason: fmt.Sprintf("HOST_AT_RISK_UNPROTECTED: largest consumer %s (%d bytes) is not guarded", redact.DisplayKey(big.Key), big.FP)}}
}
