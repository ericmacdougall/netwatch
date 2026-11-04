package guard

import (
	"fmt"
	"sort"
	"time"

	"github.com/ericmacdougall/netwatch/internal/resources"
)

// causal reports why a group is a cause of the danger, or "".
func (m *Machine) causal(s Snapshot, v *view, g *gview) string {
	ep := m.st.Episode
	if ep.D4[g.Key] {
		return "D4"
	}
	if ep.P1[g.Key] {
		return "P1+corroboration"
	}
	if pos(g.FP, ep.DangerBase[g.Key]) >= m.cfg.PauseGrowth {
		return "grew>=2GB since danger_since"
	}
	floor := uint64(m.cfg.Danger.MinShare * float64(s.Sys.RAM))
	if g.FP >= floor && g.FP >= v.largestInel().FP {
		return "largest consumer"
	}
	return ""
}

// pauseStep picks at most one new group to pause this poll.
func (m *Machine) pauseStep(s Snapshot, v *view) []Action {
	ep := m.st.Episode
	now := s.At
	if !m.st.LastPauseAt.IsZero() && now.Sub(m.st.LastPauseAt) < m.cfg.PauseGap {
		return nil
	}
	if len(m.st.Groups) >= m.cfg.MaxPaused {
		return nil
	}
	// If the largest consumer is ineligible, pause at most one causal
	// group per episode: we cannot fix the real cause.
	var mx uint64
	for _, g := range v.groups {
		if g.FP > mx {
			mx = g.FP
		}
	}
	if v.largestInel().FP > mx && ep.Pauses >= 1 {
		return nil
	}

	type cand struct {
		g      *gview
		why    string
		growth uint64
	}
	var cs []cand
	for _, g := range v.groups {
		if _, already := m.st.Groups[g.Key]; already {
			continue
		}
		if t, ok := m.st.LastResume[g.Key]; ok && t.Equal(now) {
			continue // released this very poll (max pause): do not flap
		}
		// A declared budget explains a big job; it is never paused.
		if withinBudget(g.G, g.FP) {
			continue
		}
		why := m.causal(s, v, g)
		if why == "" {
			continue
		}
		cs = append(cs, cand{g, why, pos(g.FP, ep.DangerBase[g.Key])})
	}
	if len(cs) == 0 {
		return nil
	}
	// Undeclared and over-budget groups are all that remain here, so the
	// order is growth since danger, then footprint.
	sort.SliceStable(cs, func(i, j int) bool {
		if cs[i].growth != cs[j].growth {
			return cs[i].growth > cs[j].growth
		}
		return cs[i].g.FP > cs[j].g.FP
	})
	c := cs[0]
	g := c.g
	rec := &Record{
		PGID: g.G.PGID, LeaderStart: g.G.LeaderStart, Phase: PhasePaused, PausedAt: now,
		Facts: factsOf(g.G, g.FP), Cmd: g.G.Cmd, Agent: g.G.Agent,
		Signals: append(signalNames(s), "cause="+c.why),
	}
	// Sticky: paused again within the episode, or within 10 minutes of the
	// last resume, stays paused until a manual resume, a kill or max pause.
	if ep.Resumed[g.Key] {
		rec.Sticky = true
	} else if t, ok := m.st.LastResume[g.Key]; ok && now.Sub(t) < m.cfg.StickyWindow {
		rec.Sticky = true
	}
	for _, mem := range g.G.Members {
		if mem.Stopped {
			rec.Already = append(rec.Already, PidStart{mem.PID, mem.Start})
		}
	}
	m.st.Groups[g.Key] = rec
	m.st.LastPauseAt = now
	ep.Pauses++
	m.dirty = true
	return nil // the member list is produced by membersStep, also for this group
}

// membersStep emits a pause for every running, non-excluded member of
// every paused group, so members forked later are stopped too. It stops
// chasing a group that stays unstable for UnstableAt polls.
func (m *Machine) membersStep(s Snapshot, v *view) []Action {
	var acts []Action
	for _, r := range m.st.sortedRecords() {
		if r.Phase != PhasePaused || r.Frozen {
			continue
		}
		g := v.byKey[r.Key()]
		if g == nil {
			continue
		}
		var stop []Member
		for _, mem := range g.G.Members {
			if mem.Excluded || mem.Stopped {
				continue
			}
			stop = append(stop, mem)
		}
		fresh := r.PausedAt.Equal(s.At)
		if len(stop) == 0 {
			r.Unstable = 0
			continue
		}
		if !fresh {
			r.Unstable++
		}
		if r.Unstable >= m.cfg.UnstableAt || len(g.G.Members) > m.cfg.MaxMembers {
			r.Frozen = true
			m.dirty = true
			acts = append(acts, Action{Kind: ActAlert, PGID: r.PGID, Start: r.LeaderStart, Cmd: r.Cmd, Agent: r.Agent,
				Reason: fmt.Sprintf("paused group %d is unstable (%d members, %d polls with new children): no longer chasing it", r.PGID, len(g.G.Members), r.Unstable)})
			continue
		}
		reason := "new children"
		if fresh {
			reason = "pause"
		}
		acts = append(acts, Action{Kind: ActPause, PGID: r.PGID, Start: r.LeaderStart, Members: stop, Reason: reason,
			Signals: r.Signals, DangerSince: m.dangerSince(), Cmd: r.Cmd, Agent: r.Agent, Footprint: g.FP})
	}
	return acts
}

func (m *Machine) dangerSince() time.Time {
	if m.st.Episode != nil {
		return m.st.Episode.Since
	}
	return time.Time{}
}

// clearStep resumes one group per poll, smallest first, once the clear
// condition holds. Sticky groups wait for the maximum pause, a manual
// resume or a kill.
func (m *Machine) clearStep(s Snapshot, v *view) []Action {
	ep := m.st.Episode
	if ep == nil || !s.Signals.Clear {
		return nil
	}
	if !m.restoredAt.IsZero() && s.At.Sub(m.restoredAt) < m.cfg.RestoreHold {
		return nil // the clear hold restarts after a crash
	}
	ep.Cleared = true
	var best *Record
	var bestFP uint64
	for _, r := range m.st.sortedRecords() {
		if r.Phase != PhasePaused || r.Sticky {
			continue
		}
		var fp uint64
		if g := v.byKey[r.Key()]; g != nil {
			fp = g.FP
		}
		if best == nil || fp < bestFP {
			best, bestFP = r, fp
		}
	}
	if best == nil {
		return nil
	}
	return []Action{m.release(best, s.At, "clear: pressure normal for 30s, swap and compressor not rising")}
}

// release removes a record and returns its resume action.
func (m *Machine) release(r *Record, now time.Time, why string) Action {
	a := m.resumeAction(r, why)
	delete(m.st.Groups, r.Key())
	m.st.LastResume[r.Key()] = now
	if m.st.Episode != nil {
		m.st.Episode.Resumed[r.Key()] = true
	}
	m.dirty = true
	return a
}

// maxPause applies the 30 minute conditional resume and the 2 hour cap.
func (m *Machine) maxPause(s Snapshot, v *view) []Action {
	var acts []Action
	for _, r := range m.st.sortedRecords() {
		if r.Phase != PhasePaused {
			continue
		}
		age := s.At.Sub(r.PausedAt)
		switch {
		case age >= m.cfg.AbsCap:
			a := m.release(r, s.At, "absolute cap: paused for 2h, resumed whatever the pressure")
			acts = append(acts, a, Action{Kind: ActAlert, PGID: r.PGID, Start: r.LeaderStart, Cmd: r.Cmd, Agent: r.Agent,
				Reason: fmt.Sprintf("LOUD: pgid %d resumed after the 2h absolute pause cap, pressure %s", r.PGID, s.Sys.Pressure)})
		case age >= m.cfg.MaxPause:
			if s.Sys.Pressure != resources.LevelCritical && !s.Signals.P1Corroborated {
				acts = append(acts, m.release(r, s.At, "max pause 30m reached and pressure is not critical"))
			} else if r.LastWarn.IsZero() || s.At.Sub(r.LastWarn) >= m.cfg.MaxPauseWarn {
				r.LastWarn = s.At
				m.dirty = true
				acts = append(acts, Action{Kind: ActAlert, PGID: r.PGID, Start: r.LeaderStart, Cmd: r.Cmd, Agent: r.Agent,
					Reason: fmt.Sprintf("pgid %d has been paused over 30m and the host is still critical; run netwatch resume %d to release it", r.PGID, r.PGID)})
			}
		}
	}
	return acts
}
