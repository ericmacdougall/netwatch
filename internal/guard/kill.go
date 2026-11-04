package guard

import "fmt"

// pathReached says which kill path, if any, the group has reached.
func (m *Machine) pathReached(s Snapshot, r *Record) string {
	tr := m.st.Trk
	now := s.At
	if !m.cfg.DisablePathA {
		a := r.PathA
		crit := 0
		for _, p := range a.Pts {
			if p.Crit {
				crit++
			}
		}
		if !a.Start.IsZero() && now.Sub(a.Start) >= m.cfg.PathAWindow &&
			len(a.Pts) >= m.cfg.PathAMinPolls && crit >= m.cfg.PathAMinCrit {
			return "A"
		}
	}
	if !m.cfg.DisablePathB && !tr.CondSince.IsZero() {
		since := tr.CondSince
		if r.PausedAt.After(since) {
			since = r.PausedAt
		}
		if now.Sub(since) >= m.cfg.PathBHold {
			return "B"
		}
	}
	if !m.cfg.DisableFast && m.st.Episode != nil && m.st.Episode.D4[r.Key()] && tr.CompPolls >= m.cfg.FastPolls {
		return "fast"
	}
	return ""
}

// causation reports which prong makes the group the cause, or "".
func (m *Machine) causation(s Snapshot, v *view, g *gview) (string, string) {
	ep := m.st.Episode
	if ep == nil {
		return "", "no episode"
	}
	floor := uint64(m.cfg.Danger.MinShare * float64(s.Sys.RAM))
	if g.FP < floor {
		return "", fmt.Sprintf("footprint %d below min share %d", g.FP, floor)
	}
	if ep.D4[g.Key] {
		return "D4", ""
	}
	if !m.scanFresh(s) {
		return "", "scan stale: share prong unavailable"
	}
	share, num, den := m.growthShare(v, g.Key)
	if den < m.cfg.ShareDenomMin {
		return "", fmt.Sprintf("share denominator %d under floor", den)
	}
	if share >= m.cfg.ShareMin {
		return fmt.Sprintf("share=%.2f(delta=%d,denominator=%d)", share, num, den), ""
	}
	return "", fmt.Sprintf("share %.2f under %.2f", share, m.cfg.ShareMin)
}

// killStep sends SIGTERM (while stopped) to at most one group per poll
// when the whole kill gate holds.
func (m *Machine) killStep(s Snapshot, v *view) []Action {
	now := s.At
	if now.Before(m.st.CooldownUntil) {
		return nil
	}
	for _, r := range m.st.sortedRecords() {
		if r.Phase != PhasePaused {
			continue
		}
		g := v.byKey[r.Key()]
		if g == nil {
			continue
		}
		// Facts recorded at pause time must still hold now.
		cur := factsOf(g.G, g.FP)
		if !killable(r.Facts) || cur != r.Facts {
			continue
		}
		path := m.pathReached(s, r)
		if path == "" {
			continue
		}
		prong, _ := m.causation(s, v, g)
		if prong == "" {
			continue
		}
		return []Action{m.beginKill(r, g, s, fmt.Sprintf("path=%s causation=%s footprint=%d", path, prong, g.FP))}
	}
	return nil
}

func (m *Machine) beginKill(r *Record, g *gview, s Snapshot, prong string) Action {
	r.Phase = PhaseTerm
	r.TermAt = s.At
	r.FPAtTerm = g.FP
	m.st.CooldownUntil = s.At.Add(m.cfg.Cooldown)
	m.dirty = true
	mem := m.liveMembers(r, g)
	return Action{Kind: ActTerm, PGID: r.PGID, Start: r.LeaderStart, Members: mem, Prong: prong,
		Reason: "kill gate passed: " + prong, Signals: r.Signals, DangerSince: m.dangerSince(),
		Cmd: r.Cmd, Agent: r.Agent, Footprint: g.FP}
}

// liveMembers is the union of the recorded members and the group's
// current non-excluded members, each pid once. A recorded pid that is now
// excluded (it exec'd a never-signal program) is left out too.
func (m *Machine) liveMembers(r *Record, g *gview) []Member {
	seen := map[int]bool{}
	var out []Member
	if g != nil {
		for _, mem := range g.G.Members {
			if seen[mem.PID] {
				continue
			}
			seen[mem.PID] = true
			if mem.Excluded {
				continue
			}
			out = append(out, mem)
		}
	}
	for _, rm := range r.Members {
		if !seen[rm.PID] {
			seen[rm.PID] = true
			out = append(out, Member{PID: rm.PID, Start: rm.Start})
		}
	}
	return out
}

// termProgress sends SIGKILL to survivors 5s after SIGTERM, or sooner if
// the group has grown by more than 1 GB since.
func (m *Machine) termProgress(s Snapshot, v *view) []Action {
	var acts []Action
	for _, r := range m.st.sortedRecords() {
		if r.Phase != PhaseTerm {
			continue
		}
		g := v.byKey[r.Key()]
		early := g != nil && g.FP > r.FPAtTerm && g.FP-r.FPAtTerm > m.cfg.KillEarlyGrowth
		if s.At.Sub(r.TermAt) < m.cfg.KillGrace && !early {
			continue
		}
		why := "5s after SIGTERM"
		if early {
			why = "group grew more than 1 GB after SIGTERM"
		}
		acts = append(acts, Action{Kind: ActKill, PGID: r.PGID, Start: r.LeaderStart, Reason: "SIGKILL survivors: " + why,
			Members: m.liveMembers(r, g), Cmd: r.Cmd, Agent: r.Agent, Signals: r.Signals, DangerSince: m.dangerSince()})
		delete(m.st.Groups, r.Key())
		m.dirty = true
	}
	return acts
}
