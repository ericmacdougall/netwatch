package guard

import "time"

// baselineFor is one term's footprint at the shared baseline instant
// (danger_since - 60s), using the spec's rules:
//   - a group whose leader started after the baseline did not exist then: 0;
//   - otherwise the reading nearest the baseline instant, among readings
//     taken no later than danger_since;
//   - with no such reading, 0 if a member started after the baseline,
//     else the first observed value (so a big job first seen mid-episode
//     does not count as 100% growth).
func baselineFor(t *Term, baseAt, since time.Time) uint64 {
	if t.Group != nil && t.Group.LeaderStart.After(baseAt) {
		return 0
	}
	best, bestD := -1, time.Duration(1<<62)
	for i, p := range t.Series {
		if p.At.After(since) {
			continue
		}
		d := p.At.Sub(baseAt)
		if d < 0 {
			d = -d
		}
		if d < bestD {
			best, bestD = i, d
		}
	}
	if best >= 0 {
		return t.Series[best].Bytes
	}
	if t.Group != nil {
		for _, mem := range t.Group.Members {
			if mem.Start.After(baseAt) {
				return 0
			}
		}
	}
	if len(t.Series) > 0 {
		return t.Series[0].Bytes
	}
	return 0
}

// ensureBaselines records, once, each term's baseline and its footprint at
// the start of the episode. Terms first seen later get theirs on first
// sight. The 60s ring cannot be consulted at kill time, so they persist.
func (m *Machine) ensureBaselines(s Snapshot, v *view) {
	ep := m.st.Episode
	for i := range v.terms {
		t := &v.terms[i]
		if _, ok := ep.Baselines[t.Key]; ok {
			continue
		}
		ep.Baselines[t.Key] = baselineFor(t, ep.BaselineAt, ep.Since)
		// Footprint "since danger began": what it held when it was first
		// seen in the episode, or 0 if it was born after danger began.
		db := fpOf(t)
		if t.Group != nil && t.Group.LeaderStart.After(ep.Since) {
			db = 0
		}
		ep.DangerBase[t.Key] = db
		m.dirty = true
	}
}

func pos(cur, base uint64) uint64 {
	if cur > base {
		return cur - base
	}
	return 0
}

// growthShare is the candidate's positive delta over the sum of positive
// deltas of every term (agent groups, ineligible aggregates and
// unattributed), the candidate included, so it is at most 1.
func (m *Machine) growthShare(v *view, key string) (share float64, num, den uint64) {
	ep := m.st.Episode
	if ep == nil {
		return 0, 0, 0
	}
	for i := range v.terms {
		t := &v.terms[i]
		d := pos(fpOf(t), ep.Baselines[t.Key])
		den += d
		if t.Key == key {
			num = d
		}
	}
	if den == 0 {
		return 0, num, den
	}
	return float64(num) / float64(den), num, den
}

// scanFresh reports whether the last full scan succeeded and is younger
// than two scan intervals; the share prong needs it, D4 does not.
func (m *Machine) scanFresh(s Snapshot) bool {
	return s.ScanOK && !s.ScanAt.IsZero() && s.At.Sub(s.ScanAt) < 2*m.cfg.ScanInterval
}
