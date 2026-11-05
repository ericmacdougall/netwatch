package guard

import (
	"time"
)

// Restore adopts a persisted state after a restart and returns the
// actions needed to release what must not stay paused. A crash restart
// adopts the recorded pauses, except when the mode is off or alert, the
// maximum pause has passed, the episode has cleared, or the file version
// cannot be read. The clear hold restarts from now.
func (m *Machine) Restore(st State, now time.Time) []Action {
	m.mu.Lock()
	defer m.mu.Unlock()
	st.init()
	m.restoredAt = now
	m.dirty = true
	var acts []Action
	if st.Unreadable || !m.cfg.Mode.canPause() {
		why := "restart: mode " + string(m.cfg.Mode)
		if st.Unreadable {
			why = "restart: state file version cannot be read"
		}
		m.st = newState()
		for _, r := range st.sortedRecords() {
			acts = append(acts, m.resumeAction(r, why))
		}
		return acts
	}
	m.st = st
	for _, r := range st.sortedRecords() {
		switch {
		case r.Phase == PhaseTerm:
			// A kill was in flight: release the stopped members so the
			// pending SIGTERM lands; SIGKILL follows from Step.
			a := m.resumeAction(r, "restart: kill in progress")
			acts = append(acts, a)
		case now.Sub(r.PausedAt) >= m.cfg.MaxPause:
			acts = append(acts, m.resumeAction(r, "restart: maximum pause passed"))
			delete(m.st.Groups, r.Key())
		case st.Episode == nil || st.Episode.Cleared:
			acts = append(acts, m.resumeAction(r, "restart: episode cleared"))
			delete(m.st.Groups, r.Key())
		}
	}
	return acts
}

// Shutdown returns the actions for an orderly stop: resume every recorded
// group. If a kill is in progress it also sends SIGKILL to the members
// that already received SIGTERM, after SIGCONT, so nothing is left stopped
// with a signal pending.
func (m *Machine) Shutdown() []Action {
	m.mu.Lock()
	defer m.mu.Unlock()
	var acts []Action
	for _, r := range m.st.sortedRecords() {
		acts = append(acts, m.resumeAction(r, "orderly shutdown"))
		if r.Phase == PhaseTerm && m.killAllowed() {
			var termed []Member
			for _, x := range r.Members {
				if x.Termed {
					termed = append(termed, Member{PID: x.PID, Start: x.Start})
				}
			}
			acts = append(acts, Action{Kind: ActKill, PGID: r.PGID, Start: r.LeaderStart, Members: termed,
				Reason: "shutdown during kill: SIGKILL members already sent SIGTERM", Cmd: r.Cmd, Agent: r.Agent})
		}
		delete(m.st.Groups, r.Key())
	}
	m.st.Episode = nil
	m.dirty = true
	return acts
}

// Forget drops a record that was released outside the machine (a manual
// netwatch resume) and notes the resume time for the sticky rule.
func (m *Machine) Forget(key string, now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.st.Groups[key]; ok {
		delete(m.st.Groups, key)
		m.st.LastResume[key] = now
		m.dirty = true
	}
}

// ResumeKey resumes one recorded group on request (netwatch resume while
// the daemon runs): every recorded member gets SIGCONT, including members
// paused after the CLI read the state file.
func (m *Machine) ResumeKey(key string, now time.Time, why string) []Action {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.st.Groups[key]
	if !ok {
		return nil
	}
	a := m.resumeAction(r, why)
	delete(m.st.Groups, key)
	m.st.LastResume[key] = now
	if ep := m.st.Episode; ep != nil {
		// The user overrode the guard for this group: hold it for the rest
		// of the episode, or the next poll would pause it again (sticky,
		// and in pause+kill mode on the way to a kill). A kill already in
		// progress is cancelled the same way.
		if ep.Held == nil {
			ep.Held = map[string]bool{}
		}
		ep.Held[key] = true
	}
	m.dirty = true
	return []Action{a}
}

// RecordKeys lists the recorded group keys.
func (m *Machine) RecordKeys() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for k := range m.st.Groups {
		out = append(out, k)
	}
	return out
}

// Executor helpers: they mutate records under the lock.

func (m *Machine) addMembers(key string, mem []Member) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.st.Groups[key]
	if r == nil {
		return
	}
	for _, x := range mem {
		found := false
		for _, y := range r.Members {
			if y.PID == x.PID && y.Start.Equal(x.Start) {
				found = true
				break
			}
		}
		if !found {
			r.Members = append(r.Members, RecMember{PID: x.PID, Start: x.Start})
		}
	}
	m.dirty = true
}

func (m *Machine) markSig(key string, pid int, stopped, termed bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.st.Groups[key]
	if r == nil {
		return
	}
	for i := range r.Members {
		if r.Members[i].PID == pid {
			if stopped {
				r.Members[i].Sig = true
			}
			if termed {
				r.Members[i].Termed = true
			}
			m.dirty = true
		}
	}
}
