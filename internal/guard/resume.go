package guard

import (
	"errors"
	"fmt"
	"sort"
	"time"
)

// Resume errors.
var (
	// ErrNotRecorded: netwatch did not stop that group (or its recorded
	// start times no longer match), so resume refuses it.
	ErrNotRecorded = errors.New("guard: no such paused group recorded by netwatch")
	// ErrPausedRemain: the rollback gate refuses while live paused groups
	// remain.
	ErrPausedRemain = errors.New("guard: live paused groups remain; run netwatch guard alert and netwatch resume --all first")
)

// ResumeReport says what a manual resume did.
type ResumeReport struct {
	Resumed []int    // pgids released
	Pruned  []int    // pgids dropped because every recorded pid is dead or mismatched
	Skipped []string // notes
}

// prune drops recorded members that are dead or whose start time no longer
// matches (a reused pid), and records with no live member left. It
// returns the pgids of dropped records (A5).
func prune(st *State, view ProcView) []int {
	var dropped []int
	for k, r := range st.Groups {
		live := r.Members[:0:0]
		for _, m := range r.Members {
			if view == nil || view.Alive(m.PID, m.Start) {
				live = append(live, m)
			}
		}
		r.Members = live
		if len(live) == 0 && view != nil && !view.Alive(r.PGID, r.LeaderStart) {
			dropped = append(dropped, r.PGID)
			delete(st.Groups, k)
		}
	}
	sort.Ints(dropped)
	return dropped
}

// ManualResume implements netwatch resume PGID|--all against the persisted
// state. It fails closed (no signal at all) when the state file is
// missing, corrupt or unsafe, refuses a group netwatch did not stop, and
// prunes dead or mismatched pids first. The daemon notices the removal
// through Executor.Reconcile.
func ManualResume(store Store, view ProcView, sig Signaller, now time.Time, pgid int, all bool) (ResumeReport, error) {
	return ManualResumeLive(store, view, sig, now, pgid, all, nil)
}

// ManualResumeLive is ManualResume for either case. With req nil, no
// daemon runs (the caller holds the run lock) and the state file is
// updated directly. With req set, a daemon runs: the CLI sends SIGCONT at
// once for the user, never writes the state file, and files a request per
// group so the daemon drops the record and resumes any member it stopped
// since.
func ManualResumeLive(store Store, view ProcView, sig Signaller, now time.Time, pgid int, all bool, req ResumeRequests) (ResumeReport, error) {
	var rep ResumeReport
	st, err := store.Load()
	if err != nil {
		return rep, fmt.Errorf("resume refused, state unusable: %w", err)
	}
	st.init()
	rep.Pruned = prune(&st, view)
	var targets []*Record
	if all {
		targets = st.sortedRecords()
	} else {
		for _, r := range st.Groups {
			if r.PGID == pgid {
				targets = append(targets, r)
			}
		}
		if len(targets) == 0 {
			if len(rep.Pruned) > 0 && req == nil {
				store.Save(st)
			}
			return rep, fmt.Errorf("%w: pgid %d", ErrNotRecorded, pgid)
		}
	}
	for _, r := range targets {
		leader, rest := orderMembers(r.PGID, recMembers(r))
		n := 0
		for _, m := range append(leader, rest...) {
			if err := sig.Signal(m.PID, m.Start, sigCONT); err == nil {
				n++
			} else if !errors.Is(err, ErrStartMismatch) {
				rep.Skipped = append(rep.Skipped, fmt.Sprintf("pid %d: %v", m.PID, err))
			}
		}
		rep.Resumed = append(rep.Resumed, r.PGID)
		if req != nil {
			if err := req.Add(r.Key()); err != nil {
				return rep, fmt.Errorf("resume request for pgid %d: %w", r.PGID, err)
			}
			continue
		}
		delete(st.Groups, r.Key())
		st.LastResume[r.Key()] = now
	}
	sort.Ints(rep.Resumed)
	if req != nil {
		return rep, nil
	}
	if _, err := store.Save(st); err != nil {
		return rep, err
	}
	return rep, nil
}

func recMembers(r *Record) []Member {
	var out []Member
	for _, m := range r.Members {
		out = append(out, Member{PID: m.PID, Start: m.Start})
	}
	return out
}

// RollbackReport is the result of the rollback gate.
type RollbackReport struct {
	Live        []int // pgids of live, matching paused groups
	StoppedPIDs []int // with force: the pids the swap leaves stopped
	Forced      bool
}

// RollbackGate is the check the harness rollback runs before swapping the
// binary: it prunes, then refuses (ErrPausedRemain) while any live,
// matching paused group remains. With force it proceeds and lists every
// stopped pid it leaves behind. A missing file means nothing is paused; a
// corrupt or unsafe file refuses unless forced.
func RollbackGate(store Store, view ProcView, force bool) (RollbackReport, error) {
	var rep RollbackReport
	st, err := store.Load()
	if err != nil {
		if errors.Is(err, ErrMissing) {
			return rep, nil
		}
		if force {
			rep.Forced = true
			return rep, nil
		}
		return rep, fmt.Errorf("rollback refused, state unusable: %w", err)
	}
	st.init()
	prune(&st, view)
	for _, r := range st.sortedRecords() {
		rep.Live = append(rep.Live, r.PGID)
		for _, m := range r.Members {
			if m.Sig {
				rep.StoppedPIDs = append(rep.StoppedPIDs, m.PID)
			}
		}
	}
	if len(rep.Live) == 0 {
		return rep, nil
	}
	if !force {
		rep.StoppedPIDs = nil
		return rep, ErrPausedRemain
	}
	rep.Forced = true
	sort.Ints(rep.StoppedPIDs)
	return rep, nil
}
