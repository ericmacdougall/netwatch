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
	// ErrNotStopped: resume --pid found no stopped process with that pid.
	ErrNotStopped = errors.New("guard: no stopped process with that pid")
	// ErrNotOwn: resume --pid only continues the caller's own processes.
	ErrNotOwn = errors.New("guard: that process belongs to another user")
	// ErrInRecord: the pid is a member of a group netwatch recorded; resume
	// the group instead so the record is released with it.
	ErrInRecord = errors.New("guard: that pid is in a paused group netwatch recorded")
)

// ResumePID continues one stopped process of the caller's own uid. It is
// the recovery path when the state file is unusable and a job netwatch
// stopped would otherwise stay frozen. It refuses a pid that is not
// stopped, belongs to another uid, or is a member of a usable record (use
// ManualResume for that group). The signaller re-reads the start time
// immediately before SIGCONT.
func ResumePID(store Store, view ProcView, sig Signaller, pid, uid int) error {
	if pid <= 1 {
		return fmt.Errorf("%w: %d", ErrRefused, pid)
	}
	stopped, err := view.Stopped()
	if err != nil {
		return err
	}
	var p *ProcInfo
	for i := range stopped {
		if stopped[i].PID == pid {
			p = &stopped[i]
		}
	}
	if p == nil {
		return fmt.Errorf("%w: %d", ErrNotStopped, pid)
	}
	if p.UID != uid {
		return fmt.Errorf("%w: %d", ErrNotOwn, pid)
	}
	if st, err := store.Load(); err == nil {
		for _, r := range st.Groups {
			for _, m := range r.Members {
				if m.PID == pid {
					return fmt.Errorf("%w: pid %d, group %d; run netwatch resume %d", ErrInRecord, pid, r.PGID, r.PGID)
				}
			}
		}
	}
	return sig.Signal(pid, p.Start, sigCONT)
}

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
	return manualResume(store, view, sig, now, pgid, all, req, nil)
}

// ManualResumeApplying is the no-daemon case (the caller holds the run
// lock) that first applies pending: resume requests a daemon filed for
// but never took, for example because it crashed. They are the user's
// earlier resumes, keyed by leader start time, so they can only match the
// same groups; dropping them would let a restarted daemon stop those
// groups again.
func ManualResumeApplying(store Store, view ProcView, sig Signaller, now time.Time, pgid int, all bool, pending []string) (ResumeReport, error) {
	return manualResume(store, view, sig, now, pgid, all, nil, pending)
}

// unusableHint tells the user the way out when the state file cannot be
// trusted: nothing is recorded, so groups are resumed one pid at a time.
const unusableHint = "list your stopped processes with: netwatch resume --all --check --force; resume one with: netwatch resume --pid PID"

// hintFor adds the right way out. A missing file is the normal state of an
// install whose daemon never paused anything, so there is nothing to resume.
func hintFor(err error) string {
	if errors.Is(err, ErrMissing) {
		return "no state file means netwatch has not paused anything on this install (resume fails closed by design); to check for stopped processes of yours: netwatch resume --all --check --force"
	}
	return unusableHint
}

func manualResume(store Store, view ProcView, sig Signaller, now time.Time, pgid int, all bool, req ResumeRequests, pending []string) (ResumeReport, error) {
	var rep ResumeReport
	st, err := store.Load()
	if err != nil {
		return rep, fmt.Errorf("resume refused, state unusable: %w; %s", err, hintFor(err))
	}
	st.init()
	rep.Pruned = prune(&st, view)
	dirty := len(rep.Pruned) > 0
	applied := map[int]bool{}
	if req == nil {
		for _, k := range pending {
			if r, ok := st.Groups[k]; ok {
				resumeMembers(r, sig, &rep)
				release(&st, r, now)
				applied[r.PGID] = true
				dirty = true
			}
		}
	}
	var targets []*Record
	if all {
		targets = st.sortedRecords()
	} else {
		for _, r := range st.Groups {
			if r.PGID == pgid {
				targets = append(targets, r)
			}
		}
		if len(targets) == 0 && !applied[pgid] {
			if dirty && req == nil {
				store.Save(st)
			}
			return rep, fmt.Errorf("%w: pgid %d", ErrNotRecorded, pgid)
		}
	}
	for pg := range applied {
		rep.Resumed = append(rep.Resumed, pg)
	}
	for _, r := range targets {
		resumeMembers(r, sig, &rep)
		rep.Resumed = append(rep.Resumed, r.PGID)
		if req != nil {
			if err := req.Add(r.Key()); err != nil {
				return rep, fmt.Errorf("resume request for pgid %d: %w", r.PGID, err)
			}
			continue
		}
		release(&st, r, now)
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

// resumeMembers sends SIGCONT to every recorded member, leader first.
func resumeMembers(r *Record, sig Signaller, rep *ResumeReport) {
	leader, rest := orderMembers(r.PGID, recMembers(r))
	for _, m := range append(leader, rest...) {
		if err := sig.Signal(m.PID, m.Start, sigCONT); err != nil && !errors.Is(err, ErrStartMismatch) {
			rep.Skipped = append(rep.Skipped, fmt.Sprintf("pid %d: %v", m.PID, err))
		}
	}
}

// release drops the record of a group the user resumed and holds it for
// the rest of the episode: the same effect as the daemon's ResumeKey, so
// a daemon that starts during this episode does not pause it again.
func release(st *State, r *Record, now time.Time) {
	delete(st.Groups, r.Key())
	st.LastResume[r.Key()] = now
	if st.Episode != nil {
		if st.Episode.Held == nil {
			st.Episode.Held = map[string]bool{}
		}
		st.Episode.Held[r.Key()] = true
	}
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
	// Unusable is set (with force) when the state could not be read; then
	// StoppedPIDs lists every stopped process of uid that was found.
	Unusable error
}

// RollbackGate is the check the harness rollback runs before swapping the
// binary: it prunes, then refuses (ErrPausedRemain) while any live,
// matching paused group remains. With force it proceeds and lists every
// stopped pid it leaves behind. A missing file means nothing is paused; a
// corrupt or unsafe file refuses unless forced.
func RollbackGate(store Store, view ProcView, uid int, force bool) (RollbackReport, error) {
	var rep RollbackReport
	st, err := store.Load()
	if err != nil {
		if errors.Is(err, ErrMissing) {
			return rep, nil
		}
		if force {
			rep.Forced = true
			rep.Unusable = err
			if ps, verr := view.Stopped(); verr == nil {
				for _, p := range ps {
					if p.UID == uid {
						rep.StoppedPIDs = append(rep.StoppedPIDs, p.PID)
					}
				}
			}
			sort.Ints(rep.StoppedPIDs)
			return rep, nil
		}
		return rep, fmt.Errorf("rollback refused, state unusable: %w; %s", err, hintFor(err))
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
