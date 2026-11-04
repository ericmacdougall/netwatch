package guard

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ericmacdougall/netwatch/internal/danger"
	"github.com/ericmacdougall/netwatch/internal/record"
)

// EventSink receives structured guard events (GUARD_PAUSE and so on).
// Fields must not contain argv text, only the redacted Cmd label.
type EventSink interface {
	Event(name string, fields map[string]any)
}

type nopSink struct{}

func (nopSink) Event(string, map[string]any) {}

// Executor applies the machine's actions. It re-reads each start time
// through the Signaller before every signal, signals per pid (leader
// first, then top-down), never signals an excluded member, and writes
// the intent to the store before it signals.
type Executor struct {
	M      *Machine
	Sig    Signaller
	Store  Store
	View   ProcView // optional; needed by Recover
	Clock  danger.Clock
	Events EventSink
	Notify Notifier // optional

	// SlowFsync is how long a store write may take before the pause goes
	// ahead anyway (2s). The write still completes in the background.
	SlowFsync time.Duration
	// Batch is the number of members signalled per fsync (cfg.BatchSize).
	Batch int

	seq       atomic.Uint64
	saveMu    sync.Mutex
	written   uint64
	persisted map[string]bool // keys a completed save contained
}

func (e *Executor) now() time.Time {
	if e.Clock != nil {
		return e.Clock.Now()
	}
	return time.Now()
}

func (e *Executor) events() EventSink {
	if e.Events == nil {
		return nopSink{}
	}
	return e.Events
}

func (e *Executor) notify(key, title, msg string) (bool, error) {
	if e.Notify == nil {
		return false, nil
	}
	return e.Notify.Notify(key, title, msg)
}

// save persists the machine's state. A write slower than SlowFsync does
// not hold up the caller; later writes supersede it (a stale one is
// skipped under the lock so an old state never overwrites a newer one).
func (e *Executor) save() (ms int64, slow bool, err error) {
	st := e.M.State()
	n := e.seq.Add(1)
	limit := e.SlowFsync
	if limit <= 0 {
		limit = 2 * time.Second
	}
	type res struct {
		d   time.Duration
		err error
	}
	ch := make(chan res, 1)
	go func() {
		e.saveMu.Lock()
		defer e.saveMu.Unlock()
		if n < e.written {
			ch <- res{}
			return
		}
		d, err := e.Store.Save(st)
		if err == nil {
			e.written = n
			e.persisted = make(map[string]bool, len(st.Groups))
			for k := range st.Groups {
				e.persisted[k] = true
			}
		}
		ch <- res{d, err}
	}()
	select {
	case r := <-ch:
		return r.d.Milliseconds(), false, r.err
	case <-time.After(limit):
		return limit.Milliseconds(), true, nil
	}
}

// Apply performs one poll's actions. Order: resumes first (the old state
// still records the groups, so a crash strands nothing), then one save
// that carries every new intent, then pauses, terms and kills.
func (e *Executor) Apply(acts []Action) {
	for _, a := range acts {
		if a.Kind == ActResume {
			e.applyResume(a)
		}
	}
	if _, slow, err := e.save(); err != nil {
		e.events().Event("GUARD_ERROR", map[string]any{"op": "save", "error": err.Error()})
	} else if slow {
		e.events().Event("GUARD_ERROR", map[string]any{"op": "save", "error": "slow fsync, continuing"})
	}
	for _, a := range acts {
		switch a.Kind {
		case ActAlert:
			e.applyAlert(a)
		case ActUnprotected:
			e.events().Event(record.HostAtRiskUnprotected, map[string]any{"reason": a.Reason, "signals": a.Signals, "footprint": a.Footprint})
			e.notify("unprotected", "Host at risk", a.Reason)
		case ActPause:
			e.applyPause(a)
		case ActTerm:
			e.applyTerm(a)
		case ActKill:
			e.applyKill(a)
		}
	}
	if e.M.Dirty() {
		if _, _, err := e.save(); err != nil {
			e.events().Event("GUARD_ERROR", map[string]any{"op": "save", "error": err.Error()})
		}
	}
}

func (e *Executor) applyAlert(a Action) {
	e.events().Event(record.ResourceAlert, map[string]any{
		"reason": a.Reason, "signals": a.Signals, "danger_since": a.DangerSince, "pgid": a.PGID, "cmd": a.Cmd, "agent": a.Agent,
	})
	e.notify("alert-"+fmt.Sprint(a.PGID), "Memory guard", a.Reason)
}

// orderMembers returns the non-excluded members with the leader first and
// then parents before children (top-down), pid as the tiebreak.
func orderMembers(pgid int, in []Member) (leader []Member, rest []Member) {
	byPID := map[int]Member{}
	for _, m := range in {
		if !m.Excluded {
			byPID[m.PID] = m
		}
	}
	depth := func(m Member) int {
		d := 0
		for cur := m; d < 64; d++ {
			p, ok := byPID[cur.PPID]
			if !ok || cur.PPID == cur.PID {
				break
			}
			cur = p
		}
		return d
	}
	for _, m := range byPID {
		if m.PID == pgid {
			leader = append(leader, m)
		} else {
			rest = append(rest, m)
		}
	}
	sort.Slice(rest, func(i, j int) bool {
		di, dj := depth(rest[i]), depth(rest[j])
		if di != dj {
			return di < dj
		}
		return rest[i].PID < rest[j].PID
	})
	return
}

func (e *Executor) sendTo(key string, ms []Member, sig syscall.Signal) (ok, failed int) {
	for _, m := range ms {
		if m.Excluded {
			continue
		}
		err := e.Sig.Signal(m.PID, m.Start, sig)
		if err != nil {
			failed++
			if !errors.Is(err, ErrStartMismatch) {
				e.events().Event("GUARD_ERROR", map[string]any{"op": "signal", "sig": sig.String(), "pid": m.PID, "error": err.Error()})
			}
			continue
		}
		ok++
		switch sig {
		case sigSTOP:
			e.M.markSig(key, m.PID, true, false)
		case sigTERM:
			e.M.markSig(key, m.PID, false, true)
		}
	}
	return
}

func (e *Executor) applyPause(a Action) {
	key := keyOf(a.PGID, a.Start)
	leader, rest := orderMembers(a.PGID, a.Members)
	first := a.Reason == "pause"
	var fsyncMS int64
	var signalledAt time.Time
	var slow bool
	stopped := 0
	if len(leader) > 0 {
		e.M.addMembers(key, leader)
		fsyncMS, slow, _ = e.save() // intent first, then signal
		signalledAt = e.now()
		ok, _ := e.sendTo(key, leader, sigSTOP)
		stopped += ok
	}
	batch := e.Batch
	if batch <= 0 {
		batch = 16
	}
	for i := 0; i < len(rest); i += batch {
		end := i + batch
		if end > len(rest) {
			end = len(rest)
		}
		chunk := rest[i:end]
		e.M.addMembers(key, chunk)
		ms, sl, _ := e.save()
		if fsyncMS == 0 {
			fsyncMS = ms
		}
		slow = slow || sl
		if signalledAt.IsZero() {
			signalledAt = e.now()
		}
		ok, _ := e.sendTo(key, chunk, sigSTOP)
		stopped += ok
	}
	if len(leader)+len(rest) > 0 {
		e.save() // record which members were signalled
	}
	if !first && stopped == 0 {
		return
	}
	name := record.GuardPause
	title := "Memory guard paused a job"
	if !first {
		name = "GUARD_PAUSE_MEMBERS"
		title = "Memory guard paused new children"
	}
	e.events().Event(name, map[string]any{
		"pgid": a.PGID, "signals": a.Signals, "danger_since": a.DangerSince, "signalled_at": signalledAt,
		"fsync_ms": fsyncMS, "slow_fsync": slow, "members": stopped, "cmd": a.Cmd, "agent": a.Agent,
		"footprint": a.Footprint, "reason": a.Reason,
	})
	if first {
		ok, err := e.notify(fmt.Sprintf("pause-%d", a.PGID), title,
			fmt.Sprintf("%s paused (pgid %d). Resume with: netwatch resume %d. A Claude Code tool timeout can still end a paused job.", a.Cmd, a.PGID, a.PGID))
		e.events().Event("GUARD_NOTIFY", map[string]any{"event": name, "notified": ok && err == nil})
	}
}

func (e *Executor) applyResume(a Action) {
	ms := append([]Member(nil), a.Members...)
	leader, rest := orderMembers(a.PGID, ms)
	n := 0
	ok, _ := e.sendTo("", append(leader, rest...), sigCONT)
	n += ok
	e.events().Event(record.GuardResume, map[string]any{"pgid": a.PGID, "reason": a.Reason, "members": n, "cmd": a.Cmd, "agent": a.Agent})
	e.notify(fmt.Sprintf("resume-%d", a.PGID), "Memory guard resumed a job", fmt.Sprintf("%s resumed (pgid %d): %s", a.Cmd, a.PGID, a.Reason))
}

func (e *Executor) applyTerm(a Action) {
	key := keyOf(a.PGID, a.Start)
	leader, rest := orderMembers(a.PGID, a.Members)
	all := append(leader, rest...)
	e.M.addMembers(key, all)
	e.save() // the kill intent is durable before the first signal
	// SIGTERM while stopped: the signal stays pending until SIGCONT, so
	// nothing runs between the two.
	e.sendTo(key, all, sigTERM)
	e.save()
	e.sendTo(key, all, sigCONT)
	e.events().Event(record.GuardKill, map[string]any{
		"pgid": a.PGID, "stage": "SIGTERM", "prong": a.Prong, "agent": a.Agent, "cmd": a.Cmd, "signals": a.Signals,
		"danger_since": a.DangerSince, "signalled_at": e.now(), "note": "resume from your last checkpoint",
	})
	ok, err := e.notify(fmt.Sprintf("kill-%d", a.PGID), "Memory guard killed a job",
		fmt.Sprintf("%s (pgid %d) was killed to keep the host up. Resume from your last checkpoint.", a.Cmd, a.PGID))
	e.events().Event("GUARD_NOTIFY", map[string]any{"event": record.GuardKill, "notified": ok && err == nil})
}

func (e *Executor) applyKill(a Action) {
	leader, rest := orderMembers(a.PGID, a.Members)
	ok, _ := e.sendTo("", append(leader, rest...), sigKILL)
	e.events().Event(record.GuardKill, map[string]any{
		"pgid": a.PGID, "stage": "SIGKILL", "reason": a.Reason, "killed": ok, "agent": a.Agent, "cmd": a.Cmd,
		"note": "resume from your last checkpoint",
	})
}

// Shutdown resumes everything for an orderly stop and persists the
// cleared state. A kill in flight gets SIGCONT then SIGKILL.
func (e *Executor) Shutdown() {
	e.Apply(e.M.Shutdown())
}

// RecoverReport says what start-up recovery found.
type RecoverReport struct {
	Adopted  []int
	Resumed  []int
	Stopped  []ProcInfo // stopped processes found when the state was unusable
	FailedOK bool       // true when recovery failed closed (missing or corrupt)
	Err      error
}

// Recover loads the persisted state at start-up and adopts or releases
// each recorded group. A missing or corrupt file fails closed: nothing is
// adopted, and a loud alert lists the stopped pids that were found. A
// stopped member of a recorded group that is not in the already-stopped
// set counts as netwatch's (a crash after a slow fsync strands nothing).
func (e *Executor) Recover() RecoverReport {
	var rep RecoverReport
	st, err := e.Store.Load()
	if err != nil {
		rep.Err = err
		rep.FailedOK = true
		if e.View != nil {
			rep.Stopped, _ = e.View.Stopped()
		}
		if errors.Is(err, ErrMissing) && len(rep.Stopped) == 0 {
			rep.FailedOK = false // first run: nothing to adopt, nothing stopped
			return rep
		}
		var pids []int
		for _, p := range rep.Stopped {
			pids = append(pids, p.PID)
		}
		msg := fmt.Sprintf("LOUD: guard state unusable (%v); nothing adopted. Stopped pids found: %v. Resume with: netwatch resume --all", err, pids)
		e.events().Event(record.ResourceAlert, map[string]any{"reason": msg, "stopped_pids": pids})
		e.notify("guard-state-lost", "Memory guard state lost", msg)
		return rep
	}
	st.init()
	if e.View != nil {
		for _, r := range st.Groups {
			procs, err := e.View.Group(r.PGID)
			if err != nil {
				continue
			}
			for _, p := range procs {
				if !p.Stopped || p.Start.Before(r.LeaderStart) || recorded(r, p) {
					continue
				}
				r.Members = append(r.Members, RecMember{PID: p.PID, Start: p.Start, Sig: true})
			}
		}
	}
	acts := e.M.Restore(st, e.now())
	for _, a := range acts {
		rep.Resumed = append(rep.Resumed, a.PGID)
	}
	for _, k := range e.M.RecordKeys() {
		rep.Adopted = append(rep.Adopted, e.M.pgidOf(k))
	}
	sort.Ints(rep.Adopted)
	e.Apply(acts)
	return rep
}

func recorded(r *Record, p ProcInfo) bool {
	for _, m := range r.Members {
		if m.PID == p.PID && sameStart(m.Start, p.Start) {
			return true
		}
	}
	for _, m := range r.Already {
		if m.PID == p.PID && sameStart(m.Start, p.Start) {
			return true
		}
	}
	return false
}

func (m *Machine) pgidOf(key string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r := m.st.Groups[key]; r != nil {
		return r.PGID
	}
	return 0
}

// Reconcile drops records the CLI removed with netwatch resume, so the
// daemon does not re-pause a group the user released. It compares the
// machine with the file. Call it at the start of a poll, before Step.
func (e *Executor) Reconcile() error {
	st, err := e.Store.Load()
	if err != nil {
		return err
	}
	e.saveMu.Lock()
	known := make(map[string]bool, len(e.persisted))
	for k := range e.persisted {
		known[k] = true
	}
	e.saveMu.Unlock()
	for _, k := range e.M.RecordKeys() {
		// Only a record that an earlier save wrote can have been removed
		// by the CLI; a brand-new one is simply not on disk yet.
		if _, ok := st.Groups[k]; !ok && known[k] {
			e.M.Forget(k, e.now())
		}
	}
	return nil
}
