package guard

import (
	"time"

	"github.com/ericmacdougall/netwatch/internal/resources"
)

// ProcInfo is one live process as the executor and resume logic see it.
type ProcInfo struct {
	PID, PGID, SID int
	Start          time.Time
	Stopped        bool
}

// ProcView lets recovery and resume re-enumerate processes.
type ProcView interface {
	// Group lists the members of a process group.
	Group(pgid int) ([]ProcInfo, error)
	// Alive reports whether pid is still the process that started at start.
	Alive(pid int, start time.Time) bool
	// Stopped lists every stopped process of ours, for the fail-closed alert.
	Stopped() ([]ProcInfo, error)
}

// ReaderView adapts a resources.Reader. It uses the slow full-table path,
// which is fine for start-up, resume and rollback.
type ReaderView struct{ R resources.Reader }

func (v ReaderView) all() ([]ProcInfo, error) {
	ps, err := v.R.Procs()
	if err != nil {
		return nil, err
	}
	out := make([]ProcInfo, 0, len(ps))
	for _, p := range ps {
		out = append(out, ProcInfo{PID: p.PID, PGID: p.PGID, SID: p.SID, Start: p.Start, Stopped: p.Stopped})
	}
	return out, nil
}

// Group implements ProcView.
func (v ReaderView) Group(pgid int) ([]ProcInfo, error) {
	all, err := v.all()
	if err != nil {
		return nil, err
	}
	var out []ProcInfo
	for _, p := range all {
		if p.PGID == pgid {
			out = append(out, p)
		}
	}
	return out, nil
}

// Alive implements ProcView.
func (v ReaderView) Alive(pid int, start time.Time) bool {
	_, st, err := v.R.Footprint(pid)
	return err == nil && sameStart(st, start)
}

// Stopped implements ProcView.
func (v ReaderView) Stopped() ([]ProcInfo, error) {
	all, err := v.all()
	if err != nil {
		return nil, err
	}
	var out []ProcInfo
	for _, p := range all {
		if p.Stopped {
			out = append(out, p)
		}
	}
	return out, nil
}

// ReaderStart adapts a resources.Reader to StartReader.
type ReaderStart struct{ R resources.Reader }

// Start implements StartReader.
func (r ReaderStart) Start(pid int) (time.Time, error) {
	_, st, err := r.R.Footprint(pid)
	return st, err
}
