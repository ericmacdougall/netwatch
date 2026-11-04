package budget

import (
	"time"

	"github.com/ericmacdougall/netwatch/internal/resources"
)

// ReaderFacts adapts a resources.Reader. It snapshots the process table
// once, so all checks in one Load see a consistent view.
type ReaderFacts struct {
	r     resources.Reader
	procs map[int]resources.Proc
}

// NewReaderFacts reads the process table from r.
func NewReaderFacts(r resources.Reader) (*ReaderFacts, error) {
	ps, err := r.Procs()
	if err != nil {
		return nil, err
	}
	m := make(map[int]resources.Proc, len(ps))
	for _, p := range ps {
		m[p.PID] = p
	}
	return &ReaderFacts{r: r, procs: m}, nil
}

// Start implements Facts.
func (f *ReaderFacts) Start(pid int) (time.Time, bool) {
	p, ok := f.procs[pid]
	return p.Start, ok
}

// Argv implements Facts.
func (f *ReaderFacts) Argv(pid int) []string { return f.r.Args(pid) }

// Parent implements Facts.
func (f *ReaderFacts) Parent(pid int) (int, bool) {
	p, ok := f.procs[pid]
	return p.PPID, ok
}

// PGID implements Facts.
func (f *ReaderFacts) PGID(pid int) (int, bool) {
	p, ok := f.procs[pid]
	return p.PGID, ok
}

// GroupSize implements Facts.
func (f *ReaderFacts) GroupSize(pgid int) int {
	n := 0
	for _, p := range f.procs {
		if p.PGID == pgid {
			n++
		}
	}
	return n
}
