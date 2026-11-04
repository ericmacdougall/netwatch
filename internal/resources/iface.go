package resources

import "errors"

// Errors a Reader can return and callers can test with errors.Is.
var (
	// ErrUnsupported is returned by readers on platforms without a collector.
	ErrUnsupported = errors.New("resources: unsupported platform")
	// ErrNoAccess means the kernel refuses this reading for this process
	// (macOS only allows footprint reads for our own uid). Callers treat the
	// footprint as unknown rather than as a failure.
	ErrNoAccess = errors.New("resources: no access to process")
	// ErrGone means the process no longer exists.
	ErrGone = errors.New("resources: process gone")
)

// Prober is the tracker's allocation-light fast path. Probe fills p with
// everything except Exe (cwd and argv are separate calls): ids, start,
// state, tty, footprint and CPU time. A process we may not inspect gets
// FootprintOK=false and a nil error. A vanished process returns ErrGone.
type Prober interface {
	Probe(pid int, p *Proc) error
}

// Lister appends to a caller-owned slice so a poll does not allocate.
type Lister interface {
	// AppendGroupMembers appends the pids of group pgid to dst.
	AppendGroupMembers(dst []int, pgid int) ([]int, error)
	// AppendChildren appends the direct children of pid to dst.
	AppendChildren(dst []int, pid int) ([]int, error)
}

// Full is a Reader that also offers the fast paths. Both platform readers
// satisfy it.
type Full interface {
	Reader
	Prober
	Lister
}

// MaxListed bounds one pid listing so a fork bomb cannot make a poll
// allocate without limit.
const MaxListed = 1 << 16
