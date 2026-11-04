// Package resources defines the memory and process readings netwatch takes
// for resource sampling and the memory guard, and the per-platform readers
// that produce them. Readings are plain values so policy code (alerts,
// danger, guard) can be tested with synthetic series.
package resources

import "time"

// Level is the kernel memory-pressure level. The numeric values match
// macOS kern.memorystatus_vm_pressure_level; Linux maps PSI onto them.
type Level int

// Pressure levels.
const (
	LevelUnknown  Level = 0
	LevelNormal   Level = 1
	LevelWarn     Level = 2
	LevelCritical Level = 4
)

// String returns "normal", "warn", "critical" or "unknown".
func (l Level) String() string {
	switch l {
	case LevelNormal:
		return "normal"
	case LevelWarn:
		return "warn"
	case LevelCritical:
		return "critical"
	}
	return "unknown"
}

// System is one system-wide memory reading. Byte counts are bytes; page
// counts are pages of PageSize. Fields a platform cannot supply are zero.
type System struct {
	At       time.Time
	RAM      uint64 // physical memory, bytes
	PageSize uint64

	Free, Speculative, Purgeable, Inactive uint64 // pages

	CompressorBytes      uint64 // physical bytes the compressor occupies
	PagesCompressed      uint64 // logical pages held by the compressor
	PagesCompressedLimit uint64 // logical page limit of the compressor
	Segments             uint64 // compressor segments in use
	SegmentLimit         uint64

	SwapUsed, SwapTotal uint64 // bytes
	DiskFree            uint64 // bytes free on the volume holding swap

	Pressure Level
	Load1    float64

	// Linux only.
	PSIFullAvg10 float64
	MemAvailable uint64 // bytes
}

// Proc is one process. Footprint is the macOS phys_footprint (compressed
// and swapped pages included, at their logical size) or Linux RSS+swap.
type Proc struct {
	PID, PPID, PGID, SID, UID int
	Start                     time.Time
	Name                      string // short command name (comm)
	Exe                       string // resolved executable path, "" if unreadable
	Footprint                 uint64 // bytes; 0 if unreadable
	FootprintOK               bool   // false for processes we may not inspect
	RSS                       uint64
	CPUTime                   time.Duration
	HasTTY                    bool
	Stopped                   bool // state T
}

// Reader is the per-platform source of readings. Every method must be
// safe to call from several goroutines and must not block for long: the
// caller applies timeouts but a reader should not rely on them.
type Reader interface {
	// System returns a system-wide reading.
	System() (System, error)
	// Procs returns the full process table (the slow path, used by scans).
	Procs() ([]Proc, error)
	// Footprint re-reads one process cheaply (the tracker's fast path).
	// It returns the process start so callers can detect pid reuse.
	Footprint(pid int) (bytes uint64, start time.Time, err error)
	// GroupMembers lists the pids in a process group.
	GroupMembers(pgid int) ([]int, error)
	// Children lists the direct children of pid.
	Children(pid int) ([]int, error)
	// Sid returns the session id of pid (getsid(2)).
	Sid(pid int) (int, error)
	// Args returns argv, or nil. Callers redact before storing.
	Args(pid int) []string
	// Env returns only the requested keys from the process environment.
	// The full environment must never be retained.
	Env(pid int, keys ...string) map[string]string
	// Cwd returns the working directory, or "".
	Cwd(pid int) string
	// SelfTest checks the raw interfaces against our own process. A
	// failure disables pause and kill.
	SelfTest() error
}
