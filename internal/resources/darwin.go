//go:build darwin

package resources

import (
	"encoding/binary"
	"errors"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// darwinReader reads the macOS kernel through sysctl and proc_info. Process
// tables come from kern.proc.all; per-process memory from proc_info, which
// the kernel only answers for our own uid (and root). Other processes get
// FootprintOK=false.
type darwinReader struct {
	self  int
	uid   uint32
	tbHz  uint64 // mach absolute time ticks per second (hw.tbfrequency)
	pages sync.Pool
}

// New returns the macOS reader.
func New() Full {
	r := &darwinReader{self: os.Getpid(), uid: uint32(os.Geteuid()), tbHz: 1_000_000_000}
	if v, ok := sysU("hw.tbfrequency"); ok && v > 0 {
		r.tbHz = v
	}
	r.pages.New = func() any { b := make([]int32, 4096); return &b }
	return r
}

// sysU reads a numeric sysctl of 4 or 8 bytes.
func sysU(name string) (uint64, bool) {
	b, err := unix.SysctlRaw(name)
	if err != nil {
		return 0, false
	}
	switch len(b) {
	case 4:
		return uint64(binary.LittleEndian.Uint32(b)), true
	case 8:
		return binary.LittleEndian.Uint64(b), true
	}
	return 0, false
}

// System implements Reader.
func (r *darwinReader) System() (System, error) {
	s := System{At: time.Now()}
	ok := true
	get := func(dst *uint64, name string) {
		v, found := sysU(name)
		*dst = v
		if !found {
			ok = false
		}
	}
	// The five counters the guard cannot work without.
	get(&s.RAM, "hw.memsize")
	get(&s.PageSize, "vm.pagesize")
	get(&s.Free, "vm.page_free_count")
	get(&s.Speculative, "vm.page_speculative_count")
	get(&s.Purgeable, "vm.page_purgeable_count")
	if !ok {
		return s, ErrUnsupported
	}
	// vm.page_inactive_count does not exist on current macOS. Inactive then
	// falls back to file-backed pageable pages, which the kernel keeps on
	// the inactive and speculative queues; the flag tells callers (and the
	// field check) that the number is a proxy.
	if v, found := sysU("vm.page_inactive_count"); found {
		s.Inactive = v
	} else if v, found := sysU("vm.page_pageable_external_count"); found {
		s.Inactive, s.InactiveEstimated = v, true
	}
	// Compressor facts are optional: a Mac without them reports zero and
	// the guard's D2 simply never fires.
	sysU2(&s.CompressorBytes, "vm.compressor_bytes_used")
	sysU2(&s.PagesCompressed, "vm.compressor.pages_compressed")
	sysU2(&s.PagesCompressedLimit, "vm.compressor.pages_compressed_limit")
	sysU2(&s.SegmentLimit, "vm.compressor.segment.limit")
	if v, found := sysU("vm.compressor.segment.total"); found {
		var empty uint64
		sysU2(&empty, "vm.compressor.segment.empty")
		if v >= empty {
			s.Segments = v - empty
		}
	}
	if b, err := unix.SysctlRaw("vm.swapusage"); err == nil {
		s.SwapTotal, s.SwapUsed, _ = ParseSwapUsage(b)
	}
	if v, found := sysU("kern.memorystatus_vm_pressure_level"); found {
		switch Level(v) {
		case LevelNormal, LevelWarn, LevelCritical:
			s.Pressure = Level(v)
		}
	}
	if b, err := unix.SysctlRaw("vm.loadavg"); err == nil {
		s.Load1, _ = ParseLoadavg(b)
	}
	var st unix.Statfs_t
	if unix.Statfs("/System/Volumes/VM", &st) != nil && unix.Statfs("/", &st) != nil {
		return s, nil
	}
	s.DiskFree = st.Bavail * uint64(st.Bsize)
	return s, nil
}

func sysU2(dst *uint64, name string) {
	if v, ok := sysU(name); ok {
		*dst = v
	}
}

func (r *darwinReader) ticksToDuration(t uint64) time.Duration {
	// Split the multiplication to avoid overflow on long CPU times.
	sec := t / r.tbHz
	rem := t % r.tbHz
	return time.Duration(sec)*time.Second + time.Duration(rem*1_000_000_000/r.tbHz)
}

// fillKinfo copies the fields of a kinfo_proc into p.
func (r *darwinReader) fillKinfo(k *unix.KinfoProc, p *Proc) {
	*p = Proc{
		PID:     int(k.Proc.P_pid),
		PPID:    int(k.Eproc.Ppid),
		PGID:    int(k.Eproc.Pgid),
		SID:     -1,
		UID:     int(k.Eproc.Ucred.Uid),
		Start:   time.Unix(int64(k.Proc.P_starttime.Sec), int64(k.Proc.P_starttime.Usec)*1000),
		Name:    cstr(k.Proc.P_comm[:]),
		HasTTY:  k.Eproc.Tdev != -1 && k.Eproc.Tdev != 0, // NODEV is (dev_t)-1
		Stopped: k.Proc.P_stat == 4,                      // SSTOP
	}
}

// fillMem adds footprint, RSS and CPU time for a process we may inspect.
func (r *darwinReader) fillMem(p *Proc) {
	if uint32(p.UID) != r.uid && r.uid != 0 {
		return
	}
	var ru rusageInfoV2
	if rusage(p.PID, &ru) != nil {
		return // EPERM (hardened or other uid) or the process just exited
	}
	p.Footprint, p.FootprintOK = ru.PhysFootprint, true
	p.RSS = ru.ResidentSize
	p.CPUTime = r.ticksToDuration(ru.UserTime + ru.SystemTime)
}

// Probe implements Prober.
func (r *darwinReader) Probe(pid int, p *Proc) error {
	k, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || int(k.Proc.P_pid) != pid {
		return ErrGone
	}
	r.fillKinfo(k, p)
	r.fillMem(p)
	if sid, err := unix.Getsid(pid); err == nil {
		p.SID = sid
	}
	return nil
}

// Procs implements Reader.
func (r *darwinReader) Procs() ([]Proc, error) {
	ks, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil, err
	}
	out := make([]Proc, 0, len(ks))
	for i := range ks {
		if ks[i].Proc.P_pid <= 0 {
			continue
		}
		var p Proc
		r.fillKinfo(&ks[i], &p)
		r.fillMem(&p)
		p.Exe = pidPath(p.PID)
		if sid, err := unix.Getsid(p.PID); err == nil {
			p.SID = sid
		}
		out = append(out, p)
	}
	return out, nil
}

// Footprint implements Reader.
func (r *darwinReader) Footprint(pid int) (uint64, time.Time, error) {
	var p Proc
	if err := r.Probe(pid, &p); err != nil {
		return 0, time.Time{}, err
	}
	if !p.FootprintOK {
		return 0, p.Start, ErrNoAccess
	}
	return p.Footprint, p.Start, nil
}

// appendPIDs lists with a pooled buffer, growing it if the kernel filled it.
func (r *darwinReader) appendPIDs(dst []int, typ, arg int) ([]int, error) {
	bp := r.pages.Get().(*[]int32)
	defer r.pages.Put(bp)
	for {
		buf := *bp
		n, err := listPIDs(typ, arg, buf)
		if err != nil {
			if err == unix.ESRCH {
				return dst, nil
			}
			return dst, err
		}
		cnt := n / 4
		if cnt >= len(buf) && len(buf) < MaxListed {
			*bp = make([]int32, len(buf)*4)
			continue
		}
		for _, p := range buf[:cnt] {
			if p > 0 {
				dst = append(dst, int(p))
			}
		}
		return dst, nil
	}
}

// AppendGroupMembers implements Lister.
func (r *darwinReader) AppendGroupMembers(dst []int, pgid int) ([]int, error) {
	return r.appendPIDs(dst, listPGRPOnly, pgid)
}

// AppendChildren implements Lister.
func (r *darwinReader) AppendChildren(dst []int, pid int) ([]int, error) {
	return r.appendPIDs(dst, listPPIDOnly, pid)
}

// GroupMembers implements Reader.
func (r *darwinReader) GroupMembers(pgid int) ([]int, error) {
	return r.AppendGroupMembers(nil, pgid)
}

// Children implements Reader.
func (r *darwinReader) Children(pid int) ([]int, error) { return r.AppendChildren(nil, pid) }

// Sid implements Reader.
func (r *darwinReader) Sid(pid int) (int, error) {
	sid, err := unix.Getsid(pid)
	if err == unix.ESRCH {
		return 0, ErrGone
	}
	return sid, err
}

func (r *darwinReader) procargs(pid int) []byte {
	b, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		return nil
	}
	return b
}

// Args implements Reader.
func (r *darwinReader) Args(pid int) []string {
	argv, _ := ParseProcArgs2(r.procargs(pid))
	return argv
}

// Env implements Reader. The raw buffer lives only inside this call.
func (r *darwinReader) Env(pid int, keys ...string) map[string]string {
	_, env := ParseProcArgs2(r.procargs(pid), keys...)
	return env
}

// Cwd implements Reader.
func (r *darwinReader) Cwd(pid int) string { return vnodeCwd(pid) }

// SelfTest implements Reader. On top of the common check it cross-reads
// our resident size through two different structs (proc_taskinfo and
// rusage_info_v2); a layout mistake in either puts them far apart.
func (r *darwinReader) SelfTest() error {
	if err := selfTest(r, r.self); err != nil {
		return err
	}
	var ti procTaskInfo
	var ru rusageInfoV2
	if err := taskInfo(r.self, &ti); err != nil {
		return err
	}
	if err := rusage(r.self, &ru); err != nil {
		return err
	}
	a, b := float64(ti.ResidentSize), float64(ru.ResidentSize)
	if a == 0 || b == 0 || a/b > 2 || b/a > 2 || ru.PhysFootprint == 0 {
		return errLayout
	}
	return nil
}

var errLayout = errors.New("self-test: proc_taskinfo and rusage_info_v2 disagree; struct layout is wrong")

// ExePath implements ExeResolver.
func (r *darwinReader) ExePath(pid int) string { return pidPath(pid) }
