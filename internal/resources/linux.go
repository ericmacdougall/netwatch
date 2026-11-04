//go:build linux

package resources

import (
	"os"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// linuxReader reads /proc. Every read is bounded: a fixed buffer for the
// small stat and status files, MaxProcArgs for environ, and a cap on the
// number of /proc entries listed.
type linuxReader struct {
	boot     time.Time
	pageSize uint64
	self     int
	root     string // "/proc"; tests point it at a fixture tree

	bufPool sync.Pool
}

// New returns the Linux reader.
func New() Full { return newLinux("/proc") }

func newLinux(root string) *linuxReader {
	r := &linuxReader{pageSize: uint64(os.Getpagesize()), self: os.Getpid(), root: root}
	r.bufPool.New = func() any { b := make([]byte, 8192); return &b }
	if b, err := r.read(root+"/stat", 64<<10); err == nil {
		r.boot, _ = ParseBtime(b)
	}
	return r
}

// read returns at most max bytes of path (a longer file is truncated, never
// followed past the cap). /proc is trusted kernel output, but the bound
// keeps a misbehaving mount from exhausting memory.
func (r *linuxReader) read(path string, max int) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	out := make([]byte, 0, 4096)
	for len(out) < max {
		if cap(out)-len(out) < 4096 {
			n := cap(out) * 2
			if n > max {
				n = max
			}
			if n <= len(out) {
				break
			}
			nb := make([]byte, len(out), n)
			copy(nb, out)
			out = nb
		}
		n, err := unix.Read(fd, out[len(out):cap(out)])
		if n > 0 {
			out = out[:len(out)+n]
		}
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return out, err
		}
		if n == 0 {
			break
		}
	}
	return out, nil
}

// readSmall reads into a pooled buffer and hands it to fn; no allocation
// survives the call.
func (r *linuxReader) readSmall(path string, fn func([]byte)) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	bp := r.bufPool.Get().(*[]byte)
	defer r.bufPool.Put(bp)
	b := *bp
	n := 0
	for n < len(b) {
		m, err := unix.Read(fd, b[n:])
		if m > 0 {
			n += m
		}
		if err == unix.EINTR {
			continue
		}
		if err != nil || m == 0 {
			break
		}
	}
	unix.Close(fd)
	fn(b[:n])
	return nil
}

func (r *linuxReader) procPath(buf []byte, pid int, name string) string {
	buf = append(buf[:0], r.root...)
	buf = append(buf, '/')
	buf = strconv.AppendInt(buf, int64(pid), 10)
	buf = append(buf, '/')
	buf = append(buf, name...)
	return string(buf)
}

// System implements Reader.
func (r *linuxReader) System() (System, error) {
	var s System
	s.At = time.Now()
	b, err := r.read(r.root+"/meminfo", 64<<10)
	if err != nil {
		return s, err
	}
	m := ParseMeminfo(b)
	ps := r.pageSize
	s.RAM, s.PageSize = m.Total, ps
	s.Free = m.Free / ps
	s.Inactive = m.Inactive / ps
	s.MemAvailable = m.Available
	s.SwapTotal = m.SwapTotal
	if m.SwapTotal >= m.SwapFree {
		s.SwapUsed = m.SwapTotal - m.SwapFree
	}
	if b, err := r.read(r.root+"/pressure/memory", 4096); err == nil {
		if _, full, ok := ParsePSI(b); ok {
			s.PSIFullAvg10 = full
			s.Pressure = PSILevel(full)
		}
	} // no PSI (old kernel or disabled): Pressure stays LevelUnknown
	if b, err := r.read(r.root+"/loadavg", 256); err == nil {
		for i, c := range b {
			if c == ' ' {
				s.Load1, _ = strconv.ParseFloat(string(b[:i]), 64)
				break
			}
		}
	}
	var st unix.Statfs_t
	if unix.Statfs("/", &st) == nil {
		s.DiskFree = st.Bavail * uint64(st.Bsize)
	}
	return s, nil
}

// Probe implements Prober.
func (r *linuxReader) Probe(pid int, p *Proc) error {
	var pb [96]byte
	var sf StatFields
	var ok bool
	if err := r.readSmall(r.procPath(pb[:0], pid, "stat"), func(b []byte) { sf, ok = ParseStat(b) }); err != nil {
		return ErrGone
	}
	if !ok {
		return ErrGone
	}
	*p = Proc{PID: pid, PPID: sf.PPID, PGID: sf.PGRP, SID: sf.Session, Name: sf.Comm,
		HasTTY: sf.TTYNr != 0, Stopped: sf.State == 'T' || sf.State == 't',
		Start:   StartFromTicks(r.boot, sf.StartTicks),
		CPUTime: time.Duration(sf.UTime+sf.STime) * (time.Second / 100),
		UID:     -1}
	var rss, swap uint64
	err := r.readSmall(r.procPath(pb[:0], pid, "status"), func(b []byte) {
		rss, swap, p.UID = ParseStatus(b)
	})
	if err == nil {
		// Kernel threads report no Vm lines: footprint 0 but readable.
		p.RSS = rss
		p.Footprint = rss + swap
		p.FootprintOK = true
	}
	return nil
}

// Footprint implements Reader.
func (r *linuxReader) Footprint(pid int) (uint64, time.Time, error) {
	var p Proc
	if err := r.Probe(pid, &p); err != nil {
		return 0, time.Time{}, err
	}
	if !p.FootprintOK {
		return 0, p.Start, ErrNoAccess
	}
	return p.Footprint, p.Start, nil
}

func (r *linuxReader) listPIDs(fn func(pid int) bool) error {
	d, err := os.Open(r.root)
	if err != nil {
		return err
	}
	defer d.Close()
	seen := 0
	for {
		names, err := d.Readdirnames(256)
		for _, n := range names {
			pid, perr := strconv.Atoi(n)
			if perr != nil || pid <= 0 {
				continue
			}
			if seen++; seen > MaxListed {
				return nil
			}
			if !fn(pid) {
				return nil
			}
		}
		if err != nil {
			return nil // io.EOF ends the listing
		}
	}
}

// Procs implements Reader.
func (r *linuxReader) Procs() ([]Proc, error) {
	var out []Proc
	err := r.listPIDs(func(pid int) bool {
		var p Proc
		if r.Probe(pid, &p) != nil {
			return true // exited meanwhile
		}
		var lb [128]byte
		if l, err := os.Readlink(r.procPath(lb[:0], pid, "exe")); err == nil {
			p.Exe = l
		}
		out = append(out, p)
		return true
	})
	return out, err
}

// AppendGroupMembers implements Lister. Linux has no group index, so this
// reads every stat file; the tracker bounds how often it does so.
func (r *linuxReader) AppendGroupMembers(dst []int, pgid int) ([]int, error) {
	err := r.listPIDs(func(pid int) bool {
		var pb [96]byte
		_ = r.readSmall(r.procPath(pb[:0], pid, "stat"), func(b []byte) {
			if sf, ok := ParseStat(b); ok && sf.PGRP == pgid {
				dst = append(dst, pid)
			}
		})
		return true
	})
	return dst, err
}

// AppendChildren implements Lister.
func (r *linuxReader) AppendChildren(dst []int, ppid int) ([]int, error) {
	err := r.listPIDs(func(pid int) bool {
		var pb [96]byte
		_ = r.readSmall(r.procPath(pb[:0], pid, "stat"), func(b []byte) {
			if sf, ok := ParseStat(b); ok && sf.PPID == ppid {
				dst = append(dst, pid)
			}
		})
		return true
	})
	return dst, err
}

// GroupMembers implements Reader.
func (r *linuxReader) GroupMembers(pgid int) ([]int, error) {
	return r.AppendGroupMembers(nil, pgid)
}

// Children implements Reader.
func (r *linuxReader) Children(pid int) ([]int, error) { return r.AppendChildren(nil, pid) }

// Sid implements Reader.
func (r *linuxReader) Sid(pid int) (int, error) {
	var p Proc
	if err := r.Probe(pid, &p); err != nil {
		return 0, err
	}
	return p.SID, nil
}

// Args implements Reader. /proc/PID/cmdline is NUL-separated.
func (r *linuxReader) Args(pid int) []string {
	var pb [96]byte
	b, err := r.read(r.procPath(pb[:0], pid, "cmdline"), 64<<10)
	if err != nil || len(b) == 0 {
		return nil
	}
	var out []string
	for len(b) > 0 {
		j := 0
		for j < len(b) && b[j] != 0 {
			j++
		}
		out = append(out, string(b[:j]))
		if j < len(b) {
			j++
		}
		b = b[j:]
	}
	return out
}

// Env implements Reader. The buffer is dropped on return.
func (r *linuxReader) Env(pid int, keys ...string) map[string]string {
	var pb [96]byte
	b, err := r.read(r.procPath(pb[:0], pid, "environ"), MaxProcArgs)
	if err != nil {
		return nil
	}
	return ParseEnviron(b, keys...)
}

// Cwd implements Reader.
func (r *linuxReader) Cwd(pid int) string {
	var pb [96]byte
	l, _ := os.Readlink(r.procPath(pb[:0], pid, "cwd"))
	return l
}

// SelfTest implements Reader: our own footprint and our own group.
func (r *linuxReader) SelfTest() error { return selfTest(r, r.self) }
