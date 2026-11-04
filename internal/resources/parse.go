package resources

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"time"
)

// This file holds the pure parsers. They have no build tags so the macOS
// and Linux formats are both testable anywhere.

// MaxProcArgs bounds how much of kern.procargs2 is examined. The kernel
// limit (kern.argmax) is about 1 MiB; anything larger is cut, never grown.
const MaxProcArgs = 1 << 20

// ParseProcArgs2 parses a kern.procargs2 buffer: int32 argc, the exec path,
// NUL padding, argc argument strings, then the environment strings. It
// returns argv (copied) and only the environment values whose key is in
// keys. The caller drops buf immediately afterwards; nothing here keeps a
// reference to it and no other environment value is ever copied.
func ParseProcArgs2(buf []byte, keys ...string) (argv []string, env map[string]string) {
	if len(buf) > MaxProcArgs {
		buf = buf[:MaxProcArgs]
	}
	if len(buf) < 4 {
		return nil, nil
	}
	argc := int(int32(binary.LittleEndian.Uint32(buf)))
	rest := buf[4:]
	// Skip the exec path and the NUL padding after it.
	i := bytes.IndexByte(rest, 0)
	if i < 0 {
		return nil, nil
	}
	rest = rest[i:]
	for len(rest) > 0 && rest[0] == 0 {
		rest = rest[1:]
	}
	if argc < 0 || argc > 1<<16 {
		return nil, nil
	}
	for n := 0; n < argc && len(rest) > 0; n++ {
		j := bytes.IndexByte(rest, 0)
		if j < 0 {
			j = len(rest)
		}
		argv = append(argv, string(rest[:j]))
		if j < len(rest) {
			j++
		}
		rest = rest[j:]
	}
	if len(keys) == 0 {
		return argv, nil
	}
	for len(rest) > 0 {
		j := bytes.IndexByte(rest, 0)
		var kv []byte
		if j < 0 {
			kv, rest = rest, nil
		} else {
			kv, rest = rest[:j], rest[j+1:]
		}
		eq := bytes.IndexByte(kv, '=')
		if eq <= 0 {
			continue
		}
		for _, k := range keys {
			if len(k) == eq && string(kv[:eq]) == k {
				if env == nil {
					env = make(map[string]string, len(keys))
				}
				env[k] = string(kv[eq+1:])
				break
			}
		}
	}
	return argv, env
}

// ParseEnviron is the /proc/PID/environ form (NUL-separated KEY=VALUE).
func ParseEnviron(buf []byte, keys ...string) map[string]string {
	if len(buf) > MaxProcArgs {
		buf = buf[:MaxProcArgs]
	}
	var env map[string]string
	for len(buf) > 0 {
		j := bytes.IndexByte(buf, 0)
		var kv []byte
		if j < 0 {
			kv, buf = buf, nil
		} else {
			kv, buf = buf[:j], buf[j+1:]
		}
		eq := bytes.IndexByte(kv, '=')
		if eq <= 0 {
			continue
		}
		for _, k := range keys {
			if len(k) == eq && string(kv[:eq]) == k {
				if env == nil {
					env = make(map[string]string, len(keys))
				}
				env[k] = string(kv[eq+1:])
				break
			}
		}
	}
	return env
}

// ParseSwapUsage decodes the macOS xsw_usage struct returned by the
// vm.swapusage sysctl (sys/sysctl.h): u64 xsu_total at 0, u64 xsu_avail at
// 8, u64 xsu_used at 16, u32 xsu_pagesize at 24, bool xsu_encrypted at 28.
func ParseSwapUsage(b []byte) (total, used uint64, ok bool) {
	if len(b) < 24 {
		return 0, 0, false
	}
	return binary.LittleEndian.Uint64(b[0:]), binary.LittleEndian.Uint64(b[16:]), true
}

// ParseLoadavg decodes struct loadavg (sys/resource.h): fixpt_t ldavg[3]
// (u32) at 0, then long fscale at 16 (8-byte aligned). It returns the
// 1-minute average.
func ParseLoadavg(b []byte) (float64, bool) {
	if len(b) < 24 {
		return 0, false
	}
	scale := binary.LittleEndian.Uint64(b[16:])
	if scale == 0 {
		return 0, false
	}
	return float64(binary.LittleEndian.Uint32(b[0:])) / float64(scale), true
}

// Meminfo is the subset of /proc/meminfo netwatch uses, in bytes.
type Meminfo struct {
	Total, Free, Available, Inactive, SwapTotal, SwapFree uint64
}

// ParseMeminfo reads "Name:   123 kB" lines. Unknown lines are skipped.
func ParseMeminfo(b []byte) Meminfo {
	var m Meminfo
	for len(b) > 0 {
		var line []byte
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			line, b = b[:i], b[i+1:]
		} else {
			line, b = b, nil
		}
		c := bytes.IndexByte(line, ':')
		if c < 0 {
			continue
		}
		var dst *uint64
		switch string(line[:c]) {
		case "MemTotal":
			dst = &m.Total
		case "MemFree":
			dst = &m.Free
		case "MemAvailable":
			dst = &m.Available
		case "Inactive":
			dst = &m.Inactive
		case "SwapTotal":
			dst = &m.SwapTotal
		case "SwapFree":
			dst = &m.SwapFree
		default:
			continue
		}
		if v, ok := kbValue(line[c+1:]); ok {
			*dst = v
		}
	}
	return m
}

// kbValue parses " 123 kB" (the unit is always kB in /proc) into bytes.
func kbValue(b []byte) (uint64, bool) {
	b = bytes.TrimSpace(b)
	b = bytes.TrimSuffix(b, []byte(" kB"))
	v, err := strconv.ParseUint(string(b), 10, 64)
	if err != nil || v > 1<<50 {
		return 0, false
	}
	return v << 10, true
}

// PSI thresholds. The mapping from /proc/pressure/memory to Level is a
// choice, not a kernel contract. "full" means every non-idle task was
// stalled on memory at once, which is the Linux analogue of the point where
// macOS reports warn and critical.
//
//   - warn at full avg10 >= 1.0: a sustained 1% of wall time with the whole
//     system stalled is abnormal on a healthy host (the idle value on the
//     reference machine is near 0.03) yet still well short of thrashing.
//   - critical at full avg10 >= 20.0 (spec v11): a fifth of wall time with
//     no task making progress is thrashing; systemd-oomd and oomd act at
//     similar orders of magnitude.
//
// LinuxLevel also treats MemAvailable under 3% of RAM as critical.
// They are variables so a test or a future config key can adjust them.
var (
	PSIWarn     = 1.0
	PSICritical = 20.0
	// MemAvailFloor is the MemAvailable fraction of RAM below which the
	// host counts as critical even before PSI rises.
	MemAvailFloor = 0.03
)

// LinuxLevel is PSILevel raised to critical when MemAvailable is under
// MemAvailFloor of RAM. An unknown total (0) never reads as critical.
func LinuxLevel(full float64, avail, total uint64) Level {
	if total > 0 && float64(avail) < MemAvailFloor*float64(total) {
		return LevelCritical
	}
	return PSILevel(full)
}

// ParsePSI returns the "some" and "full" avg10 values.
func ParsePSI(b []byte) (some, full float64, ok bool) {
	for len(b) > 0 {
		var line []byte
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			line, b = b[:i], b[i+1:]
		} else {
			line, b = b, nil
		}
		kind := ""
		switch {
		case bytes.HasPrefix(line, []byte("some ")):
			kind = "some"
		case bytes.HasPrefix(line, []byte("full ")):
			kind = "full"
		default:
			continue
		}
		for _, f := range bytes.Fields(line)[1:] {
			if bytes.HasPrefix(f, []byte("avg10=")) {
				v, err := strconv.ParseFloat(string(f[6:]), 64)
				if err != nil || v < 0 || v > 100 {
					return 0, 0, false
				}
				if kind == "some" {
					some = v
				} else {
					full = v
					ok = true
				}
			}
		}
	}
	return some, full, ok
}

// PSILevel maps full avg10 to a Level.
func PSILevel(full float64) Level {
	switch {
	case full >= PSICritical:
		return LevelCritical
	case full >= PSIWarn:
		return LevelWarn
	}
	return LevelNormal
}

// StatFields is the subset of /proc/PID/stat netwatch uses.
type StatFields struct {
	State      byte
	PPID, PGRP int
	Session    int
	TTYNr      int
	UTime      uint64 // clock ticks
	STime      uint64
	StartTicks uint64
	RSSPages   int64
	Comm       string
}

// ParseStat parses /proc/PID/stat. comm may contain spaces and parentheses,
// so the fields are located from the last ')'. See proc(5) for numbering:
// state=3 ppid=4 pgrp=5 session=6 tty_nr=7 utime=14 stime=15
// starttime=22 rss=24.
func ParseStat(b []byte) (StatFields, bool) {
	var s StatFields
	l := bytes.IndexByte(b, '(')
	r := bytes.LastIndexByte(b, ')')
	if l < 0 || r < l || r+2 >= len(b) {
		return s, false
	}
	s.Comm = string(b[l+1 : r])
	rest := b[r+2:]
	// rest starts at field 3.
	var f [22][]byte
	n := 0
	for len(rest) > 0 && n < len(f) {
		for len(rest) > 0 && (rest[0] == ' ' || rest[0] == '\n') {
			rest = rest[1:]
		}
		if len(rest) == 0 {
			break
		}
		j := bytes.IndexAny(rest, " \n")
		if j < 0 {
			j = len(rest)
		}
		f[n] = rest[:j]
		rest = rest[j:]
		n++
	}
	if n < 22 { // fields 3..24
		return s, false
	}
	s.State = f[0][0]
	atoi := func(i int) int { v, _ := strconv.Atoi(string(f[i])); return v }
	atou := func(i int) uint64 { v, _ := strconv.ParseUint(string(f[i]), 10, 64); return v }
	s.PPID, s.PGRP, s.Session, s.TTYNr = atoi(1), atoi(2), atoi(3), atoi(4)
	s.UTime, s.STime = atou(11), atou(12)
	s.StartTicks = atou(19)
	v, _ := strconv.ParseInt(string(f[21]), 10, 64)
	s.RSSPages = v
	return s, s.StartTicks > 0
}

// ParseStatus returns VmRSS and VmSwap in bytes from /proc/PID/status, and
// the real uid. Kernel threads have no Vm lines; they read as zero.
func ParseStatus(b []byte) (rss, swap uint64, uid int) {
	uid = -1
	for len(b) > 0 {
		var line []byte
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			line, b = b[:i], b[i+1:]
		} else {
			line, b = b, nil
		}
		switch {
		case bytes.HasPrefix(line, []byte("VmRSS:")):
			rss, _ = kbValue(line[6:])
		case bytes.HasPrefix(line, []byte("VmSwap:")):
			swap, _ = kbValue(line[7:])
		case bytes.HasPrefix(line, []byte("Uid:")):
			if f := bytes.Fields(line[4:]); len(f) > 0 {
				if v, err := strconv.Atoi(string(f[0])); err == nil {
					uid = v
				}
			}
		}
	}
	return
}

// StartFromTicks converts a Linux starttime in clock ticks since boot into
// wall time. A tick is 1/100 s on every Linux ABI netwatch supports
// (USER_HZ is fixed at 100 for the /proc interface).
func StartFromTicks(boot time.Time, ticks uint64) time.Time {
	return boot.Add(time.Duration(ticks) * (time.Second / 100))
}

// ParseBtime extracts the "btime" line of /proc/stat.
func ParseBtime(b []byte) (time.Time, bool) {
	for len(b) > 0 {
		var line []byte
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			line, b = b[:i], b[i+1:]
		} else {
			line, b = b, nil
		}
		if bytes.HasPrefix(line, []byte("btime ")) {
			v, err := strconv.ParseInt(string(bytes.TrimSpace(line[6:])), 10, 64)
			if err == nil && v > 0 {
				return time.Unix(v, 0), true
			}
		}
	}
	return time.Time{}, false
}
