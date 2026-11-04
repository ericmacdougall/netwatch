// Package darwin collects processes and network state on macOS using the
// system tools ps, nettop, route and ping, and installs a LaunchAgent.
//
// Shelling out is deliberate: nettop is the only unprivileged source of
// per-process byte counters on macOS, and ps/route are cheaper to call once
// per scan than reimplementing libproc without cgo (which would break the
// static, cross-compiled build).
//
// The parsers in this file are OS-independent so they are tested everywhere.
package darwin

import (
	"bufio"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ericmacdougall/netwatch/internal/netrate"
	"github.com/ericmacdougall/netwatch/internal/platform"
	"github.com/ericmacdougall/netwatch/internal/procscan"
)

// PSArgs are the ps arguments ParsePS expects. lstart gives a stable,
// second-resolution start time used as process identity; etime gives age.
var PSArgs = []string{"-axww", "-o", "pid=,ppid=,uid=,pcpu=,rss=,etime=,lstart=,command="}

const lstartLayout = "Mon Jan 2 15:04:05 2006"

// fields splits off the first n whitespace-separated fields and returns the
// untouched remainder, so command lines keep their internal spacing.
func fields(line string, n int) ([]string, string, bool) {
	out := make([]string, 0, n)
	rest := line
	for len(out) < n {
		rest = strings.TrimLeft(rest, " \t")
		if rest == "" {
			return nil, "", false
		}
		i := strings.IndexAny(rest, " \t")
		if i < 0 {
			out = append(out, rest)
			rest = ""
		} else {
			out = append(out, rest[:i])
			rest = rest[i:]
		}
	}
	return out, strings.TrimLeft(rest, " \t"), true
}

// ParsePS parses ps output produced with PSArgs. Lines that do not parse
// (for example a process that exited mid-listing) are skipped.
func ParsePS(out string, uid int, loc *time.Location) []procscan.Process {
	var procs []procscan.Process
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		f, cmd, ok := fields(sc.Text(), 11)
		if !ok || cmd == "" {
			continue
		}
		pid, err1 := strconv.Atoi(f[0])
		ppid, err2 := strconv.Atoi(f[1])
		u, err3 := strconv.Atoi(f[2])
		cpu, err4 := strconv.ParseFloat(f[3], 64)
		rssKB, err5 := strconv.Atoi(f[4])
		age, err6 := procscan.ParseEtime(f[5])
		start, err7 := time.ParseInLocation(lstartLayout, strings.Join(f[6:11], " "), loc)
		if err1 != nil || err2 != nil || err3 != nil || err4 != nil || err5 != nil || err6 != nil || err7 != nil {
			continue
		}
		procs = append(procs, procscan.Process{
			PID: pid, PPID: ppid, Own: u == uid, CPU: cpu, RSSMB: rssKB / 1024,
			Age: age, Start: start, Cmd: cmd,
		})
	}
	return procs
}

// NettopArgs request one CSV sample of cumulative bytes per process.
var NettopArgs = []string{"-P", "-L", "1", "-x", "-J", "bytes_in,bytes_out"}

// NettopStreamArgs keep nettop running and print a sample every interval.
// One long-lived nettop is cheaper than spawning one per sample, and nettop
// can take tens of seconds to start when the system has many flows.
func NettopStreamArgs(interval time.Duration) []string {
	secs := int(interval.Seconds())
	if secs < 1 {
		secs = 1
	}
	return []string{"-P", "-x", "-J", "bytes_in,bytes_out", "-L", "0", "-s", strconv.Itoa(secs)}
}

// parseRow parses "name.pid,in,out," or, in streaming mode,
// "15:04:05.000000,name.pid,in,out,".
func parseRow(line string, hasTime bool) (ts string, k netrate.Key, c netrate.Counter, ok bool) {
	parts := strings.Split(strings.TrimSpace(line), ",")
	if hasTime {
		if len(parts) < 4 {
			return "", k, c, false
		}
		ts, parts = parts[0], parts[1:]
	}
	if len(parts) < 3 {
		return "", k, c, false
	}
	dot := strings.LastIndexByte(parts[0], '.')
	if dot <= 0 {
		return "", k, c, false
	}
	pid, err := strconv.Atoi(parts[0][dot+1:])
	if err != nil {
		return "", k, c, false
	}
	in, err1 := parseCount(parts[1])
	out, err2 := parseCount(parts[2])
	if err1 != nil || err2 != nil {
		return "", k, c, false
	}
	return ts, netrate.Key{Name: parts[0][:dot], PID: pid}, netrate.Counter{In: in, Out: out}, true
}

// ParseNettop parses one-shot nettop CSV: a header, then rows.
// nettop truncates long process names; the PID keeps keys unique.
func ParseNettop(out string) map[netrate.Key]netrate.Counter {
	res := map[netrate.Key]netrate.Counter{}
	for i, line := range strings.Split(out, "\n") {
		if i == 0 {
			continue
		}
		_, k, c, ok := parseRow(line, false)
		if !ok {
			continue
		}
		prev := res[k]
		res[k] = netrate.Counter{In: prev.In + c.In, Out: prev.Out + c.Out}
	}
	return res
}

// StreamParser assembles samples from streaming nettop output. Each sample
// starts with a header line, and every row carries the sample's time of
// day. nettop block-buffers its output when piped, so several samples can
// arrive at once; the embedded time, not the arrival time, dates a sample.
type StreamParser struct {
	Loc *time.Location
	cur *netrate.Snapshot
}

// Feed consumes one line and returns the previous sample when this line
// starts a new one. now anchors the time of day to a date.
func (p *StreamParser) Feed(line string, now time.Time) *netrate.Snapshot {
	if strings.HasPrefix(line, "time,") || strings.HasPrefix(line, ",") {
		return p.flush()
	}
	ts, k, c, ok := parseRow(line, true)
	if !ok {
		return nil
	}
	if p.cur == nil {
		// The first row dates the sample; a sample's rows can straddle a
		// second boundary, so later rows do not start a new one.
		at, err := timeOfDay(ts, now, p.Loc)
		if err != nil {
			return nil
		}
		p.cur = &netrate.Snapshot{At: at, HasBytes: true, Procs: map[netrate.Key]netrate.Counter{}}
	}
	prev := p.cur.Procs[k]
	p.cur.Procs[k] = netrate.Counter{In: prev.In + c.In, Out: prev.Out + c.Out}
	return nil
}

func (p *StreamParser) flush() *netrate.Snapshot {
	s := p.cur
	p.cur = nil
	return s
}

// timeOfDay dates "15:04:05.000000" on now's day, or the day before when
// that would be in the future (a sample taken just before midnight).
func timeOfDay(ts string, now time.Time, loc *time.Location) (time.Time, error) {
	if loc == nil {
		loc = time.Local
	}
	t, err := time.ParseInLocation("15:04:05.999999", ts, loc)
	if err != nil {
		return time.Time{}, err
	}
	n := now.In(loc)
	at := time.Date(n.Year(), n.Month(), n.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), loc)
	if at.After(n.Add(time.Minute)) {
		at = at.AddDate(0, 0, -1)
	}
	return at, nil
}

func parseCount(s string) (uint64, error) {
	if s == "" {
		return 0, nil
	}
	return strconv.ParseUint(s, 10, 64)
}

var (
	gatewayRe = regexp.MustCompile(`(?m)^\s*gateway:\s*(\S+)`)
	ifaceRe   = regexp.MustCompile(`(?m)^\s*interface:\s*(\S+)`)
)

// ParseRoute parses `route -n get default`.
func ParseRoute(out string) platform.Gateway {
	var g platform.Gateway
	if m := gatewayRe.FindStringSubmatch(out); m != nil {
		g.Addr = m[1]
	}
	if m := ifaceRe.FindStringSubmatch(out); m != nil {
		g.Iface = m[1]
	}
	return g
}
