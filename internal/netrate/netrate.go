// Package netrate turns cumulative per-process network counters into rates
// and detects processes that start moving traffic for the first time.
package netrate

import (
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Key identifies a process in network snapshots.
type Key struct {
	Name string
	PID  int
}

// Counter is one process's cumulative counters at an instant.
type Counter struct {
	In, Out uint64 // cumulative bytes; meaningful only when Snapshot.HasBytes
	Conns   int    // established non-loopback connections, when known
}

// Snapshot is one reading of all processes' counters.
type Snapshot struct {
	At       time.Time
	Procs    map[Key]Counter
	HasBytes bool // per-process byte counters are available (not on Windows without admin)

	// Interface totals for the default-route interface, when the OS exposes them.
	HasIf       bool
	IfIn, IfOut uint64
}

// Rate is one process's traffic over a sampling interval.
type Rate struct {
	Key
	InKBps, OutKBps float64
	Conns           int
}

// Total returns the combined in+out rate.
func (r Rate) Total() float64 { return r.InKBps + r.OutKBps }

// Rates is the result of comparing two snapshots.
type Rates struct {
	Procs               []Rate // busiest first
	InKBps, OutKBps     float64
	HasIf               bool
	IfInKBps, IfOutKBps float64
}

// delta treats a decrease as zero: counters reset when a socket closes or
// an interface counter wraps, and a negative rate would be meaningless.
func delta(cur, prev uint64) uint64 {
	if cur < prev {
		return 0
	}
	return cur - prev
}

// Compute derives rates between two snapshots. Processes absent from prev
// are measured from zero, as they started their sockets inside the interval.
// Without byte counters, processes with open connections are listed with
// zero rates so connection counts can still rank them.
func Compute(prev, cur Snapshot) Rates {
	dt := cur.At.Sub(prev.At).Seconds()
	if dt < 0.1 {
		dt = 0.1
	}
	var out Rates
	for k, c := range cur.Procs {
		p := prev.Procs[k]
		r := Rate{Key: k, Conns: c.Conns}
		if cur.HasBytes {
			r.InKBps = float64(delta(c.In, p.In)) / dt / 1024
			r.OutKBps = float64(delta(c.Out, p.Out)) / dt / 1024
			if r.Total() == 0 {
				continue
			}
		} else if c.Conns == 0 {
			continue
		}
		out.Procs = append(out.Procs, r)
		out.InKBps += r.InKBps
		out.OutKBps += r.OutKBps
	}
	sort.Slice(out.Procs, func(i, j int) bool {
		a, b := out.Procs[i], out.Procs[j]
		if a.Total() != b.Total() {
			return a.Total() > b.Total()
		}
		if a.Conns != b.Conns {
			return a.Conns > b.Conns
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.PID < b.PID
	})
	if cur.HasIf && prev.HasIf {
		out.HasIf = true
		out.IfInKBps = float64(delta(cur.IfIn, prev.IfIn)) / dt / 1024
		out.IfOutKBps = float64(delta(cur.IfOut, prev.IfOut)) / dt / 1024
	}
	return out
}

// NewApp is a process that just came online.
type NewApp struct {
	Rate
	FirstName bool // no process with this name has been seen online before
}

// forgetAfter bounds memory: a known process unseen for this many samples
// is forgotten (it has exited or closed all sockets). An app identity that
// has not been online for this long is reported again when it returns.
const forgetAfter = 360

// maxNames caps the sets of remembered process names and app identities.
const maxNames = 10000

// Identify looks up what a process is running. Exe returns its executable
// path and Args its command line; either returns empty when it cannot be
// read (another user's process, or one that has already exited). Either
// may be nil.
type Identify struct {
	Exe  func(pid int) string
	Args func(pid int) []string
}

type entry struct {
	tick int    // last sample index the process was present
	id   string // app identity, from Identify or the name
}

// Detector remembers which processes and apps have already been seen online.
//
// An app is identified by its executable, so a short-lived tool that runs
// over and over (git, curl, a test worker) is reported once rather than
// once per PID. The identity lives only in memory; events carry the name.
type Detector struct {
	known    map[Key]entry
	ids      map[string]int // app identity -> last sample index it was present
	names    map[string]bool
	identify Identify
	tick     int
}

// NewDetector seeds the detector with processes already running at
// startup so they are not reported as new. With an empty identify, apps
// are told apart by name only.
func NewDetector(initial Snapshot, identify Identify) *Detector {
	d := &Detector{known: map[Key]entry{}, ids: map[string]int{}, names: map[string]bool{}, identify: identify}
	for k := range initial.Procs {
		id := d.idOf(k)
		d.known[k] = entry{0, id}
		d.remember(id, 0)
		d.names[k.Name] = true
	}
	return d
}

func (d *Detector) idOf(k Key) string {
	p := ""
	if d.identify.Exe != nil {
		p = d.identify.Exe(k.PID)
	}
	// An interpreter's path names the runtime, not the program it runs, so
	// every python or node program would look like one app. Identify those
	// by the script they run, or keep them per process when it is unknown.
	if isInterpreter(p) || (p == "" && isInterpreter(k.Name)) {
		if d.identify.Args != nil {
			if prog := programArg(d.identify.Args(k.PID)); prog != "" {
				return "run:" + interpreterOf(p, k.Name) + "|" + prog
			}
		}
		return "pid:" + k.Name + "/" + strconv.Itoa(k.PID)
	}
	if p != "" {
		return "exe:" + p
	}
	return "name:" + k.Name
}

// maxProgram bounds the remembered program text (a -c script can be long).
const maxProgram = 256

// programArg returns what an interpreter command line runs: the first
// argument after the interpreter that is not an option, or the module or
// jar named by -m or -jar. Values of a few common options are skipped.
func programArg(args []string) string {
	for i := 1; i < len(args); i++ {
		a := args[i]
		switch a {
		case "-m", "-jar", "-c", "-e", "--eval", "-Command", "-File":
			if i+1 < len(args) {
				return truncate(a + " " + args[i+1])
			}
			return ""
		case "-cp", "-classpath", "--class-path", "-r", "--require", "--import", "--loader", "-W", "-X":
			i++
			continue
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		return truncate(a)
	}
	return ""
}

func truncate(s string) string {
	if len(s) > maxProgram {
		return s[:maxProgram]
	}
	return s
}

func interpreterOf(exe, name string) string {
	if exe != "" {
		name = exe
	}
	return strings.ToLower(path.Base(strings.ReplaceAll(name, "\\", "/")))
}

// interpreters are runtimes whose executable says nothing about the program.
var interpreters = map[string]bool{
	"python": true, "pythonw": true, "node": true, "nodejs": true, "bun": true, "deno": true,
	"java": true, "javaw": true, "dotnet": true, "ruby": true, "perl": true, "php": true,
	"sh": true, "bash": true, "zsh": true, "dash": true, "fish": true, "busybox": true, "env": true,
	"pwsh": true, "powershell": true, "cmd": true, "wscript": true, "cscript": true, "osascript": true,
}

// isInterpreter reports whether a path or process name is a known runtime,
// ignoring case, a .exe suffix and a version suffix (python3.12, node22).
func isInterpreter(name string) bool {
	if name == "" {
		return false
	}
	base := strings.ToLower(path.Base(strings.ReplaceAll(name, "\\", "/")))
	base = strings.TrimSuffix(base, ".exe")
	base = strings.TrimRight(base, "0123456789.-")
	return interpreters[base]
}

func (d *Detector) remember(id string, tick int) {
	if _, ok := d.ids[id]; ok || len(d.ids) < maxNames {
		d.ids[id] = tick
	}
}

// Observe records one sample and returns apps that came online: unknown
// processes moving at least minKbps kilobits per second, or, when the OS
// gives no byte counters, holding an established connection, whose app
// has not been online in the last forgetAfter samples.
func (d *Detector) Observe(cur Snapshot, rates Rates, minKbps float64) []NewApp {
	d.tick++
	for k := range cur.Procs {
		if e, ok := d.known[k]; ok {
			d.known[k] = entry{d.tick, e.id}
			d.ids[e.id] = d.tick
		}
	}
	var out []NewApp
	for _, r := range rates.Procs {
		if _, ok := d.known[r.Key]; ok {
			continue
		}
		online := r.Total()*8 >= minKbps
		if !cur.HasBytes {
			online = r.Conns > 0
		}
		if !online {
			continue
		}
		id := d.idOf(r.Key)
		d.known[r.Key] = entry{d.tick, id}
		last, seen := d.ids[id]
		d.remember(id, d.tick)
		if seen && d.tick-last <= forgetAfter {
			continue // another instance of an app already online recently
		}
		first := !d.names[r.Name]
		if first && len(d.names) < maxNames {
			d.names[r.Name] = true
		}
		out = append(out, NewApp{Rate: r, FirstName: first})
	}
	for k, e := range d.known {
		if d.tick-e.tick > forgetAfter {
			delete(d.known, k)
		}
	}
	for id, seen := range d.ids {
		if d.tick-seen > forgetAfter {
			delete(d.ids, id)
		}
	}
	return out
}

// Known reports how many processes are currently remembered.
func (d *Detector) Known() int { return len(d.known) }
