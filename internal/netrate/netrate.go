// Package netrate turns cumulative per-process network counters into rates
// and detects processes that start moving traffic for the first time.
package netrate

import (
	"sort"
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
// is forgotten (it has exited or closed all sockets).
const forgetAfter = 360

// maxNames caps the set of remembered process names.
const maxNames = 10000

// Detector remembers which processes have already been seen online.
type Detector struct {
	known map[Key]int // key -> last sample index it was present
	names map[string]bool
	tick  int
}

// NewDetector seeds the detector with processes already running at
// startup so they are not reported as new.
func NewDetector(initial Snapshot) *Detector {
	d := &Detector{known: map[Key]int{}, names: map[string]bool{}}
	for k := range initial.Procs {
		d.known[k] = 0
		d.names[k.Name] = true
	}
	return d
}

// Observe records one sample and returns processes that came online:
// unknown processes moving at least minKbps kilobits per second, or, when
// the OS gives no byte counters, holding an established connection.
func (d *Detector) Observe(cur Snapshot, rates Rates, minKbps float64) []NewApp {
	d.tick++
	for k := range cur.Procs {
		if _, ok := d.known[k]; ok {
			d.known[k] = d.tick
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
		d.known[r.Key] = d.tick
		first := !d.names[r.Name]
		if first && len(d.names) < maxNames {
			d.names[r.Name] = true
		}
		out = append(out, NewApp{Rate: r, FirstName: first})
	}
	for k, seen := range d.known {
		if d.tick-seen > forgetAfter {
			delete(d.known, k)
		}
	}
	return out
}

// Known reports how many processes are currently remembered.
func (d *Detector) Known() int { return len(d.known) }
