// Package selfusage measures netwatch's own CPU time, including the helper
// commands it runs (ps, nettop, ping), so the monitor can report its cost.
package selfusage

import "time"

// Meter turns cumulative CPU time into a percentage over each interval.
type Meter struct {
	lastCPU  time.Duration
	lastWall time.Time
}

// NewMeter starts measuring from now.
func NewMeter() *Meter { return &Meter{lastCPU: CPUTime(), lastWall: time.Now()} }

// Sample returns the CPU percentage of one core used since the last call.
func (m *Meter) Sample() float64 {
	cpu, now := CPUTime(), time.Now()
	wall := now.Sub(m.lastWall)
	used := cpu - m.lastCPU
	m.lastCPU, m.lastWall = cpu, now
	if wall <= 0 || used < 0 {
		return 0
	}
	return float64(used) / float64(wall) * 100
}
