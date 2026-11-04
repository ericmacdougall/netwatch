// Package danger computes the host-danger signals D1-D5, the predictive
// signal P1 and the clear condition from a series of system readings.
// Every function is pure; the rules are spec v11 plus plan amendments
// A1 (headroom) and A7 (P1 corroboration).
package danger

import (
	"time"

	"github.com/ericmacdougall/netwatch/internal/resources"
)

// Signals is the result for one poll.
type Signals struct {
	D1, D2, D3, D5 bool
	D4PGIDs        []int // groups that satisfy D4 this poll
	P1             bool
	P1Corroborated bool
	Danger         bool // any of D1-D4, or corroborated P1
	Clear          bool // clear condition held for the full hold time
	CompressorFrac float64
	SwapFrac       float64
	Headroom       uint64 // bytes, per Amendment A1
}

// Headroom is min(RAM, (free+speculative+purgeable+inactive) x pagesize).
// No compressor term (Amendment A1).
func Headroom(s resources.System) uint64 {
	h := (s.Free + s.Speculative + s.Purgeable + s.Inactive) * s.PageSize
	if s.RAM != 0 && h > s.RAM {
		return s.RAM
	}
	return h
}

// Clock lets tests control time.
type Clock interface{ Now() time.Time }
