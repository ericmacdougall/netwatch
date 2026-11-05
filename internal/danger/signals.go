package danger

import (
	"time"

	"github.com/ericmacdougall/netwatch/internal/resources"
)

// CompressorFrac is max(pages_compressed / limit, segments / segment_limit),
// the D2 level. A zero limit contributes 0 so a platform without the
// sysctl never raises D2.
func CompressorFrac(s resources.System) float64 {
	var a, b float64
	if s.PagesCompressedLimit > 0 {
		a = float64(s.PagesCompressed) / float64(s.PagesCompressedLimit)
	}
	if s.SegmentLimit > 0 {
		b = float64(s.Segments) / float64(s.SegmentLimit)
	}
	if b > a {
		return b
	}
	return a
}

// SwapFrac is swap used over swap used plus free disk (D3 level).
func SwapFrac(s resources.System) float64 {
	den := s.SwapUsed + s.DiskFree
	if den == 0 {
		return 0
	}
	return float64(s.SwapUsed) / float64(den)
}

// D2 reports compressor use at or above cfg.D2Frac.
func D2(cfg Config, s resources.System) bool { return CompressorFrac(s) >= cfg.D2Frac }

// D3 reports swap at or above cfg.D3Frac of swap plus free disk.
func D3(cfg Config, s resources.System) bool {
	return s.SwapUsed > 0 && SwapFrac(s) >= cfg.D3Frac
}

// GrowthPerMin is the growth of a series in bytes per minute, measured
// from the earliest point within the last 60s to the last point. It needs
// at least 2 points at least 1s apart and never returns a negative value.
func GrowthPerMin(series []Point) float64 {
	n := len(series)
	if n < 2 {
		return 0
	}
	last := series[n-1]
	first := last
	for i := n - 2; i >= 0; i-- {
		if last.At.Sub(series[i].At) > time.Minute {
			break
		}
		first = series[i]
	}
	dt := last.At.Sub(first.At)
	if dt < time.Second || last.Bytes <= first.Bytes {
		return 0
	}
	return float64(last.Bytes-first.Bytes) / dt.Seconds() * 60
}

// GroupSeries is one agent group's footprint series, oldest first.
type GroupSeries struct {
	PGID   int
	Series []Point
}

func latest(s []Point) uint64 {
	if len(s) == 0 {
		return 0
	}
	return s[len(s)-1].Bytes
}

// D1 is critical pressure on 2 consecutive polls, or on one poll when D5
// corroborates or any group is growing over cfg.D1Growth. readings are
// oldest first; D1 only ever looks at the last two.
func D1(cfg Config, readings []resources.System, d5 bool, groups []GroupSeries) bool {
	n := len(readings)
	if n == 0 || readings[n-1].Pressure != resources.LevelCritical {
		return false
	}
	if d5 {
		return true
	}
	for _, g := range groups {
		if GrowthPerMin(g.Series) > float64(cfg.D1Growth) {
			return true
		}
	}
	return n >= 2 && readings[n-2].Pressure == resources.LevelCritical
}

// D4 lists the groups at or above GroupRAMFrac x RAM that are growing over
// cfg.D4Growth per minute while pressure is warn or worse.
func D4(cfg Config, s resources.System, groups []GroupSeries) []int {
	if s.Pressure != resources.LevelWarn && s.Pressure != resources.LevelCritical {
		return nil
	}
	var out []int
	floor := cfg.GroupRAMFrac * float64(s.RAM)
	for _, g := range groups {
		if float64(latest(g.Series)) >= floor && GrowthPerMin(g.Series) > float64(cfg.D4Growth) {
			out = append(out, g.PGID)
		}
	}
	return out
}

// P1 lists the groups of at least MinShare x RAM whose growth over the
// last two reads would use the current headroom within the horizon.
func P1(cfg Config, s resources.System, groups []GroupSeries) []int {
	var out []int
	floor := cfg.MinShare * float64(s.RAM)
	head := float64(Headroom(s))
	for _, g := range groups {
		n := len(g.Series)
		if n < 2 || float64(latest(g.Series)) < floor {
			continue
		}
		a, b := g.Series[n-2], g.Series[n-1]
		dt := b.At.Sub(a.At).Seconds()
		if dt <= 0 || b.Bytes <= a.Bytes {
			continue
		}
		rate := float64(b.Bytes-a.Bytes) / dt
		if rate*cfg.P1Horizon.Seconds() >= head {
			out = append(out, g.PGID)
		}
	}
	return out
}

// P1Corroborated says whether P1 may count as danger (amendment A7): only
// critical pressure, headroom under HeadroomFrac x RAM together with
// pressure at warn or worse, or D2 or D3 corroborate. Headroom alone never
// does, because it is routinely small on a healthy Mac.
func P1Corroborated(cfg Config, s resources.System) bool {
	if s.Pressure == resources.LevelCritical {
		return true
	}
	if (s.Pressure == resources.LevelWarn) &&
		float64(Headroom(s)) < cfg.HeadroomFrac*float64(s.RAM) {
		return true
	}
	return D2(cfg, s) || D3(cfg, s)
}

// Clear reports the clear condition: every reading in the trailing run is
// pressure normal, that run spans at least cfg.ClearHold, and swap and
// compressor bytes did not rise over the hold (beyond the noise floor).
// readings are oldest first and must end at "now".
func Clear(cfg Config, readings []resources.System) bool {
	n := len(readings)
	if n == 0 || readings[n-1].Pressure != resources.LevelNormal {
		return false
	}
	now := readings[n-1].At
	start := n - 1
	for start > 0 && readings[start-1].Pressure == resources.LevelNormal {
		start--
	}
	if now.Sub(readings[start].At) < cfg.ClearHold {
		return false
	}
	// Reference: the latest reading at least ClearHold old.
	ref := start
	for i := n - 1; i >= start; i-- {
		if now.Sub(readings[i].At) >= cfg.ClearHold {
			ref = i
			break
		}
	}
	r, l := readings[ref], readings[n-1]
	if l.SwapUsed > r.SwapUsed+cfg.ClearTolerance {
		return false
	}
	if l.CompressorBytes > r.CompressorBytes+cfg.ClearTolerance {
		return false
	}
	return true
}

// Used is the memory in use in the same units as ri_phys_footprint (the
// compressor's physical bytes are swapped for the logical size of what it
// holds), plus swap used (amendment A6). includeSwap=false is the variant
// the unit test uses to pin the direction: dropping swap raises a group's
// computed share.
func Used(s resources.System, includeSwap bool) uint64 {
	ps := s.PageSize
	free := (s.Free + s.Speculative + s.Purgeable) * ps
	var used uint64
	if s.RAM > free {
		used = s.RAM - free
	}
	if used > s.CompressorBytes {
		used -= s.CompressorBytes
	} else {
		used = 0
	}
	used += s.PagesCompressed * ps
	if includeSwap {
		used += s.SwapUsed
	}
	return used
}

// Unattributed is used minus the readable footprints, clamped at 0.
func Unattributed(s resources.System, footprints uint64, includeSwap bool) uint64 {
	u := Used(s, includeSwap)
	if u <= footprints {
		return 0
	}
	return u - footprints
}
