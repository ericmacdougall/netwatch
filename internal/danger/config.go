package danger

import "time"

// Config holds the thresholds. Bounds are enforced by Clamp, which the
// config loader calls and warns about.
type Config struct {
	GroupRAMFrac float64       // D4 group size, fraction of RAM (default 0.75, 0.25-1.5)
	MinShare     float64       // P1 group floor, fraction of RAM (default 0.25, 0.05-1.0)
	HeadroomFrac float64       // P1 corroboration, fraction of RAM (default 0.08, 0.02-0.95)
	P1Horizon    time.Duration // default 15s, bounds 5s-120s

	D2Frac   float64 // compressor use that raises D2 (0.85)
	D3Frac   float64 // swap fraction that raises D3 (0.85)
	D4Growth uint64  // bytes per minute a D4 group must exceed (1 GB)
	D1Growth uint64  // bytes per minute that lets D1 fire on one poll (2 GB)

	ClearHold      time.Duration // pressure normal this long to clear (30s)
	ClearTolerance uint64        // noise floor for "not rising", bytes
}

// Defaults returns the spec defaults.
func Defaults() Config {
	return Config{
		GroupRAMFrac:   0.75,
		MinShare:       0.25,
		HeadroomFrac:   0.08,
		P1Horizon:      15 * time.Second,
		D2Frac:         0.85,
		D3Frac:         0.85,
		D4Growth:       1 << 30,
		D1Growth:       2 << 30,
		ClearHold:      30 * time.Second,
		ClearTolerance: 32 << 20,
	}
}

// Clamp forces the user-tunable thresholds into their bounds and returns
// a warning for each one it had to change.
func (c *Config) Clamp() []string {
	var w []string
	clampF := func(name string, v *float64, lo, hi float64) {
		if *v < lo || *v > hi {
			old := *v
			if *v < lo {
				*v = lo
			} else {
				*v = hi
			}
			w = append(w, name+" out of bounds, clamped")
			_ = old
		}
	}
	clampF("guard_group_ram_fraction", &c.GroupRAMFrac, 0.25, 1.5)
	clampF("guard_min_share", &c.MinShare, 0.05, 1.0)
	clampF("guard_headroom_frac", &c.HeadroomFrac, 0.02, 0.95)
	if c.P1Horizon < 5*time.Second || c.P1Horizon > 120*time.Second {
		if c.P1Horizon < 5*time.Second {
			c.P1Horizon = 5 * time.Second
		} else {
			c.P1Horizon = 120 * time.Second
		}
		w = append(w, "guard_p1_horizon_s out of bounds, clamped")
	}
	return w
}
