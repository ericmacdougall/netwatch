package danger

import (
	"time"

	"github.com/ericmacdougall/netwatch/internal/resources"
)

// Detector keeps the short reading history the pure functions need and
// produces one Signals value per poll. A new Detector has no history, so
// after a crash restart the clear hold starts again, as the spec requires.
type Detector struct {
	Cfg      Config
	readings []resources.System
}

// historySpan is how much history Observe keeps; it must exceed ClearHold.
const historySpan = 3 * time.Minute

// Observe adds one poll and returns its signals. d5 is true when a new
// non-idle jetsam report arrived since the previous poll; D5 never raises
// danger by itself and only lets D1 fire after one poll.
func (d *Detector) Observe(s resources.System, d5 bool, groups []GroupSeries) Signals {
	d.readings = append(d.readings, s)
	cut := 0
	for cut < len(d.readings)-1 && s.At.Sub(d.readings[cut].At) > historySpan {
		cut++
	}
	d.readings = d.readings[cut:]

	sig := Signals{
		D5:             d5,
		CompressorFrac: CompressorFrac(s),
		SwapFrac:       SwapFrac(s),
		Headroom:       Headroom(s),
	}
	sig.D1 = D1(d.Cfg, d.readings, d5, groups)
	sig.D2 = D2(d.Cfg, s)
	sig.D3 = D3(d.Cfg, s)
	sig.D4PGIDs = D4(d.Cfg, s, groups)
	sig.P1PGIDs = P1(d.Cfg, s, groups)
	sig.P1 = len(sig.P1PGIDs) > 0
	sig.P1Corroborated = sig.P1 && P1Corroborated(d.Cfg, s)
	sig.Danger = sig.D1 || sig.D2 || sig.D3 || len(sig.D4PGIDs) > 0 || sig.P1Corroborated
	sig.Clear = Clear(d.Cfg, d.readings)
	return sig
}
