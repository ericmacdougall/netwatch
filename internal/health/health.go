// Package health summarises ping results and tracks the degraded/recovered
// state of the network.
package health

import (
	"math"
	"regexp"
	"strconv"
	"strings"
)

// Ping summarises one burst of echo requests. Avg and Max are nil when no
// reply arrived. The JSON shape matches the original prototype.
type Ping struct {
	Avg  *float64 `json:"avg"`
	Max  *float64 `json:"max"`
	Loss float64  `json:"loss"` // percent
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }

// Summarize builds a Ping from round-trip times (ms) of sent requests.
func Summarize(rtts []float64, sent int) Ping {
	if sent <= 0 {
		return Ping{Loss: 100}
	}
	if len(rtts) > sent {
		rtts = rtts[:sent]
	}
	p := Ping{Loss: math.Round(100 * float64(sent-len(rtts)) / float64(sent))}
	if len(rtts) == 0 {
		return p
	}
	var sum, max float64
	for _, r := range rtts {
		sum += r
		if r > max {
			max = r
		}
	}
	avg, mx := round1(sum/float64(len(rtts))), round1(max)
	p.Avg, p.Max = &avg, &mx
	return p
}

var timeRe = regexp.MustCompile(`time[=<]\s*([\d.]+)\s*ms`)

// ParsePingOutput reads the per-reply "time=12.3 ms" lines printed by the
// BSD and iputils ping commands. Duplicate replies are ignored.
func ParsePingOutput(out string, sent int) Ping {
	var rtts []float64
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "DUP!") {
			continue
		}
		m := timeRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		v, err := strconv.ParseFloat(m[1], 64)
		if err == nil {
			rtts = append(rtts, v)
		}
	}
	return Summarize(rtts, sent)
}

// Thresholds decide when the network counts as degraded.
type Thresholds struct {
	GatewayMs float64
	LossPct   float64
}

// Bad reports whether one sample is unhealthy: the gateway is slow or
// lossy (no replies at all counts as slow), or the internet host is lossy.
// A nil gateway means no default route was found; that alone is not
// "degraded" because the machine may simply be offline by choice, but
// internet loss still is.
func Bad(gw, net *Ping, th Thresholds) bool {
	if gw != nil {
		if gw.Avg == nil || *gw.Avg > th.GatewayMs || gw.Loss >= th.LossPct {
			return true
		}
	}
	return net != nil && net.Loss >= th.LossPct
}

// Transition is the outcome of feeding one sample to a Tracker.
type Transition int

// Possible transitions.
const (
	Steady Transition = iota
	BecameDegraded
	BecameRecovered
)

// Tracker is the degraded/recovered state machine. It emits a transition
// only on change so one outage produces one DEGRADED and one RECOVERED.
type Tracker struct {
	Degraded bool
}

// Update feeds one sample.
func (t *Tracker) Update(gw, net *Ping, th Thresholds) Transition {
	bad := Bad(gw, net, th)
	switch {
	case bad && !t.Degraded:
		t.Degraded = true
		return BecameDegraded
	case !bad && t.Degraded:
		t.Degraded = false
		return BecameRecovered
	}
	return Steady
}
