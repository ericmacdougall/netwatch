package incident

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/ericmacdougall/netwatch/internal/eventlog"
	"github.com/ericmacdougall/netwatch/internal/resources"
)

// Sample is one resources.jsonl record as the forensics read it. Only the
// fields used for the join are decoded; everything else is ignored, so the
// sampler can add fields freely.
type Sample struct {
	At            time.Time
	Pressure      resources.Level
	CompressorPct float64
	SwapUsed      uint64
	Top           []SampleProc
}

// SampleProc is one top-memory process of a sample, with its attribution.
type SampleProc struct {
	PID        int    `json:"pid"`
	PGID       int    `json:"pgid"`
	Name       string `json:"name"`
	Footprint  uint64 `json:"footprint"`
	Agent      string `json:"agent"`
	Confidence string `json:"confidence"`
}

type levelFlex resources.Level

func (l *levelFlex) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	switch s {
	case "normal", "1":
		*l = levelFlex(resources.LevelNormal)
	case "warn", "2":
		*l = levelFlex(resources.LevelWarn)
	case "critical", "4":
		*l = levelFlex(resources.LevelCritical)
	default:
		*l = levelFlex(resources.LevelUnknown)
	}
	return nil
}

type sampleLine struct {
	TS            string       `json:"ts"`
	Pressure      levelFlex    `json:"pressure"`
	CompressorPct float64      `json:"compressor_pct"`
	SwapUsed      uint64       `json:"swap_used"`
	TopMem        []SampleProc `json:"top_mem"`
}

// ReadSamples returns resources.jsonl samples in [from, to], oldest first.
// A missing file yields no samples and no error; torn lines are skipped.
func ReadSamples(path string, from, to time.Time) ([]Sample, error) {
	lines, err := tailJSONL(path)
	var out []Sample
	for _, l := range lines {
		var s sampleLine
		if json.Unmarshal(l, &s) != nil {
			continue
		}
		t, ok := eventlog.ParseTime(s.TS)
		if !ok || t.Before(from) || t.After(to) {
			continue
		}
		top := s.TopMem
		if len(top) > 32 {
			top = top[:32]
		}
		out = append(out, Sample{At: t, Pressure: resources.Level(s.Pressure), CompressorPct: s.CompressorPct, SwapUsed: s.SwapUsed, Top: top})
	}
	return out, err
}
