// Package jetsam parses macOS JetsamEvent .ips reports (a one-line JSON
// header followed by a JSON body) read through safeio with a 16 MiB cap.
// Times: snapshot = report date - timeDelta; a process started at
// snapshot - age/24e6 seconds (age is in 24 MHz ticks).
package jetsam

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/ericmacdougall/netwatch/internal/safeio"
)

// TicksPerSecond is the unit of the per-process "age" field.
const TicksPerSecond = 24e6

// MaxReportBytes caps one .ips read.
const MaxReportBytes = 16 << 20

// DefaultPageSize applies when memoryStatus.pageSize is absent (Apple
// silicon).
const DefaultPageSize = 16384

// Parse limits. They keep a hostile or corrupt report from producing
// absurd values, not from being read (safeio already caps the bytes).
const (
	maxProcs      = 200000
	maxTimeDelta  = 24 * 3600 * 1000 // ms
	maxAgeSeconds = 100 * 365 * 24 * 3600
	bugType       = "298"
)

// ErrNotJetsam is returned for a file whose header is not a bug_type 298
// report.
var ErrNotJetsam = errors.New("jetsam: not a JetsamEvent report")

// ErrMalformed wraps every other parse failure.
var ErrMalformed = errors.New("jetsam: malformed report")

// Proc is one process row from a report.
type Proc struct {
	PID       int
	Name      string
	Bytes     uint64 // rpages x page size
	Start     time.Time
	Coalition int
	Reason    string // jetsam kill reason, "" if not killed
	Idle      bool   // killed only as an idle exit
	States    []string
}

// Report is one parsed JetsamEvent.
type Report struct {
	Path             string
	Written          time.Time // header timestamp: when the report was written
	Date             time.Time // body date
	Snapshot         time.Time // Date - timeDelta
	TimeDeltaMS      int64
	Product          string
	Incident         string
	PageSize         uint64
	UncompressedPgs  uint64 // memoryStatus.uncompressed
	CompressorPgs    uint64 // memoryStatus.compressorSize
	CompressorLimPgs uint64 // when present
	MemoryPages      map[string]uint64
	Largest          string
	Procs            []Proc // sorted by Bytes, descending
	NonIdleKill      bool   // at least one non-idle process was killed
}

// Top returns the largest process row, or nil.
func (r *Report) Top() *Proc {
	if len(r.Procs) == 0 {
		return nil
	}
	return &r.Procs[0]
}

type header struct {
	BugType   string `json:"bug_type"`
	Timestamp string `json:"timestamp"`
	Incident  string `json:"incident_id"`
}

type memStatus struct {
	PageSize       uint64            `json:"pageSize"`
	Uncompressed   uint64            `json:"uncompressed"`
	CompressorSize uint64            `json:"compressorSize"`
	CompressorLim  uint64            `json:"compressorLimit"`
	MemoryPages    map[string]uint64 `json:"memoryPages"`
}

type procRow struct {
	PID       int      `json:"pid"`
	Name      string   `json:"name"`
	RPages    uint64   `json:"rpages"`
	Age       uint64   `json:"age"`
	Coalition int      `json:"coalition"`
	Reason    string   `json:"reason"`
	States    []string `json:"states"`
}

type body struct {
	Product   string    `json:"product"`
	Incident  string    `json:"incident"`
	Date      string    `json:"date"`
	TimeDelta float64   `json:"timeDelta"`
	Largest   string    `json:"largestProcess"`
	Memory    memStatus `json:"memoryStatus"`
	Processes []procRow `json:"processes"`
}

// timeLayout reads "2026-11-04 09:07:07.05 -0700" with any fraction length.
const timeLayout = "2006-01-02 15:04:05.999 -0700"

// ParseFile reads path through safeio (regular file, no symlink, 16 MiB
// cap) and parses it.
func ParseFile(path string) (*Report, error) {
	b, err := safeio.ReadFile(path, safeio.Opts{Max: MaxReportBytes})
	if err != nil {
		return nil, err
	}
	r, err := Parse(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	r.Path = path
	return r, nil
}

// Parse parses report bytes. It returns an error and never panics on
// malformed, truncated or hostile input.
func Parse(data []byte) (*Report, error) {
	nl := bytes.IndexByte(data, '\n')
	if nl < 0 {
		return nil, fmt.Errorf("%w: no body after header", ErrMalformed)
	}
	var h header
	if err := safeio.DecodeJSON(data[:nl], &h); err != nil {
		return nil, fmt.Errorf("%w: header: %v", ErrMalformed, err)
	}
	if h.BugType != bugType {
		return nil, fmt.Errorf("%w: bug_type %q", ErrNotJetsam, h.BugType)
	}
	var b body
	if err := safeio.DecodeJSON(data[nl+1:], &b); err != nil {
		return nil, fmt.Errorf("%w: body: %v", ErrMalformed, err)
	}
	return build(h, b)
}

func build(h header, b body) (*Report, error) {
	written, err := time.Parse(timeLayout, h.Timestamp)
	if err != nil {
		return nil, fmt.Errorf("%w: header timestamp %q", ErrMalformed, h.Timestamp)
	}
	date, err := time.Parse(timeLayout, b.Date)
	if err != nil {
		return nil, fmt.Errorf("%w: body date %q", ErrMalformed, b.Date)
	}
	if math.IsNaN(b.TimeDelta) || b.TimeDelta < 0 || b.TimeDelta > maxTimeDelta {
		return nil, fmt.Errorf("%w: timeDelta %v", ErrMalformed, b.TimeDelta)
	}
	if len(b.Processes) == 0 {
		return nil, fmt.Errorf("%w: no processes", ErrMalformed)
	}
	if len(b.Processes) > maxProcs {
		return nil, fmt.Errorf("%w: %d processes", ErrMalformed, len(b.Processes))
	}
	page := b.Memory.PageSize
	if page == 0 {
		page = DefaultPageSize
	}
	if page&(page-1) != 0 || page > 1<<20 {
		return nil, fmt.Errorf("%w: pageSize %d", ErrMalformed, page)
	}
	delta := int64(math.Round(b.TimeDelta))
	snap := date.Add(-time.Duration(delta) * time.Millisecond)
	inc := b.Incident
	if inc == "" {
		inc = h.Incident
	}
	r := &Report{
		Written: written.UTC(), Date: date.UTC(), Snapshot: snap.UTC(),
		TimeDeltaMS: delta, Product: b.Product, Incident: inc, PageSize: page,
		UncompressedPgs: b.Memory.Uncompressed, CompressorPgs: b.Memory.CompressorSize,
		CompressorLimPgs: b.Memory.CompressorLim, MemoryPages: b.Memory.MemoryPages,
		Largest: b.Largest,
	}
	for _, p := range b.Processes {
		if p.RPages > math.MaxUint64/page {
			return nil, fmt.Errorf("%w: rpages overflow for pid %d", ErrMalformed, p.PID)
		}
		// A process younger than the snapshot has a wrapped (two's
		// complement) age in real reports, so read it as signed. An
		// implausible age leaves Start unknown (zero) instead of rejecting
		// the report: one odd row must not hide the rest.
		var start time.Time
		if secs := float64(int64(p.Age)) / TicksPerSecond; math.Abs(secs) <= maxAgeSeconds {
			start = snap.Add(-time.Duration(secs * float64(time.Second))).UTC()
		}
		pr := Proc{
			PID: p.PID, Name: p.Name, Bytes: p.RPages * page, Start: start,
			Coalition: p.Coalition, Reason: p.Reason, States: p.States,
			Idle: p.Reason == "idle-exit",
		}
		if p.Reason != "" && !pr.Idle {
			r.NonIdleKill = true
		}
		r.Procs = append(r.Procs, pr)
	}
	sort.SliceStable(r.Procs, func(i, j int) bool { return r.Procs[i].Bytes > r.Procs[j].Bytes })
	return r, nil
}
