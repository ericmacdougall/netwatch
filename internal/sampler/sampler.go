// Package sampler builds the resources.jsonl record (a system reading plus
// the top processes by footprint and by CPU) and implements `netwatch top`.
//
// Command lines are redacted and truncated before they leave this package;
// callers never see raw argv.
package sampler

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/ericmacdougall/netwatch/internal/attrib"
	"github.com/ericmacdougall/netwatch/internal/danger"
	"github.com/ericmacdougall/netwatch/internal/redact"
	"github.com/ericmacdougall/netwatch/internal/resources"
)

// Defaults.
const (
	DefaultTopN   = 10
	MaxCmdRunes   = 160
	MaxCwdRunes   = 200
	DefaultWindow = time.Second // CPU sampling interval for one-shot top
)

// Row is one process in a top list.
type Row struct {
	PID       int     `json:"pid"`
	PPID      int     `json:"ppid"`
	PGID      int     `json:"pgid"`
	Start     string  `json:"start"` // RFC 3339, identifies the process across pid reuse
	Name      string  `json:"name"`
	Footprint uint64  `json:"footprint"`
	CPUPct    float64 `json:"cpu_pct"`
	Cmd       string  `json:"cmd"`
	Cwd       string  `json:"cwd,omitempty"`
	// Agent and Confidence are attribution (informational only), filled by the caller.
	Agent      string  `json:"agent,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
}

// SysRecord is the system part of the record.
type SysRecord struct {
	RAM               uint64  `json:"ram_bytes"`
	PageSize          uint64  `json:"page_size"`
	FreePages         uint64  `json:"free_pages"`
	SpeculativePages  uint64  `json:"speculative_pages"`
	PurgeablePages    uint64  `json:"purgeable_pages"`
	InactivePages     uint64  `json:"inactive_pages"`
	InactiveEstimated bool    `json:"inactive_estimated,omitempty"`
	HeadroomBytes     uint64  `json:"headroom_bytes"`
	CompressorBytes   uint64  `json:"compressor_bytes"`
	PagesCompressed   uint64  `json:"pages_compressed"`
	PagesCompLimit    uint64  `json:"pages_compressed_limit"`
	Segments          uint64  `json:"compressor_segments"`
	SegmentLimit      uint64  `json:"compressor_segment_limit"`
	SwapUsed          uint64  `json:"swap_used_bytes"`
	SwapTotal         uint64  `json:"swap_total_bytes"`
	DiskFree          uint64  `json:"disk_free_bytes"`
	Pressure          string  `json:"pressure"`
	Load1             float64 `json:"load1"`
	PSIFullAvg10      float64 `json:"psi_full_avg10,omitempty"`
	MemAvailable      uint64  `json:"mem_available_bytes,omitempty"`
}

// Record is one line of resources.jsonl.
type Record struct {
	TS            string    `json:"ts"`
	Pressure      string    `json:"pressure"`
	CompressorPct float64   `json:"compressor_pct"` // larger of page and segment fill, percent
	SwapUsed      uint64    `json:"swap_used"`      // bytes
	Sys           SysRecord `json:"sys"`
	TopMem        []Row     `json:"top_mem"`
	TopCPU        []Row     `json:"top_cpu"`
	Unread        int       `json:"unreadable_procs"`
}

// SysFrom converts a reading.
func SysFrom(s resources.System) SysRecord {
	return SysRecord{
		RAM: s.RAM, PageSize: s.PageSize,
		FreePages: s.Free, SpeculativePages: s.Speculative, PurgeablePages: s.Purgeable, InactivePages: s.Inactive,
		InactiveEstimated: s.InactiveEstimated, HeadroomBytes: danger.Headroom(s),
		CompressorBytes: s.CompressorBytes, PagesCompressed: s.PagesCompressed, PagesCompLimit: s.PagesCompressedLimit,
		Segments: s.Segments, SegmentLimit: s.SegmentLimit,
		SwapUsed: s.SwapUsed, SwapTotal: s.SwapTotal, DiskFree: s.DiskFree,
		Pressure: s.Pressure.String(), Load1: s.Load1, PSIFullAvg10: s.PSIFullAvg10, MemAvailable: s.MemAvailable,
	}
}

type key struct {
	pid   int
	start int64
}

// Sampler remembers the previous scan so it can turn cumulative CPU time
// into a percentage.
type Sampler struct {
	R   resources.Reader
	N   int
	Now func() time.Time

	prev   map[key]time.Duration
	prevAt time.Time
}

// New returns a sampler listing the top n (default 10) processes.
func New(r resources.Reader, n int) *Sampler {
	if n <= 0 {
		n = DefaultTopN
	}
	return &Sampler{R: r, N: n, Now: time.Now}
}

// Sample takes one system reading and one process scan. The CPU
// percentage of a process is zero on the first sample (no baseline).
func (s *Sampler) Sample() (Record, error) {
	now := s.Now()
	sys, err := s.R.System()
	if err != nil {
		return Record{}, err
	}
	procs, err := s.R.Procs()
	if err != nil {
		return Record{}, err
	}
	rec := Record{TS: now.UTC().Format(time.RFC3339), Sys: SysFrom(sys),
		Pressure: sys.Pressure.String(), CompressorPct: CompressorPct(sys), SwapUsed: sys.SwapUsed}
	rows, unread := s.rows(procs, now)
	rec.Unread = unread
	rec.TopMem = s.pick(rows, func(a, b *Row) bool { return a.Footprint > b.Footprint }, s.N)
	rec.TopCPU = s.pick(rows, func(a, b *Row) bool { return a.CPUPct > b.CPUPct }, s.N)
	return rec, nil
}

// CompressorPct is the compressor fill, the larger of the page and segment
// ratios, in percent (the D2 quantity). Zero when the limits are unknown.
func CompressorPct(s resources.System) float64 {
	var f float64
	if s.PagesCompressedLimit > 0 {
		f = float64(s.PagesCompressed) / float64(s.PagesCompressedLimit)
	}
	if s.SegmentLimit > 0 {
		if g := float64(s.Segments) / float64(s.SegmentLimit); g > f {
			f = g
		}
	}
	return f * 100
}

// Line returns the record as one JSON line (no trailing newline).
func (r Record) Line() ([]byte, error) { return json.Marshal(r) }

// rows converts readable processes to rows (without cmd/cwd yet, which
// are filled only for the ones that make a list) and updates the CPU
// baseline.
func (s *Sampler) rows(procs []resources.Proc, now time.Time) ([]Row, int) {
	next := make(map[key]time.Duration, len(procs))
	dt := now.Sub(s.prevAt)
	rows := make([]Row, 0, len(procs))
	unread := 0
	for _, p := range procs {
		if !p.FootprintOK {
			unread++
			continue
		}
		k := key{p.PID, p.Start.UnixNano()}
		next[k] = p.CPUTime
		r := Row{PID: p.PID, PPID: p.PPID, PGID: p.PGID, Start: p.Start.UTC().Format(time.RFC3339), Name: p.Name, Footprint: p.Footprint}
		if prev, ok := s.prev[k]; ok && dt > 0 && p.CPUTime >= prev {
			r.CPUPct = float64(p.CPUTime-prev) / float64(dt) * 100
		}
		rows = append(rows, r)
	}
	s.prev, s.prevAt = next, now
	return rows, unread
}

// pick returns the top n rows under less, with cmd and cwd filled in.
func (s *Sampler) pick(rows []Row, less func(a, b *Row) bool, n int) []Row {
	c := make([]Row, len(rows))
	copy(c, rows)
	sort.SliceStable(c, func(i, j int) bool {
		if less(&c[i], &c[j]) != less(&c[j], &c[i]) {
			return less(&c[i], &c[j])
		}
		return c[i].PID < c[j].PID
	})
	if len(c) > n {
		c = c[:n]
	}
	for i := range c {
		c[i].Cmd = Cmd(s.R, c[i].PID, c[i].Name)
		c[i].Cwd = clip(redact.Display(s.R.Cwd(c[i].PID)), MaxCwdRunes)
	}
	return c
}

// Cmd returns the redacted, truncated command line of pid, falling back to
// the process name when argv is unreadable (other users' processes).
func Cmd(r resources.Reader, pid int, name string) string {
	if argv := r.Args(pid); len(argv) > 0 {
		return attrib.CommandLine(argv, MaxCmdRunes)
	}
	return clip(redact.Display(name), MaxCmdRunes)
}

func clip(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

// Mode selects what Top ranks by.
type Mode string

// Modes.
const (
	ByMem Mode = "mem"
	ByCPU Mode = "cpu"
)

// Top ranks processes once. By CPU it needs two scans `interval` apart
// (sleep is injectable for tests); by memory one scan suffices. Processes
// whose footprint the kernel will not reveal (other users on macOS) are
// excluded and counted in the second result.
func Top(r resources.Reader, mode Mode, n int, interval time.Duration, now func() time.Time, sleep func(time.Duration)) ([]Row, int, error) {
	if n <= 0 {
		n = DefaultTopN
	}
	if now == nil {
		now = time.Now
	}
	s := &Sampler{R: r, N: n, Now: now}
	procs, err := r.Procs()
	if err != nil {
		return nil, 0, err
	}
	rows, unread := s.rows(procs, now())
	if mode == ByCPU {
		if interval <= 0 {
			interval = DefaultWindow
		}
		if sleep == nil {
			sleep = time.Sleep
		}
		sleep(interval)
		procs, err = r.Procs()
		if err != nil {
			return nil, 0, err
		}
		rows, unread = s.rows(procs, now())
		return s.pick(rows, func(a, b *Row) bool { return a.CPUPct > b.CPUPct }, n), unread, nil
	}
	return s.pick(rows, func(a, b *Row) bool { return a.Footprint > b.Footprint }, n), unread, nil
}

// Write prints rows as a table, or as JSON when asJSON is set.
func Write(w io.Writer, mode Mode, rows []Row, unread int, asJSON bool) error {
	if asJSON {
		b, err := json.Marshal(struct {
			Mode       string `json:"mode"`
			Rows       []Row  `json:"rows"`
			Unreadable int    `json:"unreadable_procs"`
		}{string(mode), rows, unread})
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(w, "%s\n", b)
		return err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%7s %7s %10s %6s  %s\n", "PID", "PPID", "FOOTPRINT", "CPU%", "COMMAND")
	for _, r := range rows {
		fmt.Fprintf(&b, "%7d %7d %10s %6.1f  %s\n", r.PID, r.PPID, human(r.Footprint), r.CPUPct, redact.Display(r.Cmd))
		if r.Cwd != "" {
			fmt.Fprintf(&b, "%27s  cwd %s\n", "", r.Cwd)
		}
	}
	if unread > 0 {
		fmt.Fprintf(&b, "(%d processes owned by other users are not readable and are not ranked)\n", unread)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func human(b uint64) string {
	const gib = 1 << 30
	switch {
	case b >= gib:
		return fmt.Sprintf("%.1f GB", float64(b)/gib)
	case b >= 1<<20:
		return fmt.Sprintf("%d MB", b>>20)
	}
	return fmt.Sprintf("%d KB", b>>10)
}
