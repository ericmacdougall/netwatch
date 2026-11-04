// Package jetsam parses macOS JetsamEvent .ips reports (a one-line JSON
// header followed by a JSON body) read through safeio with a 16 MiB cap.
// Times: snapshot = report date - timeDelta; a process started at
// snapshot - age/24e6 seconds (age is in 24 MHz ticks).
package jetsam

import "time"

// TicksPerSecond is the unit of the per-process "age" field.
const TicksPerSecond = 24e6

// MaxReportBytes caps one .ips read.
const MaxReportBytes = 16 << 20

// Proc is one process row from a report.
type Proc struct {
	PID       int
	Name      string
	Bytes     uint64 // rpages x page size
	Start     time.Time
	Coalition int
	Reason    string // jetsam kill reason, "" if not killed
	Idle      bool
}

// Report is one parsed JetsamEvent.
type Report struct {
	Path             string
	Date             time.Time // header timestamp
	Snapshot         time.Time // Date - timeDelta
	PageSize         uint64
	UncompressedPgs  uint64 // memoryStatus.uncompressed
	CompressorLimPgs uint64 // when present
	Largest          string
	Procs            []Proc // sorted by Bytes, descending
	NonIdleKill      bool   // at least one non-idle process was killed
}
