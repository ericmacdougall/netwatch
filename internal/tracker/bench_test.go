//go:build !windows

package tracker

import (
	"os/exec"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/ericmacdougall/netwatch/internal/alerts"
	"github.com/ericmacdougall/netwatch/internal/guard"
	"github.com/ericmacdougall/netwatch/internal/resources"
)

// spawnGroups starts n process groups of three sleepers each (a shell and
// two children). Only these spawned processes are ever killed.
func spawnGroups(tb testing.TB, n int) []GroupInfo {
	tb.Helper()
	r := resources.New()
	var gs []GroupInfo
	for i := 0; i < n; i++ {
		c := exec.Command("/bin/sh", "-c", "sleep 120 & sleep 120 & wait")
		c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := c.Start(); err != nil {
			tb.Fatal(err)
		}
		cmd := c
		tb.Cleanup(func() { syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); cmd.Wait() }) // our own spawned group only
		var p resources.Proc
		for tries := 0; tries < 100; tries++ {
			if r.(resources.Prober).Probe(c.Process.Pid, &p) == nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		gs = append(gs, GroupInfo{PGID: c.Process.Pid, LeaderStart: p.Start, Tier: guard.TierTool, Agent: "main", Cmd: "sh -c sleep " + strconv.Itoa(i)})
	}
	time.Sleep(200 * time.Millisecond) // let the children start
	return gs
}

// BenchmarkPollAndScan is the guard's steady-state cost: one tracker poll
// (system reading plus top-16 group listing and footprints) and one full
// scan with its aggregation and alert evaluation. Run on the host being
// measured; the groups are real processes the benchmark spawned.
func BenchmarkPollAndScan(b *testing.B) {
	r := resources.New()
	tr := New(r.(Source), Config{})
	tr.SetGroups(spawnGroups(b, 8))
	eng := alerts.New(alerts.Config{}, nil, nil)
	owner := func(p resources.Proc) string { return p.Name }
	b.ReportAllocs()
	b.ResetTimer()
	now := time.Now()
	var procs int
	for i := 0; i < b.N; i++ {
		now = now.Add(10 * time.Second)
		sys, err := r.System()
		if err != nil {
			b.Fatal(err)
		}
		terms := tr.Poll(now, sys)
		scan, err := r.Procs()
		if err != nil {
			b.Fatal(err)
		}
		procs = len(scan)
		tr.SetScan(scan, owner)
		eng.Evaluate(alerts.Input{At: now, Sys: sys, Procs: scan})
		if len(terms) < 2 {
			b.Fatal("no terms")
		}
	}
	b.ReportMetric(float64(procs), "procs")
}

// BenchmarkPollOnly is the 2s hot-loop cost: system reading plus the poll
// of eight groups, without the full scan.
func BenchmarkPollOnly(b *testing.B) {
	r := resources.New()
	tr := New(r.(Source), Config{})
	tr.SetGroups(spawnGroups(b, 8))
	b.ReportAllocs()
	b.ResetTimer()
	now := time.Now()
	for i := 0; i < b.N; i++ {
		now = now.Add(2 * time.Second)
		sys, _ := r.System()
		tr.Poll(now, sys)
	}
}
