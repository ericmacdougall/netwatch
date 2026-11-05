package resources

import (
	"encoding/binary"
	"testing"
	"time"
)

func procargs(argc int32, exe string, args []string, env []string) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(argc))
	b = append(b, exe...)
	b = append(b, 0, 0, 0) // padding
	for _, a := range args {
		b = append(b, a...)
		b = append(b, 0)
	}
	for _, e := range env {
		b = append(b, e...)
		b = append(b, 0)
	}
	return b
}

func TestParseProcArgs2EnvSubset(t *testing.T) {
	buf := procargs(2, "/usr/bin/x", []string{"x", "-c"}, []string{
		"HOME=/Users/user", "CLAUDECODE=1", "AWS_SECRET_ACCESS_KEY=hunter2", "CLAUDE_PID=4242", "CLAUDECODE_X=no",
	})
	argv, env := ParseProcArgs2(buf, "CLAUDECODE", "CLAUDE_PID", "CLAUDE_CODE_SESSION_ID")
	if len(argv) != 2 || argv[0] != "x" || argv[1] != "-c" {
		t.Fatalf("argv = %q", argv)
	}
	if len(env) != 2 || env["CLAUDECODE"] != "1" || env["CLAUDE_PID"] != "4242" {
		t.Fatalf("env = %v", env)
	}
	for k, v := range env {
		if v == "hunter2" || k == "HOME" {
			t.Fatalf("unrequested env value retained: %s", k)
		}
	}
}

func TestParseProcArgs2Malformed(t *testing.T) {
	cases := map[string][]byte{
		"empty":     nil,
		"short":     {1, 0},
		"no nul":    append([]byte{1, 0, 0, 0}, "abc"...),
		"neg argc":  procargs(-5, "/x", []string{"x"}, nil),
		"huge argc": procargs(1<<30, "/x", []string{"x"}, nil),
	}
	for name, b := range cases {
		argv, env := ParseProcArgs2(b, "CLAUDECODE")
		if len(argv) != 0 || env != nil {
			t.Errorf("%s: got %q %v, want nothing", name, argv, env)
		}
	}
	// argc larger than the strings present must not panic or invent args.
	argv, _ := ParseProcArgs2(procargs(9, "/x", []string{"a", "b"}, nil), "K")
	if len(argv) != 2 {
		t.Fatalf("argv = %q", argv)
	}
}

func TestParseProcArgs2Bounded(t *testing.T) {
	big := procargs(1, "/x", []string{"x"}, nil)
	for len(big) < 2*MaxProcArgs {
		big = append(big, "PAD=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x00"...)
	}
	big = append(big, "CLAUDECODE=1\x00"...) // beyond the cap: must not be seen
	_, env := ParseProcArgs2(big, "CLAUDECODE")
	if env != nil {
		t.Fatal("value beyond MaxProcArgs was read")
	}
}

func TestParseEnviron(t *testing.T) {
	env := ParseEnviron([]byte("A=1\x00CLAUDE_PID=7\x00CLAUDECODE=1\x00=bad\x00"), "CLAUDECODE", "CLAUDE_PID")
	if env["CLAUDECODE"] != "1" || env["CLAUDE_PID"] != "7" || len(env) != 2 {
		t.Fatalf("env = %v", env)
	}
}

func TestParseSwapAndLoad(t *testing.T) {
	b := make([]byte, 32)
	binary.LittleEndian.PutUint64(b[0:], 8<<30)
	binary.LittleEndian.PutUint64(b[8:], 3<<30)
	binary.LittleEndian.PutUint64(b[16:], 5<<30)
	total, used, ok := ParseSwapUsage(b)
	if !ok || total != 8<<30 || used != 5<<30 {
		t.Fatalf("swap %d %d %v", total, used, ok)
	}
	if _, _, ok := ParseSwapUsage(b[:10]); ok {
		t.Fatal("short swap buffer accepted")
	}
	l := make([]byte, 24)
	binary.LittleEndian.PutUint32(l[0:], 2048*3/2) // 1.5 at fscale 2048
	binary.LittleEndian.PutUint64(l[16:], 2048)
	if v, ok := ParseLoadavg(l); !ok || v != 1.5 {
		t.Fatalf("load %v %v", v, ok)
	}
	binary.LittleEndian.PutUint64(l[16:], 0)
	if _, ok := ParseLoadavg(l); ok {
		t.Fatal("zero fscale accepted")
	}
}

func TestParseMeminfo(t *testing.T) {
	m := ParseMeminfo([]byte("MemTotal:       16384 kB\nMemFree:         1000 kB\nMemAvailable:    8000 kB\nInactive:        2000 kB\nSwapTotal: 4096 kB\nSwapFree: 1024 kB\nBogus: x kB\n"))
	if m.Total != 16384<<10 || m.Free != 1000<<10 || m.Available != 8000<<10 || m.Inactive != 2000<<10 ||
		m.SwapTotal != 4096<<10 || m.SwapFree != 1024<<10 {
		t.Fatalf("%+v", m)
	}
}

func TestPSILevelMapping(t *testing.T) {
	some, full, ok := ParsePSI([]byte("some avg10=3.50 avg60=1.80 avg300=2.11 total=1\nfull avg10=1.00 avg60=1.80 avg300=2.10 total=2\n"))
	if !ok || some != 3.5 || full != 1.0 {
		t.Fatalf("%v %v %v", some, full, ok)
	}
	if _, _, ok := ParsePSI([]byte("garbage")); ok {
		t.Fatal("garbage accepted")
	}
	// Just-under controls and the boundaries.
	cases := []struct {
		full float64
		want Level
	}{{0.99, LevelNormal}, {1.0, LevelWarn}, {19.99, LevelWarn}, {20.0, LevelCritical}, {0, LevelNormal}}
	for _, c := range cases {
		if got := PSILevel(c.full); got != c.want {
			t.Errorf("PSILevel(%v) = %v, want %v", c.full, got, c.want)
		}
	}
}

// Spec v11: Linux is critical at PSI full avg10 >= 20 or MemAvailable
// under 3% of RAM, whichever comes first.
func TestLinuxLevelMemAvailableFloor(t *testing.T) {
	const total = 100 << 30
	cases := []struct {
		full  float64
		avail uint64
		want  Level
	}{
		{0, total * 3 / 100, LevelNormal},   // exactly 3%: not under
		{0, total*3/100 - 1, LevelCritical}, // just under 3%
		{1.5, total / 2, LevelWarn},         // PSI alone
		{25, total / 2, LevelCritical},      // PSI alone
		{0, 0, LevelNormal},                 // MemAvailable unknown (0 total) handled below
	}
	for i, c := range cases[:4] {
		if got := LinuxLevel(c.full, c.avail, total); got != c.want {
			t.Errorf("case %d: LinuxLevel(%v, %d) = %v, want %v", i, c.full, c.avail, got, c.want)
		}
	}
	if got := LinuxLevel(0, 0, 0); got != LevelNormal {
		t.Errorf("unknown RAM must not read as critical, got %v", got)
	}
}

func TestParseStatCommWithParens(t *testing.T) {
	// comm holds spaces and a ')' so a split on spaces would shift every field.
	line := "1234 (my (odd) cmd) T 77 88 99 34816 55 4194560 100 0 0 0 5 6 0 0 20 0 1 0 424242 1000 25 18446744073709551615\n"
	s, ok := ParseStat([]byte(line))
	if !ok {
		t.Fatal("not parsed")
	}
	if s.Comm != "my (odd) cmd" || s.State != 'T' || s.PPID != 77 || s.PGRP != 88 || s.Session != 99 ||
		s.TTYNr != 34816 || s.UTime != 5 || s.STime != 6 || s.StartTicks != 424242 || s.RSSPages != 25 {
		t.Fatalf("%+v", s)
	}
	if _, ok := ParseStat([]byte("1 (x) S 1 2")); ok {
		t.Fatal("truncated stat accepted")
	}
}

func TestParseStatusAndBtime(t *testing.T) {
	rss, swap, uid := ParseStatus([]byte("Name:\tx\nUid:\t1000\t1000\t1000\t1000\nVmRSS:\t   2048 kB\nVmSwap:\t    512 kB\n"))
	if rss != 2048<<10 || swap != 512<<10 || uid != 1000 {
		t.Fatalf("%d %d %d", rss, swap, uid)
	}
	if _, _, uid := ParseStatus([]byte("Name:\tkthreadd\n")); uid != -1 {
		t.Fatal("missing Uid must be -1")
	}
	bt, ok := ParseBtime([]byte("cpu 1 2\nbtime 1700000000\n"))
	if !ok || bt.Unix() != 1700000000 {
		t.Fatal("btime")
	}
	if got := StartFromTicks(bt, 150); got.Sub(bt) != 1500*time.Millisecond {
		t.Fatal("ticks")
	}
}
