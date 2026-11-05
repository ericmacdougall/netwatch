package config

import (
	"strings"
	"testing"
)

func TestGuardDefaults(t *testing.T) {
	c := Default()
	if c.GuardMinShare != 0.25 || c.GuardGroupRAMFrac != 0.75 || c.GuardHeadroomFrac != 0.08 || c.GuardP1HorizonS != 15 ||
		c.AlertProcGB != 8 || c.AlertGrowthGBPerMin != 2 || c.AlertSwapGB != 10 || c.AlertChromeHelpers != 60 ||
		c.ResourcesEveryS != 10 || c.GuardMode != "" || c.GuardNeverSignal != nil || len(c.RunCappedPaths) != 0 || c.HotAlways {
		t.Fatalf("defaults wrong: %+v", c)
	}
	_, w, err := Parse([]byte(`{}`))
	if err != nil || len(w) != 0 {
		t.Fatalf("defaults must not warn: %v %v", err, w)
	}
}

func TestGuardBoundsAreClampedWithAWarning(t *testing.T) {
	cases := []struct {
		json string
		key  string
		get  func(Config) any
		want any
	}{
		{`{"guard_min_share":0.01}`, "guard_min_share", func(c Config) any { return c.GuardMinShare }, 0.05},
		{`{"guard_min_share":3}`, "guard_min_share", func(c Config) any { return c.GuardMinShare }, 1.0},
		{`{"guard_group_ram_fraction":0.1}`, "guard_group_ram_fraction", func(c Config) any { return c.GuardGroupRAMFrac }, 0.25},
		{`{"guard_group_ram_fraction":9}`, "guard_group_ram_fraction", func(c Config) any { return c.GuardGroupRAMFrac }, 1.5},
		{`{"guard_headroom_frac":0}`, "guard_headroom_frac", func(c Config) any { return c.GuardHeadroomFrac }, 0.02},
		{`{"guard_headroom_frac":1}`, "guard_headroom_frac", func(c Config) any { return c.GuardHeadroomFrac }, 0.95},
		{`{"guard_p1_horizon_s":1}`, "guard_p1_horizon_s", func(c Config) any { return c.GuardP1HorizonS }, 5},
		{`{"guard_p1_horizon_s":999}`, "guard_p1_horizon_s", func(c Config) any { return c.GuardP1HorizonS }, 120},
		{`{"alert_proc_gb":0}`, "alert_proc_gb", func(c Config) any { return c.AlertProcGB }, 8.0},
		{`{"alert_chrome_helpers":0}`, "alert_chrome_helpers", func(c Config) any { return c.AlertChromeHelpers }, 60},
		{`{"resources_every_s":0}`, "resources_every_s", func(c Config) any { return c.ResourcesEveryS }, 10},
		{`{"guard_mode":"yolo"}`, "guard_mode", func(c Config) any { return c.GuardMode }, ""},
	}
	for _, c := range cases {
		cfg, w, err := Parse([]byte(c.json))
		if err != nil {
			t.Fatalf("%s: %v", c.json, err)
		}
		if got := c.get(cfg); got != c.want {
			t.Errorf("%s: got %v want %v", c.json, got, c.want)
		}
		if len(w) != 1 || !strings.Contains(w[0], c.key) {
			t.Errorf("%s: want one warning naming %s, got %v", c.json, c.key, w)
		}
	}
	// Control: in-bounds values (including the bounds themselves) pass silently.
	cfg, w, _ := Parse([]byte(`{"guard_min_share":0.05,"guard_group_ram_fraction":1.5,"guard_headroom_frac":0.95,"guard_p1_horizon_s":120,"guard_mode":"pause+kill"}`))
	if len(w) != 0 || cfg.GuardMinShare != 0.05 || cfg.GuardMode != "pause+kill" {
		t.Fatalf("bounds are inclusive: %v %+v", w, cfg)
	}
}

func TestTestOnlyKeysIgnoredWithoutTestDaemon(t *testing.T) {
	js := []byte(`{"hot_always":true}`)
	cfg, w, err := Parse(js)
	if err != nil || cfg.HotAlways || len(w) != 1 {
		t.Fatalf("a normal daemon must ignore hot_always with a warning: %v %v %+v", err, w, cfg)
	}
	// Control: a test daemon honours it.
	cfg, w, err = ParseOpts(js, Options{TestDaemon: true})
	if err != nil || !cfg.HotAlways || len(w) != 0 {
		t.Fatalf("test daemon must honour hot_always: %v %v %+v", err, w, cfg)
	}
	// The removed target keys are unknown: a config can never aim the guard.
	_, w, _ = ParseOpts([]byte(`{"guard_test_target":"4242@1"}`), Options{TestDaemon: true})
	if len(w) != 1 || !strings.Contains(w[0], "unknown key") {
		t.Fatalf("guard_test_target must be an unknown key: %v", w)
	}
}

func TestGuardKeysAreKnown(t *testing.T) {
	_, w, _ := Parse([]byte(`{"guard_never_signal":["foo"],"guard_claude_versions":["2.1.318"],"run_capped_paths":["/x/run_capped"]}`))
	if len(w) != 0 {
		t.Fatalf("guard keys must be known keys: %v", w)
	}
	cfg, _, _ := Parse([]byte(`{"guard_never_signal":[]}`))
	if cfg.GuardNeverSignal == nil {
		t.Fatalf("an explicit empty list must stay non-nil (nothing is never-signal), distinct from the default nil")
	}
}
