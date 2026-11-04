// Package config holds netwatch's tunables, their defaults, and the JSON
// loader. A config file only needs the keys it changes: values are overlaid
// on the defaults, so an empty or missing file means "all defaults".
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
)

// EnvConfig names the environment variable that overrides the config path.
const EnvConfig = "NETWATCH_CONFIG"

// EnvLogDir names the environment variable that overrides the log directory.
const EnvLogDir = "NETWATCH_LOG_DIR"

// Config mirrors the JSON keys of the original prototype so existing config
// files keep working.
type Config struct {
	Interval           int      `json:"interval"`             // seconds between network samples
	OrphanEvery        int      `json:"orphan_every"`         // seconds between process scans
	NetEvery           int      `json:"net_every"`            // seconds between per-process traffic samples while healthy
	InternetHost       string   `json:"internet_host"`        // host pinged for internet health
	DegradedGwMs       float64  `json:"degraded_gw_ms"`       // avg gateway RTT considered bad
	DegradedLossPct    float64  `json:"degraded_loss_pct"`    // packet loss considered bad
	NewAppMinKbps      float64  `json:"new_app_min_kbps"`     // kilobits/s a process must move to "come online"
	TopN               int      `json:"top_n"`                // talkers kept per sample
	OrphanMinAgeMin    float64  `json:"orphan_min_age_min"`   // younger orphans are ignored
	RunawayCPUPct      float64  `json:"runaway_cpu_pct"`      // CPU considered hot
	RunawayScans       int      `json:"runaway_scans"`        // consecutive hot scans before RUNAWAY
	RunawayRSSMB       int      `json:"runaway_rss_mb"`       // RSS ceiling for RUNAWAY
	Notify             bool     `json:"notify"`               // desktop notifications on/off
	NotifyCooldownS    int      `json:"notify_cooldown_s"`    // per-key notification cooldown
	MaxLogMB           float64  `json:"max_log_mb"`           // rotate a log file above this size
	WatchPatterns      []string `json:"watch_patterns"`       // regexes on the command line; replaces defaults
	OrphanIgnore       []string `json:"orphan_ignore"`        // regexes for legitimate init-parented processes
	WatchPatternsExtra []string `json:"watch_patterns_extra"` // appended to watch_patterns
	OrphanIgnoreExtra  []string `json:"orphan_ignore_extra"`  // appended to orphan_ignore

	// Resource guard (GoodQA work-tracker-automatic#35742).
	GuardMode           string   `json:"guard_mode"`               // "" = platform default
	GuardClaudeVersions []string `json:"guard_claude_versions"`    // extra Claude versions kill may apply to
	GuardNeverSignal    []string `json:"guard_never_signal"`       // added to the built-in list
	GuardMinShare       float64  `json:"guard_min_share"`          // fraction of RAM, 0.05-1.0
	GuardGroupRAMFrac   float64  `json:"guard_group_ram_fraction"` // D4 size, 0.25-1.5
	GuardHeadroomFrac   float64  `json:"guard_headroom_frac"`      // P1 corroboration, 0.02-0.95
	GuardP1HorizonS     int      `json:"guard_p1_horizon_s"`       // 5-120
	RunCappedPaths      []string `json:"run_capped_paths"`         // empty = no sidecar is honoured
	AlertProcGB         float64  `json:"alert_proc_gb"`
	AlertGrowthGBPerMin float64  `json:"alert_growth_gb_per_min"`
	AlertSwapGB         float64  `json:"alert_swap_gb"`
	AlertChromeHelpers  int      `json:"alert_chrome_helpers"`
	ResourcesEveryS     int      `json:"resources_every_s"`
	HotAlways           bool     `json:"hot_always"` // test daemon only

	// Compiled forms, filled by Compile.
	Watch  []*regexp.Regexp `json:"-"`
	Ignore []*regexp.Regexp `json:"-"`
}

// commonWatch are dev tools that tend to outlive the terminal or test that
// started them. They are matched against the full command line; on Windows
// the executable path is normalised to forward slashes without ".exe".
var commonWatch = []string{
	`(^|/)node( |$)`,
	`(^|/)(npm|npx|pnpm|yarn|bun|deno|tsx|vite|esbuild|next-server|wrangler|workerd)( |$)`,
	`Google Chrome( Helper[^/]*)?(\.app)?/`,
	`Chromium`,
	`chrome-headless-shell`,
	`--headless`,
	`chromedriver`,
	`playwright`,
	`puppeteer`,
	`(^|/)Xvfb`,
	`Electron`,
	`chrome-native-host`,
	`crashpad_handler`,
	`(^|/)python3? .*(http\.server|uvicorn|gunicorn)`,
	`(^|/)rclone `,
	// Chrome/Edge renderer, GPU and utility helpers on Linux and Windows.
	// Only helpers carry --type=, so a normally launched browser is not matched.
	`(^|/)(chrome|chromium|chromium-browser|msedge) .*--type=`,
}

// commonIgnore are normal desktop apps whose parent is legitimately launchd.
var commonIgnore = []string{
	`^/Applications/Google Chrome\.app/Contents/MacOS/Google Chrome$`,
	`^/Applications/Google Chrome\.app/Contents/MacOS/Google Chrome -psn`,
	`^/Applications/[^/]+\.app/Contents/MacOS/[^/ ]+$`,
	`/Contents/Frameworks/Electron Framework`,
	// An installed browser's crash reporter always detaches to init by
	// design, so it would look orphaned for as long as the browser runs.
	// Handlers from test-browser caches (ms-playwright, puppeteer) are
	// still reported.
	`^/Applications/[^/]+\.app/Contents/.*crashpad_handler`,
	`^/opt/(google|microsoft|brave\.com)/[^ ]*crashpad_handler`,
	`^/usr/lib(64)?/chromium[^ ]*/[^ ]*crashpad_handler`,
	`^[A-Za-z]:/Program Files( \(x86\))?/.*crashpad_handler`,
}

// Default returns the built-in configuration.
func Default() Config {
	return Config{
		Interval:        10,
		OrphanEvery:     60,
		NetEvery:        30,
		InternetHost:    "1.1.1.1",
		DegradedGwMs:    40,
		DegradedLossPct: 10,
		NewAppMinKbps:   50,
		TopN:            6,
		OrphanMinAgeMin: 30,
		RunawayCPUPct:   80,
		RunawayScans:    3,
		RunawayRSSMB:    3000,
		Notify:          true,
		NotifyCooldownS: 600,
		MaxLogMB:        20,

		GuardMinShare:       0.25,
		GuardGroupRAMFrac:   0.75,
		GuardHeadroomFrac:   0.08,
		GuardP1HorizonS:     15,
		AlertProcGB:         8,
		AlertGrowthGBPerMin: 2,
		AlertSwapGB:         10,
		AlertChromeHelpers:  60,
		ResourcesEveryS:     10,
		WatchPatterns:       append([]string(nil), commonWatch...),
		OrphanIgnore:        append([]string(nil), commonIgnore...),
	}
}

// DefaultPath is where netwatch looks for its config when neither the
// --config flag nor NETWATCH_CONFIG is set.
func DefaultPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "netwatch.json"
	}
	return filepath.Join(dir, "netwatch", "config.json")
}

// Load reads path (missing file = defaults), validates it and compiles the
// patterns. Problems that still leave a usable config are returned as
// warnings so a typo never stops the monitor; a malformed file is an error
// and the caller decides whether to fall back to defaults.
func Load(path string) (Config, []string, error) { return LoadOpts(path, Options{}) }

// Options changes how a config is read.
type Options struct {
	// TestDaemon honours hot_always. Without it the key is ignored with a
	// warning. (The test daemon's target is the job it spawns itself, never
	// a config value.)
	TestDaemon bool
}

// LoadOpts is Load with Options.
func LoadOpts(path string, opt Options) (Config, []string, error) {
	cfg := Default()
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		warnings := cfg.Compile()
		return cfg, warnings, nil
	}
	if err != nil {
		return cfg, nil, fmt.Errorf("read config: %w", err)
	}
	return ParseOpts(data, opt)
}

// Parse overlays JSON data on the defaults (not a test daemon).
func Parse(data []byte) (Config, []string, error) { return ParseOpts(data, Options{}) }

// ParseOpts overlays JSON data on the defaults.
func ParseOpts(data []byte, opt Options) (Config, []string, error) {
	cfg := Default()
	var warnings []string
	if len(bytes.TrimSpace(data)) == 0 {
		return cfg, cfg.Compile(), nil
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		w := Default()
		return w, w.Compile(), fmt.Errorf("parse config: %w", err)
	}
	known := knownKeys()
	var unknown []string
	for k := range raw {
		if !known[k] {
			unknown = append(unknown, k)
		}
	}
	sort.Strings(unknown)
	for _, k := range unknown {
		warnings = append(warnings, fmt.Sprintf("config: unknown key %q ignored", k))
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		w := Default()
		return w, w.Compile(), fmt.Errorf("parse config: %w", err)
	}
	warnings = append(warnings, cfg.validate()...)
	warnings = append(warnings, cfg.testOnly(opt)...)
	warnings = append(warnings, cfg.Compile()...)
	return cfg, warnings, nil
}

func knownKeys() map[string]bool {
	keys := map[string]bool{}
	b, _ := json.Marshal(Default())
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	for k := range m {
		keys[k] = true
	}
	return keys
}

// validate clamps values that would make the loop spin or never fire.
func (c *Config) validate() []string {
	d := Default()
	var w []string
	clampInt := func(name string, v *int, min, def int) {
		if *v < min {
			w = append(w, fmt.Sprintf("config: %s=%d below %d; using %d", name, *v, min, def))
			*v = def
		}
	}
	clampF := func(name string, v *float64, min, def float64) {
		if *v < min {
			w = append(w, fmt.Sprintf("config: %s=%g below %g; using %g", name, *v, min, def))
			*v = def
		}
	}
	clampInt("interval", &c.Interval, 1, d.Interval)
	clampInt("orphan_every", &c.OrphanEvery, 1, d.OrphanEvery)
	clampInt("net_every", &c.NetEvery, 1, d.NetEvery)
	clampInt("top_n", &c.TopN, 1, d.TopN)
	clampInt("runaway_scans", &c.RunawayScans, 1, d.RunawayScans)
	clampInt("runaway_rss_mb", &c.RunawayRSSMB, 1, d.RunawayRSSMB)
	clampInt("notify_cooldown_s", &c.NotifyCooldownS, 0, d.NotifyCooldownS)
	clampF("orphan_min_age_min", &c.OrphanMinAgeMin, 0, d.OrphanMinAgeMin)
	clampF("max_log_mb", &c.MaxLogMB, 0.01, d.MaxLogMB)
	clampF("degraded_gw_ms", &c.DegradedGwMs, 0, d.DegradedGwMs)
	clampF("degraded_loss_pct", &c.DegradedLossPct, 0, d.DegradedLossPct)
	clampF("new_app_min_kbps", &c.NewAppMinKbps, 0, d.NewAppMinKbps)
	clampF("runaway_cpu_pct", &c.RunawayCPUPct, 0, d.RunawayCPUPct)
	w = append(w, c.validateGuard()...)
	return w
}

// guardModes are the accepted guard_mode values ("" means the platform default).
var guardModes = map[string]bool{"": true, "off": true, "alert": true, "pause": true, "pause+kill": true}

// validateGuard clamps the guard thresholds into their bounds (a value out
// of bounds is moved to the nearest bound, not reset) and fixes bad values.
func (c *Config) validateGuard() []string {
	d := Default()
	var w []string
	clampF := func(name string, v *float64, lo, hi float64) {
		switch {
		case *v != *v: // NaN
			w = append(w, fmt.Sprintf("config: %s is not a number; using %g", name, lo))
			*v = lo
		case *v < lo:
			w = append(w, fmt.Sprintf("config: %s=%g below %g; clamped to %g", name, *v, lo, lo))
			*v = lo
		case *v > hi:
			w = append(w, fmt.Sprintf("config: %s=%g above %g; clamped to %g", name, *v, hi, hi))
			*v = hi
		}
	}
	clampF("guard_min_share", &c.GuardMinShare, 0.05, 1.0)
	clampF("guard_group_ram_fraction", &c.GuardGroupRAMFrac, 0.25, 1.5)
	clampF("guard_headroom_frac", &c.GuardHeadroomFrac, 0.02, 0.95)
	if c.GuardP1HorizonS < 5 || c.GuardP1HorizonS > 120 {
		old := c.GuardP1HorizonS
		if old < 5 {
			c.GuardP1HorizonS = 5
		} else {
			c.GuardP1HorizonS = 120
		}
		w = append(w, fmt.Sprintf("config: guard_p1_horizon_s=%d out of bounds 5-120; clamped to %d", old, c.GuardP1HorizonS))
	}
	if !guardModes[c.GuardMode] {
		w = append(w, fmt.Sprintf("config: guard_mode %q is not off, alert, pause or pause+kill; using the platform default", c.GuardMode))
		c.GuardMode = ""
	}
	posF := func(name string, v *float64, def float64) {
		if !(*v > 0) {
			w = append(w, fmt.Sprintf("config: %s=%g must be positive; using %g", name, *v, def))
			*v = def
		}
	}
	posF("alert_proc_gb", &c.AlertProcGB, d.AlertProcGB)
	posF("alert_growth_gb_per_min", &c.AlertGrowthGBPerMin, d.AlertGrowthGBPerMin)
	posF("alert_swap_gb", &c.AlertSwapGB, d.AlertSwapGB)
	if c.AlertChromeHelpers < 1 {
		w = append(w, fmt.Sprintf("config: alert_chrome_helpers=%d below 1; using %d", c.AlertChromeHelpers, d.AlertChromeHelpers))
		c.AlertChromeHelpers = d.AlertChromeHelpers
	}
	if c.ResourcesEveryS < 1 {
		w = append(w, fmt.Sprintf("config: resources_every_s=%d below 1; using %d", c.ResourcesEveryS, d.ResourcesEveryS))
		c.ResourcesEveryS = d.ResourcesEveryS
	}
	return w
}

// testOnly drops the test-daemon keys unless the daemon is a test daemon.
func (c *Config) testOnly(opt Options) []string {
	if opt.TestDaemon || !c.HotAlways {
		return nil
	}
	c.HotAlways = false
	return []string{"config: hot_always is only honoured with --test-daemon; ignored"}
}

// Compile turns the pattern strings into regexps; invalid patterns are
// dropped with a warning rather than disabling all matching.
func (c *Config) Compile() []string {
	var w []string
	compile := func(name string, pats ...[]string) []*regexp.Regexp {
		var out []*regexp.Regexp
		for _, list := range pats {
			for _, p := range list {
				re, err := regexp.Compile(p)
				if err != nil {
					w = append(w, fmt.Sprintf("config: bad %s pattern %q: %v", name, p, err))
					continue
				}
				out = append(out, re)
			}
		}
		return out
	}
	c.Watch = compile("watch_patterns", c.WatchPatterns, c.WatchPatternsExtra)
	c.Ignore = compile("orphan_ignore", c.OrphanIgnore, c.OrphanIgnoreExtra)
	return w
}

// MatchAny reports whether s matches any of the patterns.
func MatchAny(res []*regexp.Regexp, s string) bool {
	for _, re := range res {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}
