package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseOverlaysDefaults(t *testing.T) {
	cfg, warnings, err := Parse([]byte(`{"interval": 5, "orphan_min_age_min": 0, "notify": false}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	if cfg.Interval != 5 || cfg.OrphanMinAgeMin != 0 || cfg.Notify {
		t.Fatalf("overrides not applied: %+v", cfg)
	}
	if cfg.OrphanEvery != 60 || cfg.InternetHost != "1.1.1.1" || cfg.TopN != 6 {
		t.Fatalf("defaults lost: %+v", cfg)
	}
	if len(cfg.Watch) != len(commonWatch) || len(cfg.Ignore) != len(commonIgnore) {
		t.Fatalf("patterns not compiled: %d %d", len(cfg.Watch), len(cfg.Ignore))
	}
}

func TestListsReplaceButExtraAppends(t *testing.T) {
	cfg, _, err := Parse([]byte(`{"watch_patterns": ["^foo$"], "orphan_ignore_extra": ["bar"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Watch) != 1 || !MatchAny(cfg.Watch, "foo") || MatchAny(cfg.Watch, "node x") {
		t.Fatalf("watch_patterns should replace defaults, got %d", len(cfg.Watch))
	}
	if len(cfg.Ignore) != len(commonIgnore)+1 || !MatchAny(cfg.Ignore, "xbarx") {
		t.Fatalf("orphan_ignore_extra should append, got %d", len(cfg.Ignore))
	}
}

func TestWarningsForUnknownKeysBadRegexAndBadValues(t *testing.T) {
	cfg, warnings, err := Parse([]byte(`{"intervall": 3, "interval": 0, "watch_patterns": ["(", "ok"], "max_log_mb": -1}`))
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(warnings, "\n")
	for _, want := range []string{`unknown key "intervall"`, "interval=0", `bad watch_patterns pattern "("`, "max_log_mb"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing warning %q in:\n%s", want, joined)
		}
	}
	if cfg.Interval != 10 || cfg.MaxLogMB != 20 {
		t.Fatalf("bad values should fall back to defaults: %+v", cfg)
	}
	if len(cfg.Watch) != 1 {
		t.Fatalf("valid pattern should survive a bad sibling, got %d", len(cfg.Watch))
	}
}

func TestMalformedJSONIsErrorWithUsableDefaults(t *testing.T) {
	cfg, _, err := Parse([]byte(`{"interval": `))
	if err == nil {
		t.Fatal("expected parse error")
	}
	if cfg.Interval != 10 || len(cfg.Watch) == 0 {
		t.Fatalf("fallback config not usable: %+v", cfg)
	}
	if _, _, err := Parse([]byte(`{"interval": "ten"}`)); err == nil {
		t.Fatal("wrong type should be an error")
	}
}

func TestLoadMissingAndEmptyFile(t *testing.T) {
	dir := t.TempDir()
	cfg, _, err := Load(filepath.Join(dir, "nope.json"))
	if err != nil || cfg.Interval != 10 || len(cfg.Watch) == 0 {
		t.Fatalf("missing file should be defaults: %v %+v", err, cfg)
	}
	p := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(p, []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if cfg, _, err = Load(p); err != nil || cfg.Interval != 10 {
		t.Fatalf("empty file should be defaults: %v", err)
	}
}

func TestDefaultPatternsMatchExpectedCommands(t *testing.T) {
	cfg := Default()
	cfg.Compile()
	watched := []string{
		"/usr/local/bin/node server.js",
		"node",
		"C:/Program Files/nodejs/node -e x",
		"/opt/google/chrome/chrome --type=renderer --lang=en",
		"C:/Program Files/Google/Chrome/Application/chrome --type=gpu-process",
		"/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Helpers/Google Chrome Helper (Renderer).app/Contents/MacOS/Google Chrome Helper (Renderer) --type=renderer",
		"/home/u/.cache/ms-playwright/chromium-1/chrome-linux/headless_shell --headless",
		"python3 -m http.server 8000",
		"/usr/bin/Xvfb :99",
	}
	for _, c := range watched {
		if !MatchAny(cfg.Watch, c) {
			t.Errorf("should be watched: %q", c)
		}
	}
	notWatched := []string{
		"/usr/bin/nodejs-helper-thing",
		"/opt/google/chrome/chrome",
		"/usr/sbin/sshd -D",
		"vim notes.md",
	}
	for _, c := range notWatched {
		if MatchAny(cfg.Watch, c) {
			t.Errorf("should not be watched: %q", c)
		}
	}
	if !MatchAny(cfg.Ignore, "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome") {
		t.Error("main Chrome app should be ignored as an orphan")
	}
}
