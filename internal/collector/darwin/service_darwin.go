//go:build darwin

package darwin

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ericmacdougall/netwatch/internal/execx"
	"github.com/ericmacdougall/netwatch/internal/platform"
)

// DefaultLabel is the LaunchAgent label used when none is given. It matches
// the label of the original prototype so installing replaces it.
const DefaultLabel = "com.ericmacdougall.netwatch"

func labelOr(l string) string {
	if l == "" {
		return DefaultLabel
	}
	return l
}

func plistPath(label string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "LaunchAgents", label+".plist"), nil
}

func domain() string { return fmt.Sprintf("gui/%d", os.Getuid()) }

func launchctl(args ...string) (string, error) {
	out, err := execx.Output(context.Background(), 30*time.Second, "/bin/launchctl", args...)
	return strings.TrimSpace(string(out)), err
}

// Install writes the LaunchAgent and (re)loads it, replacing any agent with
// the same label (including an older netwatch).
func (c *Collector) Install(o platform.ServiceOptions) (string, error) {
	o.Label = labelOr(o.Label)
	path, err := plistPath(o.Label)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	if err := os.MkdirAll(o.LogDir, 0o700); err != nil {
		return "", err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(RenderPlist(o)), 0o644); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", err
	}
	// bootout fails harmlessly when nothing is loaded.
	_, _ = launchctl("bootout", domain()+"/"+o.Label)
	var lastErr error
	for i := 0; i < 5; i++ { // bootout is asynchronous; bootstrap can race it
		if _, lastErr = launchctl("bootstrap", domain(), path); lastErr == nil {
			return "installed LaunchAgent " + path, nil
		}
		time.Sleep(time.Second)
	}
	return "", fmt.Errorf("launchctl bootstrap: %w", lastErr)
}

// Uninstall unloads and removes the LaunchAgent.
func (c *Collector) Uninstall(label string) (string, error) {
	label = labelOr(label)
	path, err := plistPath(label)
	if err != nil {
		return "", err
	}
	_, _ = launchctl("bootout", domain()+"/"+label)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return "", err
	}
	return "removed LaunchAgent " + path, nil
}

// Status reports whether the agent is loaded and its PID.
func (c *Collector) Status(label string) (string, error) {
	label = labelOr(label)
	out, err := launchctl("print", domain()+"/"+label)
	if err != nil {
		return "not loaded", nil
	}
	state, pid := "unknown", "-"
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "state = "); ok && state == "unknown" {
			state = v
		}
		if v, ok := strings.CutPrefix(line, "pid = "); ok {
			pid = v
		}
	}
	return fmt.Sprintf("loaded, state %s, pid %s", state, pid), nil
}
