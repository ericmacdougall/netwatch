//go:build linux

package linux

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

// DefaultLabel is the systemd unit name (without .service).
const DefaultLabel = "netwatch"

func unitName(label string) string {
	if label == "" {
		label = DefaultLabel
	}
	return strings.TrimSuffix(label, ".service") + ".service"
}

func unitPath(name string) (string, error) {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if !filepath.IsAbs(dir) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "systemd", "user", name), nil
}

func systemctl(args ...string) (string, error) {
	out, err := execx.Output(context.Background(), 30*time.Second, "systemctl", append([]string{"--user"}, args...)...)
	return strings.TrimSpace(string(out)), err
}

// Install writes a systemd --user unit, enables it and (re)starts it.
// Without lingering (loginctl enable-linger, which may need an admin) the
// unit runs only while the user is logged in.
func (c *Collector) Install(o platform.ServiceOptions) (string, error) {
	name := unitName(o.Label)
	path, err := unitPath(name)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(RenderUnit(o)), 0o644); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", err
	}
	if _, err := systemctl("daemon-reload"); err != nil {
		return "", fmt.Errorf("systemctl --user daemon-reload: %w", err)
	}
	if _, err := systemctl("enable", name); err != nil {
		return "", fmt.Errorf("systemctl --user enable: %w", err)
	}
	if _, err := systemctl("restart", name); err != nil {
		return "", fmt.Errorf("systemctl --user restart: %w", err)
	}
	return "installed systemd user unit " + path, nil
}

// Uninstall stops, disables and removes the unit.
func (c *Collector) Uninstall(label string) (string, error) {
	name := unitName(label)
	path, err := unitPath(name)
	if err != nil {
		return "", err
	}
	_, _ = systemctl("disable", "--now", name)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return "", err
	}
	_, _ = systemctl("daemon-reload")
	return "removed systemd user unit " + path, nil
}

// Status reports the unit's state and main PID.
func (c *Collector) Status(label string) (string, error) {
	name := unitName(label)
	out, _ := systemctl("show", name, "--property=LoadState,ActiveState,SubState,MainPID,UnitFileState")
	props := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			props[k] = v
		}
	}
	if props["LoadState"] == "" || props["LoadState"] == "not-found" {
		return "not installed", nil
	}
	return fmt.Sprintf("%s %s/%s (%s), pid %s", name, props["ActiveState"], props["SubState"],
		props["UnitFileState"], props["MainPID"]), nil
}
