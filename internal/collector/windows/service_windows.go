//go:build windows

package windows

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows/registry"

	"github.com/ericmacdougall/netwatch/internal/execx"
	"github.com/ericmacdougall/netwatch/internal/platform"
)

// DefaultLabel is the Scheduled Task (and Run value) name.
const DefaultLabel = "netwatch"

const runKey = `Software\Microsoft\Windows\CurrentVersion\Run`

func labelOr(l string) string {
	if l == "" {
		return DefaultLabel
	}
	return l
}

func schtasks(args ...string) (string, error) {
	out, err := execx.Output(context.Background(), 30*time.Second, "schtasks.exe", args...)
	return strings.TrimSpace(string(out)), err
}

// Install registers a per-user logon task. Standard users can usually
// create logon tasks for themselves from an XML definition; when policy
// forbids it, netwatch falls back to the per-user Run registry key, which
// never needs elevation. Either way the monitor is started immediately.
func (c *Collector) Install(o platform.ServiceOptions) (string, error) {
	o.Label = labelOr(o.Label)
	u, err := user.Current()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(o.LogDir, 0o700); err != nil {
		return "", err
	}
	xmlPath := filepath.Join(filepath.Dir(o.LogDir), o.Label+"-task.xml")
	if err := os.WriteFile(xmlPath, UTF16File(RenderTaskXML(o, u.Username)), 0o600); err != nil {
		return "", err
	}
	defer os.Remove(xmlPath)
	_, _ = schtasks("/End", "/TN", o.Label) // replace a running older version
	_, taskErr := schtasks("/Create", "/TN", o.Label, "/XML", xmlPath, "/F")
	if taskErr == nil {
		removeRunValue(o.Label)
		if _, err := schtasks("/Run", "/TN", o.Label); err != nil {
			return "", fmt.Errorf("task created but not started: %w", err)
		}
		return "installed Scheduled Task " + o.Label + " (runs at logon)", nil
	}
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return "", fmt.Errorf("schtasks: %v; Run key: %w", taskErr, err)
	}
	defer k.Close()
	args := append(append([]string{}, o.Args...), "run")
	if err := k.SetStringValue(o.Label, quoteArg(o.Exe)+" "+JoinArgs(args)); err != nil {
		return "", err
	}
	cmd := exec.Command(o.Exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true,
		CreationFlags: 0x00000008 | 0x00000200 | 0x08000000} // DETACHED_PROCESS | NEW_PROCESS_GROUP | NO_WINDOW
	if err := cmd.Start(); err != nil {
		return "", err
	}
	_ = cmd.Process.Release()
	return fmt.Sprintf("Scheduled Task refused (%v); installed HKCU Run entry %s instead", taskErr, o.Label), nil
}

func removeRunValue(label string) {
	if k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE); err == nil {
		_ = k.DeleteValue(label)
		k.Close()
	}
}

// Uninstall removes the task (stopping it) and any Run entry. A monitor
// started from the Run key keeps running until logoff or until stopped.
func (c *Collector) Uninstall(label string) (string, error) {
	label = labelOr(label)
	_, _ = schtasks("/End", "/TN", label)
	_, taskErr := schtasks("/Delete", "/TN", label, "/F")
	removeRunValue(label)
	if taskErr != nil {
		return "removed Run entry " + label + " (no Scheduled Task found)", nil
	}
	return "removed Scheduled Task " + label, nil
}

// Status reports the task state or the Run entry.
func (c *Collector) Status(label string) (string, error) {
	label = labelOr(label)
	if out, err := schtasks("/Query", "/TN", label, "/FO", "LIST"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			if k, v, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(k) == "Status" {
				return "Scheduled Task " + label + ": " + strings.TrimSpace(v), nil
			}
		}
		return "Scheduled Task " + label + " registered", nil
	}
	if k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE); err == nil {
		defer k.Close()
		if v, _, err := k.GetStringValue(label); err == nil {
			return "HKCU Run entry " + label + ": " + v, nil
		}
	}
	return "not installed", nil
}
