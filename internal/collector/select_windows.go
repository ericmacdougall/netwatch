//go:build windows

package collector

import "github.com/ericmacdougall/netwatch/internal/collector/windows"

// New returns the Windows collector and service manager.
func New() (Collector, Service) { c := windows.New(); return c, c }

// DefaultLogDir is %LOCALAPPDATA%\netwatch\logs.
func DefaultLogDir() string { return windows.DefaultLogDir() }
