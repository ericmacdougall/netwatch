//go:build linux

package collector

import "github.com/ericmacdougall/netwatch/internal/collector/linux"

// New returns the Linux collector and service manager.
func New() (Collector, Service) { c := linux.New(); return c, c }

// DefaultLogDir is $XDG_STATE_HOME/netwatch (default ~/.local/state/netwatch).
func DefaultLogDir() string { return linux.DefaultLogDir() }
