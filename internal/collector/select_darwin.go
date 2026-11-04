//go:build darwin

package collector

import "github.com/ericmacdougall/netwatch/internal/collector/darwin"

// New returns the macOS collector and service manager.
func New() (Collector, Service) { c := darwin.New(); return c, c }

// DefaultLogDir is ~/Library/Logs/netwatch.
func DefaultLogDir() string { return darwin.DefaultLogDir() }
