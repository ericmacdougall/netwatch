// Package collector defines what netwatch needs from the operating system
// and selects the implementation for the current platform at build time.
// Each platform lives in its own package (darwin, linux, windows) behind
// build tags.
package collector

import (
	"context"

	"github.com/ericmacdougall/netwatch/internal/health"
	"github.com/ericmacdougall/netwatch/internal/netrate"
	"github.com/ericmacdougall/netwatch/internal/platform"
	"github.com/ericmacdougall/netwatch/internal/procscan"
)

// Gateway is the default route.
type Gateway = platform.Gateway

// ServiceOptions describes the background service to register.
type ServiceOptions = platform.ServiceOptions

// Collector reads processes and network state.
type Collector interface {
	// Processes returns the process table. CPU is a recent percentage of
	// one core; collectors without a native recent figure compute it from
	// the previous call (or the lifetime average on the first call).
	Processes(ctx context.Context) ([]procscan.Process, error)
	// Net returns cumulative per-process counters, plus interface totals
	// for iface when available.
	Net(ctx context.Context, iface string) (netrate.Snapshot, error)
	Gateway(ctx context.Context) (Gateway, error)
	// Ping sends count echo requests; it never returns nil.
	Ping(ctx context.Context, host string, count int) *health.Ping
	// OrphanRule is this platform's definition of "lost its parent".
	OrphanRule() procscan.OrphanRule
	// Terminate asks a verified process to exit. Unix sends SIGTERM only.
	// Windows has no SIGTERM: without force it asks politely (taskkill)
	// and with force it calls TerminateProcess.
	Terminate(p procscan.Process, force bool) error
	// Notify shows a desktop notification, or returns an error if the
	// platform cannot.
	Notify(title, msg string) error
}

// Service installs netwatch as a per-user background service.
type Service interface {
	Install(opts ServiceOptions) (string, error)
	Uninstall(label string) (string, error)
	Status(label string) (string, error)
}
