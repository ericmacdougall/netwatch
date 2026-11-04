// Package platform holds the small value types shared by the collector
// interface and the per-OS implementations, so neither imports the other.
package platform

// Gateway is the default route.
type Gateway struct {
	Addr  string // next hop; empty when there is no default route
	Iface string
}

// ServiceOptions describes the background service to register.
type ServiceOptions struct {
	Exe    string   // absolute path of the netwatch binary
	Args   []string // global arguments placed before "run", e.g. --config FILE
	LogDir string
	Label  string // launchd label / systemd unit name / scheduled task name
}
