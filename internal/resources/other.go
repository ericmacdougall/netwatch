//go:build !darwin && !linux

package resources

import "time"

type unsupported struct{}

// New returns a reader whose every method reports ErrUnsupported, so the
// build stays green on platforms without a collector (windows).
func New() Full { return unsupported{} }

func (unsupported) System() (System, error)              { return System{}, ErrUnsupported }
func (unsupported) Procs() ([]Proc, error)               { return nil, ErrUnsupported }
func (unsupported) Probe(int, *Proc) error               { return ErrUnsupported }
func (unsupported) GroupMembers(int) ([]int, error)      { return nil, ErrUnsupported }
func (unsupported) Children(int) ([]int, error)          { return nil, ErrUnsupported }
func (unsupported) Sid(int) (int, error)                 { return 0, ErrUnsupported }
func (unsupported) Args(int) []string                    { return nil }
func (unsupported) Env(int, ...string) map[string]string { return nil }
func (unsupported) Cwd(int) string                       { return "" }
func (unsupported) SelfTest() error                      { return ErrUnsupported }
func (unsupported) Footprint(int) (uint64, time.Time, error) {
	return 0, time.Time{}, ErrUnsupported
}
func (unsupported) AppendGroupMembers(d []int, _ int) ([]int, error) { return d, ErrUnsupported }
func (unsupported) AppendChildren(d []int, _ int) ([]int, error)     { return d, ErrUnsupported }
