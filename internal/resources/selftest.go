//go:build darwin || linux

package resources

import (
	"errors"
	"fmt"
)

// selfTest verifies a Full reader against our own process: the footprint
// must be readable and non-zero, and a listing of our own process group
// must contain us. A wrong struct layout or a kernel change shows up here,
// and the guard then refuses to pause or kill.
func selfTest(r Full, self int) error {
	var p Proc
	if err := r.Probe(self, &p); err != nil {
		return fmt.Errorf("self-test: probe self: %w", err)
	}
	if !p.FootprintOK || p.Footprint == 0 {
		return errors.New("self-test: own footprint unreadable or zero")
	}
	if p.PID != self || p.Start.IsZero() {
		return errors.New("self-test: own identity wrong")
	}
	pgid := p.PGID
	if pgid == 0 {
		return errors.New("self-test: own pgid unknown")
	}
	got, err := r.AppendGroupMembers(nil, pgid)
	if err != nil {
		return fmt.Errorf("self-test: list own group: %w", err)
	}
	for _, m := range got {
		if m == self {
			return nil
		}
	}
	return fmt.Errorf("self-test: pid %d not in its own group %d (%d members)", self, pgid, len(got))
}
