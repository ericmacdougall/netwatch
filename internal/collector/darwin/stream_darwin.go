//go:build darwin

package darwin

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ericmacdougall/netwatch/internal/execx"
	"github.com/ericmacdougall/netwatch/internal/netrate"
)

// netStream keeps one nettop running and remembers its latest sample.
type netStream struct {
	interval time.Duration

	mu       sync.Mutex
	latest   *netrate.Snapshot
	received time.Time
	lastErr  error
}

// StartNetStream switches Net to a long-lived nettop for the life of ctx.
func (c *Collector) StartNetStream(ctx context.Context, interval time.Duration) {
	s := &netStream{interval: interval}
	c.mu.Lock()
	c.stream = s
	c.mu.Unlock()
	go s.loop(ctx)
}

func (s *netStream) loop(ctx context.Context) {
	backoff := 10 * time.Second
	for ctx.Err() == nil {
		start := time.Now()
		err := s.runOnce(ctx)
		s.mu.Lock()
		s.lastErr = err
		s.mu.Unlock()
		if time.Since(start) > 5*time.Minute {
			backoff = 10 * time.Second // it ran fine for a while
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 5*time.Minute)
	}
}

func (s *netStream) runOnce(ctx context.Context) error {
	cmd := execx.Command(ctx, "/usr/bin/nettop", NettopStreamArgs(s.interval)...)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("nettop: %w", err)
	}
	p := &StreamParser{}
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		if snap := p.Feed(sc.Text(), time.Now()); snap != nil {
			s.mu.Lock()
			s.latest, s.received, s.lastErr = snap, time.Now(), nil
			s.mu.Unlock()
		}
	}
	err = cmd.Wait()
	if ctx.Err() != nil {
		return nil
	}
	if err == nil {
		err = errors.New("exited")
	}
	return fmt.Errorf("nettop stream: %w", err)
}

// get returns the latest sample, or an error while none is fresh.
func (s *netStream) get() (netrate.Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.latest == nil {
		if s.lastErr != nil {
			return netrate.Snapshot{}, s.lastErr
		}
		return netrate.Snapshot{}, errors.New("nettop stream: waiting for the first sample")
	}
	// nettop buffers output, so a sample can legitimately be a few
	// intervals old; much older means it is stuck.
	if age := time.Since(s.received); age > 6*s.interval+time.Minute {
		return netrate.Snapshot{}, fmt.Errorf("nettop stream: no sample for %s", age.Round(time.Second))
	}
	return *s.latest, nil
}
