package guard

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ericmacdougall/netwatch/internal/safeio"
)

// Store persists the guard State. Save must be durable (fsynced) when it
// returns, and returns how long the write took.
type Store interface {
	Load() (State, error)
	Save(State) (time.Duration, error)
}

// Store errors. A missing or corrupt file fails closed: nothing is
// adopted and the caller raises a loud alert.
var (
	ErrMissing = errors.New("guard: state file missing")
	ErrCorrupt = errors.New("guard: state file corrupt")
	ErrUnsafe  = errors.New("guard: state path is unsafe (symlink, wrong owner or permissions)")
)

// MaxStateBytes bounds a state read.
const MaxStateBytes = 4 << 20

// FileStore is the on-disk Store. The directory must be 0700 and ours;
// the file is written and read through internal/safeio (amendment A8).
type FileStore struct {
	Path string
	mu   sync.Mutex
}

// Save writes st durably.
func (f *FileStore) Save(st State) (time.Duration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	st.Version = StateVersion
	b, err := json.Marshal(st)
	if err != nil {
		return 0, err
	}
	t0 := time.Now()
	if err := writeState(f.Path, b); err != nil {
		return time.Since(t0), err
	}
	return time.Since(t0), nil
}

// Load reads the state, refusing symlinks, devices, FIFOs, foreign owners
// and wide permissions.
func (f *FileStore) Load() (State, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, err := readState(f.Path)
	if err != nil {
		return State{}, err
	}
	return decodeState(b)
}

func decodeState(b []byte) (State, error) {
	var env struct {
		Version *int `json:"version"`
	}
	if err := json.Unmarshal(b, &env); err != nil || env.Version == nil {
		return State{}, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	if *env.Version != StateVersion {
		// Valid JSON in a version we cannot interpret: trust only the
		// stable minimal envelope so start-up can still resume.
		var min struct {
			Groups map[string]struct {
				PGID        int         `json:"pgid"`
				LeaderStart time.Time   `json:"leader_start"`
				Members     []RecMember `json:"members"`
			} `json:"groups"`
		}
		st := newState()
		st.Unreadable = true
		if json.Unmarshal(b, &min) == nil {
			for k, g := range min.Groups {
				st.Groups[k] = &Record{PGID: g.PGID, LeaderStart: g.LeaderStart, Members: g.Members, Phase: PhasePaused}
			}
		}
		return st, nil
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		return State{}, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	st.init()
	return st, nil
}

// readState reads the state file through safeio: no symlink, regular file,
// ours, mode 0600 or narrower, capped.
func readState(path string) ([]byte, error) {
	b, err := safeio.ReadFile(path, safeio.Opts{Max: MaxStateBytes, RequireOwner: true, MaxPerm: 0o600})
	switch {
	case err == nil:
		return b, nil
	case errors.Is(err, os.ErrNotExist):
		return nil, ErrMissing
	case errors.Is(err, safeio.ErrTooLarge):
		return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	case errors.Is(err, safeio.ErrNotRegular), errors.Is(err, safeio.ErrOwner), errors.Is(err, safeio.ErrPerm):
		return nil, fmt.Errorf("%w: %v", ErrUnsafe, err)
	}
	return nil, err
}

// writeState writes through safeio.WriteFileAtomic (A8). A symlink at the
// target is refused up front: rename would silently replace it.
func writeState(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if li, err := os.Lstat(path); err == nil && li.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: target is a symlink", ErrUnsafe)
	}
	err := safeio.WriteFileAtomic(dir, filepath.Base(path), data)
	if errors.Is(err, safeio.ErrNotRegular) || errors.Is(err, safeio.ErrOwner) || errors.Is(err, safeio.ErrPerm) {
		return fmt.Errorf("%w: %v", ErrUnsafe, err)
	}
	return err
}

// MemStore is an in-memory Store for tests and dry runs. Delay simulates a
// slow fsync; Fail simulates a write error.
type MemStore struct {
	mu    sync.Mutex
	st    *State
	Delay time.Duration
	Fail  error
	Saves int
}

// Save implements Store.
func (s *MemStore) Save(st State) (time.Duration, error) {
	if s.Delay > 0 {
		time.Sleep(s.Delay)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Fail != nil {
		return s.Delay, s.Fail
	}
	c := st.Clone()
	c.Version = StateVersion
	s.st = &c
	s.Saves++
	return s.Delay, nil
}

// Load implements Store.
func (s *MemStore) Load() (State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st == nil {
		return State{}, ErrMissing
	}
	return s.st.Clone(), nil
}
