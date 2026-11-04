package guard

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
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
// the file is written through a temp file (O_EXCL|O_NOFOLLOW, 0600),
// fsynced and renamed (amendment A8). internal/safeio will replace the
// local helpers below; they implement the same rules.
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
	if err := writeFileAtomicLocal(f.Path, b); err != nil {
		return time.Since(t0), err
	}
	return time.Since(t0), nil
}

// Load reads the state, refusing symlinks, devices, FIFOs, foreign owners
// and wide permissions.
func (f *FileStore) Load() (State, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, err := readFileLocal(f.Path, MaxStateBytes)
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

func readFileLocal(path string, max int64) ([]byte, error) {
	li, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrMissing
		}
		return nil, err
	}
	if li.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: symlink", ErrUnsafe)
	}
	fl, err := os.OpenFile(path, os.O_RDONLY|oNoFollow|oNonblock, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnsafe, err)
	}
	defer fl.Close()
	fi, err := fl.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: not a regular file", ErrUnsafe)
	}
	if !ownedBySelf(fi) || fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%w: owner or mode", ErrUnsafe)
	}
	b, err := io.ReadAll(io.LimitReader(fl, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%w: larger than %d bytes", ErrCorrupt, max)
	}
	return b, nil
}

func writeFileAtomicLocal(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	di, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if di.Mode()&os.ModeSymlink != 0 || !di.IsDir() || !ownedBySelf(di) || di.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: directory %s", ErrUnsafe, dir)
	}
	if li, err := os.Lstat(path); err == nil && li.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: target is a symlink", ErrUnsafe)
	}
	tmp := fmt.Sprintf("%s.tmp-%d-%d", path, os.Getpid(), time.Now().UnixNano())
	fl, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY|oNoFollow, 0o600)
	if err != nil {
		return err
	}
	cleanup := func() { fl.Close(); os.Remove(tmp) }
	if _, err := fl.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := fl.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := fl.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return fsyncDir(dir)
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
