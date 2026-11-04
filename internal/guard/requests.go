package guard

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/ericmacdougall/netwatch/internal/safeio"
)

// ResumeRequests carries `netwatch resume` from the CLI to a running
// daemon. While the daemon runs, the CLI never rewrites the state file:
// two processes rewriting one file lose each other's updates, and a
// record the daemon added could vanish without its members being resumed.
// The CLI files one request per group instead; the daemon takes them at
// the start of a poll and resumes those groups itself, recorded members
// and all.
type ResumeRequests interface {
	Add(key string) error
	// Take returns every pending key and removes it.
	Take() ([]string, error)
}

// DirRequests keeps one 0600 file per request in a private directory.
type DirRequests struct{ Dir string }

const reqPrefix = "resume-"

// Add implements ResumeRequests.
func (d DirRequests) Add(key string) error {
	if !strings.HasPrefix(key, "pg:") {
		return fmt.Errorf("guard: bad group key %q", key)
	}
	name := reqPrefix + strings.ReplaceAll(strings.TrimPrefix(key, "pg:"), ":", "-")
	return safeio.WriteFileAtomic(d.Dir, name, []byte(key))
}

// Take implements ResumeRequests. Unreadable or malformed files are
// removed and skipped: a request is only ever a key the daemon looks up
// in its own records.
func (d DirRequests) Take() ([]string, error) {
	ents, err := os.ReadDir(d.Dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var keys []string
	for _, e := range ents {
		if !strings.HasPrefix(e.Name(), reqPrefix) {
			continue
		}
		p := filepath.Join(d.Dir, e.Name())
		b, rerr := safeio.ReadFile(p, safeio.Opts{Max: 128, RequireOwner: true, MaxPerm: 0o600})
		_ = os.Remove(p)
		if rerr == nil && strings.HasPrefix(string(b), "pg:") {
			keys = append(keys, string(b))
		}
	}
	return keys, nil
}

// Clear removes every request and any temp file a crashed writer left.
// Only safe while no daemon can take requests (the caller holds run.lock):
// with no daemon, a pending request has no reader.
func (d DirRequests) Clear() error {
	ents, err := os.ReadDir(d.Dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, e := range ents {
		n := e.Name()
		if strings.HasPrefix(n, reqPrefix) ||
			(strings.HasPrefix(n, "."+reqPrefix) && strings.Contains(n, ".tmp-")) {
			if rerr := os.Remove(filepath.Join(d.Dir, n)); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
				err = rerr
			}
		}
	}
	return err
}
