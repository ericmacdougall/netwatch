// Package guardmode reads and writes the guard mode file, <state dir>/mode.
// Any same-user process can change the mode, so every change carries a
// redacted attribution label and the caller logs and notifies MODE_CHANGE.
package guardmode

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ericmacdougall/netwatch/internal/guard"
	"github.com/ericmacdougall/netwatch/internal/redact"
	"github.com/ericmacdougall/netwatch/internal/safeio"
)

// File is the mode file's name inside the state directory.
const File = "mode"

const maxBytes = 4 << 10

// Record is the file's content.
type Record struct {
	Mode  string    `json:"mode"`
	SetAt time.Time `json:"set_at"`
	By    string    `json:"by"`
}

// Valid reports whether s is one of off, alert, pause, pause+kill.
func Valid(s string) bool {
	switch guard.Mode(s) {
	case guard.ModeOff, guard.ModeAlert, guard.ModePause, guard.ModePauseKill:
		return true
	}
	return false
}

// Parse validates a mode string.
func Parse(s string) (guard.Mode, error) {
	if !Valid(s) {
		return "", fmt.Errorf("unknown guard mode %q (want off, alert, pause or pause+kill)", s)
	}
	return guard.Mode(s), nil
}

// Write stores mode atomically (0600, in a 0700 directory we own, no
// symlinks). label says who asked; it is redacted and bounded.
func Write(dir string, mode guard.Mode, label string) error {
	if !Valid(string(mode)) {
		return fmt.Errorf("guardmode: invalid mode %q", mode)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	p := filepath.Join(dir, File)
	if li, err := os.Lstat(p); err == nil && li.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("guardmode: %s is a symlink", p)
	}
	label = redact.String(label)
	if len(label) > 80 {
		label = label[:80]
	}
	b, err := json.Marshal(Record{Mode: string(mode), SetAt: time.Now().UTC(), By: label})
	if err != nil {
		return err
	}
	return safeio.WriteFileAtomic(dir, File, b)
}

// ReadRecord returns the stored record, ok=false when the file is missing
// or unsafe (symlink, FIFO, not ours, wider than 0600, oversized, bad JSON
// or an invalid mode).
func ReadRecord(dir string) (Record, bool) {
	b, err := safeio.ReadFile(filepath.Join(dir, File), safeio.Opts{Max: maxBytes, RequireOwner: true, MaxPerm: 0o600})
	if err != nil {
		return Record{}, false
	}
	var r Record
	if err := safeio.DecodeJSON(b, &r); err != nil || !Valid(r.Mode) {
		return Record{}, false
	}
	return r, true
}

// Read returns the stored mode; ok=false means "use the configured default".
func Read(dir string) (guard.Mode, bool) {
	r, ok := ReadRecord(dir)
	if !ok {
		return "", false
	}
	return guard.Mode(r.Mode), true
}
