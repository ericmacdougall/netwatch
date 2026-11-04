// Package eventlog appends JSON records to size-rotated JSONL files and
// reads them back for reports.
//
// Files are created 0600 inside a 0700 directory because records contain
// process names and (redacted) command lines.
package eventlog

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// TimeFormat is the timestamp layout written to records (RFC 3339 with the
// local offset, second precision).
const TimeFormat = time.RFC3339

// legacyFormat is the prototype's offset-less local timestamp, still accepted
// when reading old logs.
const legacyFormat = "2006-01-02T15:04:05"

// Writer appends records to one file, rotating it to "<path>.1" once it
// exceeds MaxBytes. Only one previous generation is kept, which bounds disk
// use to about twice MaxBytes per file.
type Writer struct {
	Path     string
	MaxBytes int64

	mu sync.Mutex
}

// NewWriter returns a Writer for path.
func NewWriter(path string, maxBytes int64) *Writer {
	return &Writer{Path: path, MaxBytes: maxBytes}
}

// Append writes rec as one JSON line.
func (w *Writer) Append(rec any) error {
	line, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("encode record: %w", err)
	}
	line = append(line, '\n')
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(w.Path), 0o700); err != nil {
		return err
	}
	if err := w.rotateIfNeeded(); err != nil {
		return err
	}
	f, err := os.OpenFile(w.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(line)
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	return cerr
}

func (w *Writer) rotateIfNeeded() error {
	st, err := os.Stat(w.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if st.Size() <= w.MaxBytes {
		return nil
	}
	// os.Rename replaces the old generation atomically on Unix and, via
	// MoveFileEx, on Windows.
	return os.Rename(w.Path, w.Path+".1")
}

// ParseTime parses a record timestamp in the current or legacy format.
func ParseTime(s string) (time.Time, bool) {
	if t, err := time.Parse(TimeFormat, s); err == nil {
		return t, true
	}
	if t, err := time.ParseInLocation(legacyFormat, s, time.Local); err == nil {
		return t, true
	}
	return time.Time{}, false
}

// maxLine bounds one record; longer lines are skipped rather than failing.
const maxLine = 4 << 20

// ReadSince decodes records at or after cutoff from the rotated generation
// and the current file, oldest first. Malformed lines and lines without a
// readable "ts" are skipped so a torn write never breaks a report.
func ReadSince[T any](path string, cutoff time.Time, ts func(T) string) ([]T, error) {
	var out []T
	for _, p := range []string{path + ".1", path} {
		f, err := os.Open(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return out, err
		}
		err = scan(f, func(line []byte) {
			var rec T
			if json.Unmarshal(line, &rec) != nil {
				return
			}
			t, ok := ParseTime(ts(rec))
			if ok && !t.Before(cutoff) {
				out = append(out, rec)
			}
		})
		f.Close()
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

func scan(r io.Reader, fn func([]byte)) error {
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		line, err := br.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			// Overlong line: skip to its end.
			for errors.Is(err, bufio.ErrBufferFull) {
				_, err = br.ReadSlice('\n')
			}
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
			continue
		}
		if len(line) > 0 && len(line) <= maxLine {
			fn(line)
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}
