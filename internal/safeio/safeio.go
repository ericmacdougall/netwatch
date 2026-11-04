// Package safeio is the single hardened reader and writer for every
// untrusted or shared file netwatch touches: run_capped sidecars, jetsam
// .ips reports, hook WALs, transcripts, settings, config, guard state,
// mode and allowlist files. It never follows symlinks, never blocks on a
// FIFO or device, caps every read and rejects pathological JSON. The
// conformance corpus mirrors harness safe_input (#49) by copy.
package safeio

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// Opts bounds one read.
type Opts struct {
	Max          int64  // maximum bytes; reading Max+1 is an error
	RequireOwner bool   // the file must belong to our uid
	MaxPerm      uint32 // if non-zero, mode&0777 must have no bits outside it
}

// Errors callers can test with errors.Is.
var (
	ErrTooLarge   = errors.New("safeio: file exceeds limit")
	ErrNotRegular = errors.New("safeio: not a regular file")
	ErrOwner      = errors.New("safeio: wrong owner")
	ErrPerm       = errors.New("safeio: permissions too open")
	ErrJSON       = errors.New("safeio: rejected JSON")
)

// MaxJSONDepth is the nesting limit for DecodeJSON.
const MaxJSONDepth = 64

// selfUID is a variable so tests can simulate a foreign owner without root.
var selfUID = os.Getuid

// openRegular opens path without following a final symlink or blocking on
// a FIFO, then validates the descriptor itself (not the path) so there is no
// check-then-use race. The caller closes the file.
func openRegular(path string, o Opts) (*os.File, os.FileInfo, error) {
	f, err := os.OpenFile(path, readFlags, 0)
	if err != nil {
		if isSymlinkLoop(err) {
			return nil, nil, fmt.Errorf("%w: %s is a symlink", ErrNotRegular, path)
		}
		return nil, nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, nil, fmt.Errorf("%w: %s", ErrNotRegular, path)
	}
	if err := checkOwnerPerm(fi, o); err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("%w: %s", err, path)
	}
	return f, fi, nil
}

func checkOwnerPerm(fi os.FileInfo, o Opts) error {
	if o.RequireOwner {
		uid, ok := ownerUID(fi)
		if !ok || uid != uint32(selfUID()) {
			return ErrOwner
		}
	}
	if o.MaxPerm != 0 && uint32(fi.Mode().Perm())&^o.MaxPerm != 0 {
		return ErrPerm
	}
	return nil
}

// ReadFile reads a regular file of at most o.Max bytes. Max <= 0 is an
// error: every caller must choose a cap.
func ReadFile(path string, o Opts) ([]byte, error) {
	if o.Max <= 0 {
		return nil, fmt.Errorf("safeio: no read cap for %s", path)
	}
	f, fi, err := openRegular(path, o)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// The stat size is advisory (procfs reports 0, files can grow), so the
	// LimitReader is what actually enforces the cap.
	if fi.Size() > o.Max {
		return nil, fmt.Errorf("%w: %s", ErrTooLarge, path)
	}
	b, err := io.ReadAll(io.LimitReader(f, o.Max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > o.Max {
		return nil, fmt.Errorf("%w: %s", ErrTooLarge, path)
	}
	return b, nil
}

// TailLines returns up to n of the last complete lines of a regular file,
// oldest first, looking at no more than the last o.Max bytes. Lines longer
// than maxLine bytes are dropped rather than failing the read, and a first
// line cut by the window is dropped as partial. An unterminated final line
// is kept (a writer may have been killed mid-line; callers tolerate junk).
func TailLines(path string, n, maxLine int, o Opts) ([][]byte, error) {
	if o.Max <= 0 || n <= 0 || maxLine <= 0 {
		return nil, fmt.Errorf("safeio: invalid tail bounds for %s", path)
	}
	f, fi, err := openRegular(path, o)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	start := fi.Size() - o.Max
	if start < 0 {
		start = 0
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(f, o.Max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > o.Max { // grew while reading: keep the newest bytes
		b = b[int64(len(b))-o.Max:]
		start++
	}
	var lines [][]byte
	first := start > 0
	for len(b) > 0 {
		i := indexByte(b, '\n')
		var line []byte
		if i < 0 {
			line, b = b, nil
		} else {
			line, b = b[:i], b[i+1:]
		}
		if first { // possibly a fragment of a longer line
			first = false
			continue
		}
		if len(line) == 0 || len(line) > maxLine {
			continue
		}
		lines = append(lines, line)
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines, nil
}

func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}
