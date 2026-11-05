package safeio

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// openPrivateDir opens dir and checks, on the descriptor, that it is a
// directory we own with no group or other access. A shared or foreign
// directory would let another user plant or swap files.
func openPrivateDir(dir string) (*os.File, error) {
	d, err := os.OpenFile(dir, dirFlags, 0)
	if err != nil {
		if isSymlinkLoop(err) {
			return nil, fmt.Errorf("%w: %s is a symlink", ErrNotRegular, dir)
		}
		return nil, err
	}
	fi, err := d.Stat()
	if err != nil {
		d.Close()
		return nil, err
	}
	if !fi.IsDir() {
		d.Close()
		return nil, fmt.Errorf("%w: %s is not a directory", ErrNotRegular, dir)
	}
	if err := checkOwnerPerm(d, fi, Opts{RequireOwner: true, MaxPerm: 0o700}); err != nil {
		d.Close()
		return nil, fmt.Errorf("%w: %s", err, dir)
	}
	return d, nil
}

func validName(name string) bool {
	return name != "" && name != "." && name != ".." &&
		!strings.ContainsAny(name, `/\`+"\x00")
}

// WriteFileAtomic replaces dir/name with data. The temp file is created
// O_EXCL|O_NOFOLLOW with mode 0600 inside a 0700 directory we own, then
// fsynced, renamed over the target and the directory fsynced, so a crash
// leaves either the old or the new file and an attacker cannot redirect the
// write through a planted symlink.
func WriteFileAtomic(dir, name string, data []byte) (err error) {
	if !validName(name) {
		return fmt.Errorf("safeio: bad file name %q", name)
	}
	d, err := openPrivateDir(dir)
	if err != nil {
		return err
	}
	defer d.Close()

	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	tmp := filepath.Join(dir, "."+name+".tmp-"+hex.EncodeToString(rnd[:]))
	f, err := os.OpenFile(tmp, tmpFlags, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Chmod(0o600); err != nil { // umask cannot widen, but be explicit
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		return err
	}
	return syncDir(d)
}

// OpenAppend opens an append-only log without following a symlink and
// verifies the opened file is a regular file owned by us. Created files are
// 0600. The caller closes it.
func OpenAppend(path string) (*os.File, error) {
	f, err := os.OpenFile(path, appendFlags, 0o600)
	if err != nil {
		if isSymlinkLoop(err) {
			return nil, fmt.Errorf("%w: %s is a symlink", ErrNotRegular, path)
		}
		return nil, err
	}
	fi, err := f.Stat()
	if err == nil && !fi.Mode().IsRegular() {
		err = fmt.Errorf("%w: %s", ErrNotRegular, path)
	}
	if err == nil {
		if e := checkOwnerPerm(f, fi, Opts{RequireOwner: true}); e != nil {
			err = fmt.Errorf("%w: %s", e, path)
		}
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
