//go:build !windows

package attrib

import (
	"os"

	"golang.org/x/sys/unix"
)

// openNoFollow opens a file without following a final symlink or blocking
// on a FIFO.
func openNoFollow(p string) (*os.File, error) {
	fd, err := unix.Open(p, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), p), nil
}
