//go:build windows

package safeio

import "os"

// Windows has no O_NOFOLLOW; reparse points are rejected by the regular-file
// check on the opened handle where the platform reports them.
const (
	readFlags   = os.O_RDONLY
	dirFlags    = os.O_RDONLY
	appendFlags = os.O_WRONLY | os.O_APPEND | os.O_CREATE
	tmpFlags    = os.O_WRONLY | os.O_CREATE | os.O_EXCL
)

func isSymlinkLoop(error) bool { return false }

// ownerUID is unsupported: RequireOwner fails closed on Windows.
func ownerUID(os.FileInfo) (uint32, bool) { return 0, false }

func syncDir(*os.File) error { return nil }
