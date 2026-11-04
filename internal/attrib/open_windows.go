//go:build windows

package attrib

import "os"

func openNoFollow(p string) (*os.File, error) { return os.Open(p) }
