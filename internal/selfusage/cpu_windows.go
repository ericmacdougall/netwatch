//go:build windows

package selfusage

import (
	"time"

	"golang.org/x/sys/windows"
)

func ft(f windows.Filetime) time.Duration {
	return time.Duration(uint64(f.HighDateTime)<<32|uint64(f.LowDateTime)) * 100
}

// CPUTime is user+kernel time of this process. Windows helpers are rare
// (notifications only) and not included.
func CPUTime() time.Duration {
	var c, e, k, u windows.Filetime
	if windows.GetProcessTimes(windows.CurrentProcess(), &c, &e, &k, &u) != nil {
		return 0
	}
	return ft(k) + ft(u)
}
