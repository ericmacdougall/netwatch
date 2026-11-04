//go:build unix

package selfusage

import (
	"syscall"
	"time"
)

func tv(t syscall.Timeval) time.Duration {
	return time.Duration(t.Sec)*time.Second + time.Duration(t.Usec)*time.Microsecond
}

// CPUTime is user+system time of this process plus its reaped children.
func CPUTime() time.Duration {
	var self, kids syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &self)
	_ = syscall.Getrusage(syscall.RUSAGE_CHILDREN, &kids)
	return tv(self.Utime) + tv(self.Stime) + tv(kids.Utime) + tv(kids.Stime)
}
