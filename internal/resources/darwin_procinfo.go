//go:build darwin

package resources

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// Raw proc_info(2) interface. libproc's proc_listpids, proc_pidinfo and
// proc_pid_rusage are thin wrappers over SYS_PROC_INFO (336), so calling
// the syscall directly works with CGO_ENABLED=0. The prototype is
//
//	int proc_info(int callnum, int pid, int flavor, uint64_t arg,
//	              user_addr_t buffer, int buffersize)
//
// (xnu bsd/sys/proc_info.h). proc_listpids passes its type as the second
// argument and its typeinfo as the third; the layout below follows that.

const (
	piListPIDs  = 1 // PROC_INFO_CALL_LISTPIDS
	piPIDInfo   = 2 // PROC_INFO_CALL_PIDINFO
	piPIDRusage = 9 // PROC_INFO_CALL_PIDRUSAGE

	listPGRPOnly = 2 // PROC_PGRP_ONLY
	listPPIDOnly = 6 // PROC_PPID_ONLY

	flavTaskInfo  = 4  // PROC_PIDTASKINFO
	flavVnodePath = 9  // PROC_PIDVNODEPATHINFO
	flavPIDPath   = 11 // PROC_PIDPATHINFO

	rusageV2 = 2 // RUSAGE_INFO_V2

	maxPathLen = 1024 // MAXPATHLEN
)

// procTaskInfo mirrors struct proc_taskinfo (sys/proc_info.h), 96 bytes.
// Times are in mach absolute time units, not nanoseconds.
type procTaskInfo struct {
	VirtualSize      uint64 // 0
	ResidentSize     uint64 // 8
	TotalUser        uint64 // 16
	TotalSystem      uint64 // 24
	ThreadsUser      uint64 // 32
	ThreadsSystem    uint64 // 40
	Policy           int32  // 48
	Faults           int32  // 52
	Pageins          int32  // 56
	CowFaults        int32  // 60
	MessagesSent     int32  // 64
	MessagesReceived int32  // 68
	SyscallsMach     int32  // 72
	SyscallsUnix     int32  // 76
	Csw              int32  // 80
	Threadnum        int32  // 84
	Numrunning       int32  // 88
	Priority         int32  // 92
}

// Offsets and sizes below were checked against the macOS SDK headers with
// offsetof/sizeof (taskinfo 96, rusage_v2 160 with ri_phys_footprint at 72,
// vnodepathinfo 2352 with the cwd path at 152).
//
// rusageInfoV2 mirrors struct rusage_info_v2 (sys/resource.h), 160 bytes.
// ri_phys_footprint (offset 72) is the number Activity Monitor shows as
// Memory: it counts compressed and swapped pages at their logical size.
type rusageInfoV2 struct {
	UUID            [16]byte // 0
	UserTime        uint64   // 16 (mach absolute time)
	SystemTime      uint64   // 24
	PkgIdleWkups    uint64   // 32
	InterruptWkups  uint64   // 40
	Pageins         uint64   // 48
	WiredSize       uint64   // 56
	ResidentSize    uint64   // 64
	PhysFootprint   uint64   // 72
	ProcStartAbs    uint64   // 80
	ProcExitAbs     uint64   // 88
	ChildUserTime   uint64   // 96
	ChildSystemTime uint64   // 104
	ChildPkgIdle    uint64   // 112
	ChildInterrupt  uint64   // 120
	ChildPageins    uint64   // 128
	ChildElapsedAbs uint64   // 136
	DiskBytesRead   uint64   // 144
	DiskBytesWrit   uint64   // 152
}

// vnodePathInfo is struct proc_vnodepathinfo: two struct vnode_info_path
// (cwd, root). Each is a struct vnode_info (struct vinfo_stat 136 bytes,
// int vi_type, int vi_pad, fsid_t vi_fsid 8 bytes = 152) followed by
// char vip_path[MAXPATHLEN]. So the cwd path starts at offset 152 and the
// whole struct is 2*(152+1024) = 2352 bytes.
type vnodePathInfo struct {
	_    [152]byte
	Path [maxPathLen]byte // 152
	_    [152 + maxPathLen]byte
}

const (
	sizeTaskInfo = 96
	sizeRusageV2 = 160
	sizeVnode    = 2352
)

// Compile-time layout checks.
var (
	_ [sizeTaskInfo - unsafe.Sizeof(procTaskInfo{})]struct{}
	_ [unsafe.Sizeof(procTaskInfo{}) - sizeTaskInfo]struct{}
	_ [sizeRusageV2 - unsafe.Sizeof(rusageInfoV2{})]struct{}
	_ [unsafe.Sizeof(rusageInfoV2{}) - sizeRusageV2]struct{}
	_ [sizeVnode - unsafe.Sizeof(vnodePathInfo{})]struct{}
	_ [unsafe.Sizeof(vnodePathInfo{}) - sizeVnode]struct{}
	_ [72 - unsafe.Offsetof(rusageInfoV2{}.PhysFootprint)]struct{}
	_ [unsafe.Offsetof(rusageInfoV2{}.PhysFootprint) - 72]struct{}
	_ [8 - unsafe.Offsetof(procTaskInfo{}.ResidentSize)]struct{}
	_ [unsafe.Offsetof(procTaskInfo{}.ResidentSize) - 8]struct{}
)

// procInfo issues proc_info and returns the byte count.
func procInfo(call, pid, flavor int, arg uint64, buf unsafe.Pointer, size int) (int, error) {
	r, _, e := unix.Syscall6(unix.SYS_PROC_INFO, uintptr(call), uintptr(pid), uintptr(flavor),
		uintptr(arg), uintptr(buf), uintptr(size))
	if e != 0 {
		return 0, e
	}
	return int(r), nil
}

// listPIDs fills dst (pids as int32) for a PGRP_ONLY or PPID_ONLY listing
// and returns how many bytes the kernel wrote.
func listPIDs(typ, arg int, dst []int32) (int, error) {
	if len(dst) == 0 {
		return 0, nil
	}
	return procInfo(piListPIDs, typ, arg, 0, unsafe.Pointer(&dst[0]), len(dst)*4)
}

func taskInfo(pid int, ti *procTaskInfo) error {
	n, err := procInfo(piPIDInfo, pid, flavTaskInfo, 0, unsafe.Pointer(ti), sizeTaskInfo)
	if err != nil {
		return err
	}
	if n < sizeTaskInfo {
		return unix.EIO
	}
	return nil
}

func rusage(pid int, ru *rusageInfoV2) error {
	n, err := procInfo(piPIDRusage, pid, rusageV2, 0, unsafe.Pointer(ru), sizeRusageV2)
	if err != nil {
		return err
	}
	_ = n // pid_rusage returns 0 on success
	return nil
}

func pidPath(pid int) string {
	var b [4 * maxPathLen]byte
	// The kernel returns 0 on success and fills the buffer with a C string.
	if _, err := procInfo(piPIDInfo, pid, flavPIDPath, 0, unsafe.Pointer(&b[0]), len(b)); err != nil {
		return ""
	}
	return cstr(b[:])
}

func vnodeCwd(pid int) string {
	var v vnodePathInfo
	n, err := procInfo(piPIDInfo, pid, flavVnodePath, 0, unsafe.Pointer(&v), sizeVnode)
	if err != nil || n < sizeVnode {
		return ""
	}
	return cstr(v.Path[:])
}

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
