//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// lockRun takes an exclusive, non-blocking lock so only one monitor writes
// to a log directory. Windows releases it when the process exits.
func lockRun(path string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	ol := new(windows.Overlapped)
	err = windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, ol)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("another netwatch is already running for %s", filepath.Dir(path))
	}
	return func() { f.Close() }, nil
}

var (
	kernel32                  = windows.NewLazySystemDLL("kernel32.dll")
	procGetConsoleProcessList = kernel32.NewProc("GetConsoleProcessList")
	procGetConsoleWindow      = kernel32.NewProc("GetConsoleWindow")
	procFreeConsole           = kernel32.NewProc("FreeConsole")
	user32                    = windows.NewLazySystemDLL("user32.dll")
	procShowWindow            = user32.NewProc("ShowWindow")
)

// background lowers our priority and, when Windows created a console just
// for us (started from a logon task or Run key rather than a terminal),
// hides and detaches it so no empty window stays on screen.
func background() {
	_ = windows.SetPriorityClass(windows.CurrentProcess(), windows.BELOW_NORMAL_PRIORITY_CLASS)
	var pids [4]uint32
	n, _, _ := procGetConsoleProcessList.Call(uintptr(unsafe.Pointer(&pids[0])), 4)
	if n == 1 {
		if hwnd, _, _ := procGetConsoleWindow.Call(); hwnd != 0 {
			_, _, _ = procShowWindow.Call(hwnd, 0) // SW_HIDE
		}
		_, _, _ = procFreeConsole.Call()
	}
}
