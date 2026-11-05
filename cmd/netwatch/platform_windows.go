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
		return nil, fmt.Errorf("%w for %s", errLockHeld, filepath.Dir(path))
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

// background hides and detaches the console when Windows created one just
// for us (started from a logon task or Run key rather than a terminal), so
// no empty window stays on screen. Unlike on Unix the priority is left at
// normal: Windows priority classes are strict, and a below-normal monitor
// was starved for tens of seconds on a busy machine, exactly when a
// runaway process makes monitoring matter.
func background() {
	var pids [4]uint32
	n, _, _ := procGetConsoleProcessList.Call(uintptr(unsafe.Pointer(&pids[0])), 4)
	if n == 1 {
		if hwnd, _, _ := procGetConsoleWindow.Call(); hwnd != 0 {
			_, _, _ = procShowWindow.Call(hwnd, 0) // SW_HIDE
		}
		_, _, _ = procFreeConsole.Call()
	}
}
