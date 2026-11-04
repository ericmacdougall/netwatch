//go:build windows

package execx

import (
	"os/exec"
	"syscall"
)

// createNoWindow keeps helper consoles (route, schtasks, powershell) from
// flashing on screen when netwatch runs from a logon task.
const createNoWindow = 0x08000000

func hide(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
}
