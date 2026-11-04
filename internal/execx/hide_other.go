//go:build !windows

package execx

import "os/exec"

func hide(*exec.Cmd) {}
