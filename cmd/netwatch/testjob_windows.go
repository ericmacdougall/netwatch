//go:build windows

package main

import (
	"errors"
	"os"
	"os/exec"
)

func startTestJob([]string, *os.File) (*exec.Cmd, error) {
	return nil, errors.New("--test-daemon is not supported on Windows")
}
