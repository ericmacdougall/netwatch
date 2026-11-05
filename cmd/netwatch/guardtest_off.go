//go:build !guardtest

package main

import (
	"errors"

	"github.com/ericmacdougall/netwatch/internal/resources"
)

// guardtestBuild is false in every release build: no danger injection and
// no --test-tier kill.
const guardtestBuild = false

func testReader(r resources.Full, _ string) resources.Full { return r }

func (a *app) guardSimulate(string, []string) error {
	return usageError{errors.New(`unknown guard subcommand "simulate"`)}
}
