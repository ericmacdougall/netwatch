//go:build !darwin

package resmon

import (
	"context"

	"github.com/ericmacdougall/netwatch/internal/resources"
)

// NewWatcher returns nil: only darwin has a fork watcher. Without one no
// group reaches the tool tier, which is why linux defaults to alert mode.
func NewWatcher(context.Context, resources.Full, func(string, error)) Watcher { return nil }
