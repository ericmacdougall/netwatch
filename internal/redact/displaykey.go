package redact

import (
	"path"
	"strings"
)

// DisplayKey turns a term key into text for notifications and events.
// Aggregate keys can hold an absolute exe path ("inel:exe:/home/<user>/
// bin/tool"); only its base name is shown, so no home path reaches a
// notification (AC-3, red-team F6).
func DisplayKey(key string) string {
	k := strings.TrimPrefix(key, "inel:")
	if rest, ok := strings.CutPrefix(k, "exe:"); ok {
		return path.Base(rest)
	}
	return k
}
