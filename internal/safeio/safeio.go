// Package safeio is the single hardened reader and writer for every
// untrusted or shared file netwatch touches: run_capped sidecars, jetsam
// .ips reports, hook WALs, transcripts, settings, config, guard state,
// mode and allowlist files. It never follows symlinks, never blocks on a
// FIFO or device, caps every read and rejects pathological JSON. The
// conformance corpus mirrors harness safe_input (#49) by copy.
package safeio

import "errors"

// Opts bounds one read.
type Opts struct {
	Max          int64  // maximum bytes; reading Max+1 is an error
	RequireOwner bool   // the file must belong to our uid
	MaxPerm      uint32 // if non-zero, mode&0777 must have no bits outside it
}

// Errors callers can test with errors.Is.
var (
	ErrTooLarge   = errors.New("safeio: file exceeds limit")
	ErrNotRegular = errors.New("safeio: not a regular file")
	ErrOwner      = errors.New("safeio: wrong owner")
	ErrPerm       = errors.New("safeio: permissions too open")
	ErrJSON       = errors.New("safeio: rejected JSON")
)

// MaxJSONDepth is the nesting limit for DecodeJSON.
const MaxJSONDepth = 64
