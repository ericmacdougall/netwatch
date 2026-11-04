// Package tracker keeps 60s footprint rings for agent groups, ineligible
// aggregates and "unattributed", using PGRP_ONLY listings for the top 16
// groups (at most 64 members each) with preallocated buffers.
package tracker

// Window is the ring length in seconds.
const Window = 60

// Limits on one poll.
const (
	MaxGroups  = 16
	MaxMembers = 64
)
