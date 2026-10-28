//go:build !linux

package server

// No portable cache-eviction syscall exists; synced file readback still runs.
func dropArtifactCache(artifactTemp) error { return nil }
