//go:build linux

package server

import "golang.org/x/sys/unix"

func dropArtifactCache(file artifactTemp) error {
	return unix.Fadvise(int(file.Fd()), 0, 0, unix.FADV_DONTNEED)
}
