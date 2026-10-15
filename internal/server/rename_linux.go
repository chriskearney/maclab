package server

import "golang.org/x/sys/unix"

// renameNoReplace renames oldpath to newpath, failing if newpath exists.
func renameNoReplace(oldpath, newpath string) error {
	return unix.Renameat2(unix.AT_FDCWD, oldpath, unix.AT_FDCWD, newpath, unix.RENAME_NOREPLACE)
}
