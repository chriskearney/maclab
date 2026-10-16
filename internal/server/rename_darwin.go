package server

import "golang.org/x/sys/unix"

// renameNoReplace renames oldpath to newpath, failing if newpath exists.
func renameNoReplace(oldpath, newpath string) error {
	return unix.RenamexNp(oldpath, newpath, unix.RENAME_EXCL)
}
