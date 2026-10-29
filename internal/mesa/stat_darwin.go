package mesa

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// statTimes is a file's modification and change times.
func statTimes(st *syscall.Stat_t) [2]syscall.Timespec {
	return [2]syscall.Timespec{st.Mtimespec, st.Ctimespec}
}

// openRegularData opens p for reading only if it is a regular file. macOS has
// no O_PATH, so it opens the path itself, never following a symlink and never
// blocking on a FIFO, and checks the opened file's type before any read. Only
// labd runs here, on files in its own data directory; the Mac side is Linux.
// held is the opened file's Stat.
func openRegularData(p string) (r *os.File, held os.FileInfo, err error) {
	r, err = os.OpenFile(p, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	a, err := r.Stat()
	if err != nil || !a.Mode().IsRegular() {
		r.Close()
		return nil, nil, errNonRegular
	}
	return r, a, nil
}
