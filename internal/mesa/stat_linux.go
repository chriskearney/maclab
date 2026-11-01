package mesa

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// statTimes is a file's modification and change times.
func statTimes(st *syscall.Stat_t) [2]syscall.Timespec { return [2]syscall.Timespec{st.Mtim, st.Ctim} }

// openRegularData opens p for reading only once it is known to be a regular
// file: O_PATH types it without opening a device or FIFO for data, and the
// exact held inode is then reopened through procfs. held is its Stat.
func openRegularData(p string) (r *os.File, held os.FileInfo, err error) {
	f, e := os.OpenFile(p, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, nil, e
	}
	defer f.Close()
	a, e := f.Stat()
	if e != nil || !a.Mode().IsRegular() {
		return nil, nil, errNonRegular
	}
	r, e = os.OpenFile(fmt.Sprintf("/proc/self/fd/%d", f.Fd()), os.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, nil, e
	}
	return r, a, nil
}
