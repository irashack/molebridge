//go:build linux || darwin

package panel

import (
	"os"
	"syscall"
)

// stRdonly is the read-only bit of statfs's flags: ST_RDONLY (MS_RDONLY) on
// Linux, which reports a read-only bind mount this way too, and MNT_RDONLY
// on macOS.
const stRdonly = 1

// readOnlyMount reports whether the file system holding dir is mounted
// read-only, by statfs.
func readOnlyMount(dir string) (bool, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return false, err
	}
	if !info.IsDir() {
		return false, errNotDirectory
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return false, err
	}
	return uint64(st.Flags)&stRdonly != 0, nil
}
