//go:build !linux

package applier

import (
	"os"
	"syscall"
)

// statIdentity is the file's inode and its modification and change times in
// nanoseconds: what identifies a credential file without reading it.
func statIdentity(info os.FileInfo) (ino uint64, mtime, ctime int64) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, info.ModTime().UnixNano(), 0
	}
	return uint64(st.Ino), st.Mtimespec.Nano(), st.Ctimespec.Nano()
}
