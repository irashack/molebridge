package exit

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// NetNamespace is netNamespace, for tests outside the package.
func NetNamespace() string { return netNamespace() }

// netNamespace names the caller's network namespace for the guard heartbeat,
// or "" when it can't be named. The kernel's namespace cookie (5.14 and
// later) is unique within a boot. The inode number in /proc/self/ns/net, the
// fallback on older kernels, is not: a namespace created after another was
// destroyed can be given its number (docs/native-sidecar.md#kubernetes).
func netNamespace() string {
	if fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0); err == nil {
		cookie, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_NETNS_COOKIE)
		_ = unix.Close(fd)
		if err == nil {
			return fmt.Sprintf("netns-cookie:%d", cookie)
		}
	}
	name, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return ""
	}
	return name
}
