package exit

import (
	"errors"
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
// destroyed can be given its number (docs/native-sidecar.md#the-startup-gate).
func netNamespace() string { return nameNetNamespace(netnsCookie, os.Readlink) }

func netnsCookie() (uint64, error) {
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)
	return unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_NETNS_COOKIE)
}

// nameNetNamespace falls back to the inode number only where the kernel has
// no cookie (ENOPROTOOPT). Any other failure (a sandbox that denies the
// socket or the option) names nothing, so the heartbeat is neither written
// nor accepted: a reusable number must not stand in for the cookie on a
// kernel that has one.
func nameNetNamespace(cookie func() (uint64, error), readlink func(string) (string, error)) string {
	c, err := cookie()
	switch {
	case err == nil:
		return fmt.Sprintf("netns-cookie:%d", c)
	case !errors.Is(err, unix.ENOPROTOOPT):
		return ""
	}
	name, err := readlink("/proc/self/ns/net")
	if err != nil {
		return ""
	}
	return name
}
