//go:build linux

package proc

import "golang.org/x/sys/unix"

// BecomeSubreaper makes this process the parent of every orphan below it, as
// PID 1 already is. It lets a supervisor that does not run as PID 1 (a test,
// or an engine without an init) still collect the processes its children leave
// behind and see their process groups empty.
func BecomeSubreaper() error {
	return unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)
}
