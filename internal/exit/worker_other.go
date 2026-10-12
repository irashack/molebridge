//go:build !linux

package exit

import (
	"fmt"
	"io"
)

// RunWorker is Linux only: the exit manages a network namespace.
func RunWorker(environ []string, stderr io.Writer) int {
	fmt.Fprintln(stderr, prefix+"the exit worker runs on Linux only")
	return 1
}

// RunCleanup is Linux only.
func RunCleanup(args []string, env map[string]string, stderr io.Writer) int {
	fmt.Fprintln(stderr, prefix+"the exit cleanup runs on Linux only")
	return 1
}
