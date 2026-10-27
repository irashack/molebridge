package main

import (
	"fmt"
	"io"
	"os"
)

// version is the release this binary was built as. The Dockerfile sets it
// from its VERSION build argument with -ldflags -X; the release workflow
// passes the candidate tag (a promoted release keeps the candidate's build,
// so it reports the candidate tag it was built as). A build without the flag,
// such as `go run`, says dev.
var version = "dev"

func init() {
	register("version", "print the release this binary was built as",
		func(args []string) int { return versionMain(args, os.Stdout, os.Stderr) })
}

func versionMain(args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: molebridge version")
		return 2
	}
	fmt.Fprintf(stdout, "molebridge %s\n", version)
	return 0
}
