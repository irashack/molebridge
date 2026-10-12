package exit

import (
	"os/signal"
	"syscall"
)

func signalIgnore() { signal.Ignore(syscall.SIGTERM, syscall.SIGINT) }
