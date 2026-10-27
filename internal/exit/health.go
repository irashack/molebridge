package exit

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/irashack/molebridge/internal/applier"
	"github.com/irashack/molebridge/internal/bootclock"
	"github.com/irashack/molebridge/internal/jsonfile"
	"github.com/irashack/molebridge/internal/state"
)

// BootIDFile is where the kernel keeps the boot's id.
const BootIDFile = "/proc/sys/kernel/random/boot_id"

func readBootID() string {
	b, err := os.ReadFile(BootIDFile)
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(b))
}

// writeHeartbeat records, atomically, that an operational tick just passed:
// "molebridge-heartbeat 1 <boot id> <boot-clock nanoseconds>".
func writeHeartbeat(path string, now time.Duration) error {
	return replaceFile(path, []byte(fmt.Sprintf("molebridge-heartbeat 1 %s %d\n", readBootID(), int64(now))))
}

// replaceFile replaces path with data (mode 0644), creating its directory if
// needed. The data goes to a new temporary file in the same directory, which
// is renamed over path: a reader sees the old file or the new one, and
// nothing at a fixed name beside path (a symbolic link left there, say) is
// followed or written through. On an error the temporary file is removed.
// It does not sync: the heartbeats live in memory (the run directory).
func replaceFile(path string, data []byte) (err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(f.Name())
		}
	}()
	if err = f.Chmod(0o644); err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

// heartbeatMaxBytes bounds a heartbeat file: its one line is under 100
// bytes.
const heartbeatMaxBytes = 512

// readHeartbeat reads a heartbeat file the way the other state files are
// read (jsonfile.ReadBytes): a symbolic link, a file that is not regular (a
// FIFO is never opened for reading) or one past heartbeatMaxBytes is not
// read. The writers replace the file by rename and never follow a link; the
// readers don't either.
func readHeartbeat(path string) (string, bool) {
	b, ok := jsonfile.ReadBytes(path, heartbeatMaxBytes)
	return string(b), ok
}

// HeartbeatAge reads the heartbeat and returns its age on the boot clock. An
// absent or unreadable file, another boot's, a malformed one or one from the
// future is an error.
func HeartbeatAge(path string, clock bootclock.Clock) (time.Duration, error) {
	b, ok := readHeartbeat(path)
	if !ok {
		return 0, fmt.Errorf("no heartbeat yet")
	}
	f := strings.Fields(b)
	if len(f) != 4 || f[0] != "molebridge-heartbeat" || f[1] != "1" {
		return 0, fmt.Errorf("the heartbeat is unreadable")
	}
	if f[2] != readBootID() {
		return 0, fmt.Errorf("the heartbeat is from another boot")
	}
	ns, err := strconv.ParseInt(f[3], 10, 64)
	if err != nil || ns < 0 {
		return 0, fmt.Errorf("the heartbeat is unreadable")
	}
	age := clock() - time.Duration(ns)
	if age < 0 {
		return 0, fmt.Errorf("the heartbeat is from the future")
	}
	return age, nil
}

// MaxHeartbeatAge is how old the heartbeat may be for `molebridge health`:
// HealthAge (three ticks, 15 seconds) and never more than 30 seconds. The
// heartbeat is written every 5 seconds only while the operational checks pass,
// so two missed ticks still pass and three do not.
func MaxHeartbeatAge() time.Duration {
	if HealthAge > 30*time.Second {
		return 30 * time.Second
	}
	return HealthAge
}

// Healthy is `molebridge health`: the heartbeat is fresh on the boot clock.
func Healthy(path string, clock bootclock.Clock) (bool, string) {
	age, err := HeartbeatAge(path, clock)
	if err != nil {
		return false, err.Error()
	}
	if age > MaxHeartbeatAge() {
		return false, fmt.Sprintf("the last operational tick was %d seconds ago", int(age/time.Second))
	}
	return true, ""
}

// writeGuarded records, atomically, that a native sidecar's guards held just
// now, in this network namespace: "molebridge-guarded 1 <boot id> <netns>
// <boot-clock nanoseconds>". The namespace binds the evidence to the guards
// it is about: a file that outlived its namespace (a pod's emptyDir across a
// sandbox recreation) proves nothing about the new one. netNamespace names it
// by its cookie, which the kernel never reuses within a boot.
func writeGuarded(path string, now time.Duration) error {
	ns := netNamespace()
	if ns == "" {
		return fmt.Errorf("the network namespace can't be named")
	}
	return replaceFile(path, []byte(fmt.Sprintf("molebridge-guarded 1 %s %s %d\n", readBootID(), ns, int64(now))))
}

// Guarded is `molebridge health --guarded`: the guard heartbeat is from this
// boot and this network namespace, and fresh on the boot clock.
func Guarded(path string, clock bootclock.Clock) (bool, string) {
	b, ok := readHeartbeat(path)
	if !ok {
		return false, "no guard heartbeat yet"
	}
	f := strings.Fields(b)
	if len(f) != 5 || f[0] != "molebridge-guarded" || f[1] != "1" {
		return false, "the guard heartbeat is unreadable"
	}
	if f[2] != readBootID() {
		return false, "the guard heartbeat is from another boot"
	}
	if ns := netNamespace(); ns == "" || f[3] != ns {
		return false, "the guard heartbeat is from another network namespace"
	}
	at, err := strconv.ParseInt(f[4], 10, 64)
	if err != nil || at < 0 {
		return false, "the guard heartbeat is unreadable"
	}
	age := clock() - time.Duration(at)
	switch {
	case age < 0:
		return false, "the guard heartbeat is from the future"
	case age > MaxHeartbeatAge():
		return false, fmt.Sprintf("the guards were last seen in place %d seconds ago", int(age/time.Second))
	}
	return true, ""
}

// readResult reads the published status record, bounded and strictly.
//
//lint:ignore U1000 linux-only: called from worker_linux.go
func readResult(path string) (map[string]any, bool) {
	return state.ReadObject(path, applier.ResultMaxBytes)
}
