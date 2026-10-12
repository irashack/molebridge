package exit

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/irashack/molebridge/internal/bootclock"
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
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(fmt.Sprintf("molebridge-heartbeat 1 %s %d\n", readBootID(), int64(now))), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// HeartbeatAge reads the heartbeat and returns its age on the boot clock. An
// absent file, another boot's, a malformed one or one from the future is an
// error.
func HeartbeatAge(path string, clock bootclock.Clock) (time.Duration, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("no heartbeat yet")
	}
	f := strings.Fields(string(b))
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
