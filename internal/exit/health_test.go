package exit

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestHeartbeatFreshness(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "run", "heartbeat")
	now := 1000 * time.Second
	clock := func() time.Duration { return now }
	if ok, _ := Healthy(path, clock); ok {
		t.Fatal("no heartbeat is unhealthy")
	}
	if err := writeHeartbeat(path, now); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "linux" {
		t.Skip("the boot id comes from /proc")
	}
	if ok, why := Healthy(path, clock); !ok {
		t.Fatal(why)
	}
	now += MaxHeartbeatAge()
	if ok, why := Healthy(path, clock); !ok {
		t.Fatalf("exactly the maximum age is fresh: %s", why)
	}
	now += time.Second
	if ok, _ := Healthy(path, clock); ok {
		t.Fatal("older than the maximum is not")
	}
	if MaxHeartbeatAge() > 30*time.Second || MaxHeartbeatAge() != 3*TickInterval {
		t.Errorf("the maximum age is %v", MaxHeartbeatAge())
	}
	// A heartbeat from the future (another clock) or another boot is not fresh.
	if err := writeHeartbeat(path, now+time.Hour); err != nil {
		t.Fatal(err)
	}
	if ok, _ := Healthy(path, clock); ok {
		t.Fatal("future")
	}
	if err := os.WriteFile(path, []byte("molebridge-heartbeat 1 other-boot 5\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if ok, _ := Healthy(path, clock); ok {
		t.Fatal("another boot")
	}
	if err := os.WriteFile(path, []byte("garbage"), 0o644); err != nil {
		t.Fatal(err)
	}
	if ok, _ := Healthy(path, clock); ok {
		t.Fatal("garbage")
	}
}
