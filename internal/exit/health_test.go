package exit

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
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

// The heartbeats are written through a temporary file of their own: a link
// left at the old fixed name (path + ".tmp") is not followed, the file is
// replaced whole with mode 0644, and no temporary file stays behind.
func TestHeartbeatWritesFollowNoLinkAndLeaveNothingBehind(t *testing.T) {
	writers := map[string]func(string, time.Duration) error{"heartbeat": writeHeartbeat, "guarded": writeGuarded}
	for name, write := range writers {
		t.Run(name, func(t *testing.T) {
			if name == "guarded" && netNamespace() == "" {
				t.Skip("the network namespace can't be named here")
			}
			dir := t.TempDir()
			path := filepath.Join(dir, "run", name)
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			victim := filepath.Join(dir, "victim")
			if err := os.WriteFile(victim, []byte("untouched\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(victim, path+".tmp"); err != nil {
				t.Fatal(err)
			}
			for i := 1; i <= 3; i++ {
				if err := write(path, time.Duration(i)*time.Second); err != nil {
					t.Fatal(err)
				}
			}
			if b, err := os.ReadFile(victim); err != nil || string(b) != "untouched\n" {
				t.Fatalf("the link's target was written: %q %v", b, err)
			}
			fi, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o644 {
				t.Errorf("mode %v", fi.Mode())
			}
			if b, err := os.ReadFile(path); err != nil || !strings.HasPrefix(string(b), "molebridge-") || !strings.HasSuffix(string(b), " 3000000000\n") {
				t.Errorf("content %q %v", b, err)
			}
			if names := dirNames(t, filepath.Dir(path)); len(names) != 2 {
				t.Errorf("the directory holds %v, want only %s and the link", names, name)
			}
		})
	}
}

// A heartbeat that cannot be put in place leaves no temporary file behind
// and the old heartbeat as it was.
func TestAFailedHeartbeatWriteLeavesNothingBehind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "heartbeat")
	if err := writeHeartbeat(path, time.Second); err != nil {
		t.Fatal(err)
	}
	// A non-empty directory where the file should be: the rename fails.
	blocked := filepath.Join(dir, "blocked")
	if err := os.MkdirAll(filepath.Join(blocked, "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeHeartbeat(blocked, 2*time.Second); err == nil {
		t.Fatal("a heartbeat over a non-empty directory was written")
	}
	if names := dirNames(t, dir); len(names) != 2 {
		t.Errorf("the directory holds %v", names)
	}
	if b, err := os.ReadFile(path); err != nil || !strings.HasSuffix(string(b), " 1000000000\n") {
		t.Errorf("the old heartbeat changed: %q %v", b, err)
	}
}

func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// The heartbeat readers read as the writers write: a symbolic link, a file
// that is not regular (a FIFO, which would otherwise block the reader) or an
// oversized file is no heartbeat, however fresh what it points at.
func TestHeartbeatReadersFollowNoLinkAndReadBounded(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the boot id comes from /proc")
	}
	now := 1000 * time.Second
	clock := func() time.Duration { return now }
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := writeHeartbeat(real, now); err != nil {
		t.Fatal(err)
	}
	if ok, why := Healthy(real, clock); !ok {
		t.Fatal(why)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Fatal(err)
	}
	large := filepath.Join(dir, "large")
	content, err := os.ReadFile(real)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(large, append(content, bytes.Repeat([]byte(" "), heartbeatMaxBytes)...), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{link, fifo, large} {
		if ok, why := Healthy(path, clock); ok || why != "no heartbeat yet" {
			t.Errorf("%s: %v %q", filepath.Base(path), ok, why)
		}
		if ok, why := Guarded(path, clock); ok || why != "no guard heartbeat yet" {
			t.Errorf("guarded %s: %v %q", filepath.Base(path), ok, why)
		}
	}
}
