//go:build linux

package nstest

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vishvananda/netns"
)

var counter atomic.Int64

// NS is a named network namespace.
type NS struct {
	t    *testing.T
	Name string
	fd   *os.File
}

// New creates a namespace with loopback up and removes it when the test ends.
// It skips the test when the environment cannot create namespaces.
func New(t *testing.T, label string) *NS {
	t.Helper()
	// Unique across processes even if a pid is reused while a leaked namespace
	// of an earlier test binary still has the name.
	name := fmt.Sprintf("mb%d-%d-%s-%s", os.Getpid(), counter.Add(1), label, uniqueSuffix()[:4])
	h, err := newNamed(name)
	if err != nil {
		t.Skipf("cannot create a network namespace (run the drills in a privileged container): %v", err)
	}
	_ = h.Close()
	f, err := os.Open("/var/run/netns/" + name)
	if err != nil {
		_ = netns.DeleteNamed(name)
		t.Fatal(err)
	}
	ns := &NS{t: t, Name: name, fd: f}
	t.Cleanup(func() {
		_ = f.Close()
		_ = netns.DeleteNamed(name)
	})
	ns.IP("link", "set", "lo", "up")
	return ns
}

// newNamed is netns.NewNamed on one locked thread that goes back to its
// namespace afterwards. NewNamed unshares the calling thread into the new
// namespace and later bind-mounts the namespace of whatever thread it is then
// running on. Unlocked, the goroutine could move between the two, binding the
// name to another thread's namespace (the host's, or another rig's, which then
// had two names: the drills' "File exists" and "invalid gateway" flakes), and
// the thread it left behind served other goroutines from the new namespace.
func newNamed(name string) (netns.NsHandle, error) {
	runtime.LockOSThread()
	orig, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		return netns.None(), err
	}
	defer orig.Close()
	h, err := netns.NewNamed(name)
	if serr := netns.Set(orig); serr != nil {
		// The thread stays locked, so it ends with this goroutine instead
		// of serving others from the wrong namespace.
		if h.IsOpen() {
			_ = h.Close()
		}
		_ = netns.DeleteNamed(name)
		return netns.None(), fmt.Errorf("back to the original namespace: %w", serr)
	}
	runtime.UnlockOSThread()
	return h, err
}

// Fd is a file descriptor of the namespace for rtnl.Options.NetNS. It stays
// open until the test ends.
func (n *NS) Fd() int { return int(n.fd.Fd()) }

// IP runs `ip -n <ns> args...` and fails the test on error.
func (n *NS) IP(args ...string) string {
	n.t.Helper()
	out, err := n.TryIP(args...)
	if err != nil {
		n.t.Fatalf("ip -n %s %s: %v\n%s", n.Name, strings.Join(args, " "), err, out)
	}
	return out
}

// TryIP runs `ip -n <ns> args...` and returns the error.
func (n *NS) TryIP(args ...string) (string, error) {
	cmd := exec.Command("ip", append([]string{"-n", n.Name}, args...)...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// Exec runs a command inside the namespace.
func (n *NS) Exec(name string, args ...string) (string, error) {
	cmd := exec.Command("ip", append([]string{"netns", "exec", n.Name, name}, args...)...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// ExecInput runs a command inside the namespace with the given standard input.
func (n *NS) ExecInput(input, name string, args ...string) (string, error) {
	cmd := exec.Command("ip", append([]string{"netns", "exec", n.Name, name}, args...)...)
	cmd.Stdin = strings.NewReader(input)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// Start runs a long-lived command inside the namespace and stops it when the
// test ends.
func (n *NS) Start(name string, args ...string) *exec.Cmd {
	n.t.Helper()
	cmd := exec.Command("ip", append([]string{"netns", "exec", n.Name, name}, args...)...)
	if err := cmd.Start(); err != nil {
		n.t.Fatal(err)
	}
	n.t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	return cmd
}

// Do runs fn on a thread that is in the namespace. Sockets created inside fn
// belong to the namespace for good; the goroutines that use them afterwards
// may run anywhere.
func (n *NS) Do(fn func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	orig, err := netns.Get()
	if err != nil {
		return err
	}
	defer orig.Close()
	if err := netns.Set(netns.NsHandle(n.Fd())); err != nil {
		return err
	}
	defer func() { _ = netns.Set(orig) }()
	return fn()
}

// Sysctl sets a sysctl inside the namespace.
func (n *NS) Sysctl(kv ...string) {
	n.t.Helper()
	if out, err := n.Exec("sysctl", append([]string{"-qw"}, kv...)...); err != nil {
		n.t.Fatalf("sysctl %v: %v\n%s", kv, err, out)
	}
}

// Veth creates a veth pair, one end in n named a, the other in other named b.
//
// The pair is created under names no other test can use (the packages' drills
// run in parallel in one container, and interface names are the one thing
// they could contend for), and each end is renamed inside its own namespace,
// where a clash would be a bug of the test itself.
func (n *NS) Veth(a string, other *NS, b string) {
	n.t.Helper()
	var last string
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(50 * time.Millisecond)
		}
		u := uniqueSuffix()
		ta, tb := "va"+u, "vb"+u
		n.IP("link", "add", ta, "type", "veth", "peer", "name", tb, "netns", other.Name)
		failed, renamed := "", false
		for _, r := range []struct {
			ns       *NS
			from, to string
		}{{n, ta, a}, {other, tb, b}} {
			if out, err := r.ns.TryIP("link", "set", r.from, "name", r.to); err != nil {
				all, _ := r.ns.TryIP("-d", "link")
				failed = fmt.Sprintf("ip -n %s link set %s name %s: %v\n%s\nthe namespace holds:\n%s", r.ns.Name, r.from, r.to, err, out, all)
				break
			}
			renamed = r.ns == n // the first end has its final name
		}
		if failed == "" {
			return
		}
		// The rename of a fresh interface in a fresh namespace has failed with
		// "File exists" on a busy machine, once in several hundred runs, with
		// nothing of that name in the namespace. The pair is removed and made
		// again under new names, and what was seen is kept for the report.
		n.t.Logf("making the veth pair %s/%s failed (attempt %d), trying again:\n%s", a, b, attempt+1, failed)
		if renamed {
			_, _ = n.TryIP("link", "del", a)
		} else {
			_, _ = n.TryIP("link", "del", ta)
		}
		_, _ = other.TryIP("link", "del", tb)
		last = failed
	}
	n.t.Fatalf("making the veth pair %s/%s failed three times; the last:\n%s", a, b, last)
}

// uniqueSuffix is 10 hex digits, random per call, short enough for an
// interface name (IFNAMSIZ is 16 with the terminator).
func uniqueSuffix() string {
	var b [5]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%010x", counter.Add(1)+int64(os.Getpid())<<20)
	}
	return hex.EncodeToString(b[:])
}
