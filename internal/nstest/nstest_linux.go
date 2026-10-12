//go:build linux

package nstest

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

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
	name := fmt.Sprintf("mb%d-%d-%s", os.Getpid(), counter.Add(1), label)
	h, err := netns.NewNamed(name)
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
func (n *NS) Veth(a string, other *NS, b string) {
	n.t.Helper()
	n.IP("link", "add", a, "type", "veth", "peer", "name", b, "netns", other.Name)
}
