//go:build drill && linux

package nft_test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/irashack/molebridge/internal/nstest"
)

// The Alpine drill image has no util-linux setpriv. Re-exec the test binary
// after clearing every capability set: exec leaves a single capability-free
// thread, so all threads the new Go runtime creates inherit empty sets too.
// Keep uid 0 because go test's temporary executable directory can be private.
// Mode "raw" keeps CAP_NET_RAW alone, as an application given NET_RAW for
// ping would have it (and as Docker's default capability set has it).
func TestSidecarCapabilityFreeSender(t *testing.T) {
	mode := os.Getenv("MOLEBRIDGE_NFT_SENDER")
	if mode == "" {
		return
	}
	if err := sidecarSenderMain(mode); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

func sidecarSenderMain(mode string) error {
	runtime.LockOSThread()
	if mode == "drop" || mode == "raw" {
		// What the exec'd sender keeps: nothing, or CAP_NET_RAW alone. uid 0
		// gets its bounding set on exec, and no_new_privs keeps it to what is
		// permitted here.
		var keep uint32
		if mode == "raw" {
			keep = 1 << unix.CAP_NET_RAW
		}
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			return err
		}
		for cap := uintptr(0); ; cap++ {
			if keep != 0 && cap == unix.CAP_NET_RAW {
				continue
			}
			if err := unix.Prctl(unix.PR_CAPBSET_DROP, cap, 0, 0, 0); err != nil {
				if err == unix.EINVAL { // past the kernel's last capability
					break
				}
				return err
			}
		}
		if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
			return err
		}
		hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
		var caps [2]unix.CapUserData
		caps[0] = unix.CapUserData{Effective: keep, Permitted: keep, Inheritable: keep}
		if err := unix.Capset(&hdr, &caps[0]); err != nil {
			return err
		}
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		if err := os.Setenv("MOLEBRIDGE_NFT_SENDER", "send"); err != nil {
			return err
		}
		if err := os.Setenv("MOLEBRIDGE_NFT_KEEP", fmt.Sprintf("%016x", keep)); err != nil {
			return err
		}
		return unix.Exec(exe, os.Args, os.Environ())
	}
	if mode != "send" {
		return fmt.Errorf("unknown sender mode %q", mode)
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return err
	}
	keep := os.Getenv("MOLEBRIDGE_NFT_KEEP")
	for _, name := range []string{"CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"} {
		want := keep
		if name == "CapAmb:" {
			want = "0000000000000000"
		}
		if !strings.Contains(string(status), name+"\t"+want+"\n") {
			return fmt.Errorf("sender capability set %s is not %s", name, want)
		}
	}
	addr := netip.MustParseAddr(os.Getenv("MOLEBRIDGE_NFT_DEST"))
	device := os.Getenv("MOLEBRIDGE_NFT_DEVICE")
	family := unix.AF_INET
	if addr.Is6() {
		family = unix.AF_INET6
	}
	fd, err := unix.Socket(family, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, device); err != nil {
		return fmt.Errorf("capability-free bind device: %w", err)
	}
	// The mark, if asked for: "ready marked" once it is set, "ready refused"
	// if the kernel refuses it to this sender's capabilities.
	ready := "ready"
	if v := os.Getenv("MOLEBRIDGE_NFT_MARK"); v != "" {
		var mark uint32
		if _, err := fmt.Sscanf(v, "%d", &mark); err != nil {
			return err
		}
		switch err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, int(mark)); {
		case err == nil:
			ready = "ready marked"
		case err == unix.EPERM:
			ready = "ready refused"
		default:
			return fmt.Errorf("set mark: %w", err)
		}
	}
	var dest unix.Sockaddr = &unix.SockaddrInet4{Port: 42345}
	if addr.Is4() {
		dest = &unix.SockaddrInet4{Addr: addr.As4(), Port: 42345}
	} else {
		iface, err := net.InterfaceByName(device)
		if err != nil {
			return err
		}
		dest = &unix.SockaddrInet6{Addr: addr.As16(), Port: 42345, ZoneId: uint32(iface.Index)}
	}
	commands := make(chan string)
	go func() {
		defer close(commands)
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			commands <- scanner.Text()
		}
	}()
	fmt.Println(ready)
	ticker := time.NewTicker(2 * time.Millisecond)
	defer ticker.Stop()
	sent, denied := 0, 0
	for {
		select {
		case command, ok := <-commands:
			if !ok {
				return nil
			}
			if command != "status" {
				return fmt.Errorf("unknown sender command %q", command)
			}
			fmt.Printf("sent %d denied %d\n", sent, denied)
		case <-ticker.C:
			err := unix.Sendto(fd, []byte("sidecar-drill"), 0, dest)
			if err == unix.EPERM {
				denied++
			} else if err != nil {
				return fmt.Errorf("capability-free send: %w", err)
			}
			sent++
		}
	}
}

type sidecarSender struct {
	in  io.WriteCloser
	out *bufio.Reader
}

func startSidecarSender(t *testing.T, ns *nstest.NS, device, dest string) *sidecarSender {
	t.Helper()
	s, ready := startSidecarSenderWith(t, ns, "drop", device, dest, 0)
	if ready != "ready" {
		t.Fatalf("sender readiness: %q", ready)
	}
	return s
}

// startSidecarSenderWith starts a sender with no capabilities (mode "drop")
// or CAP_NET_RAW alone ("raw"), which sets mark on its socket if it is not 0,
// and returns its readiness line: "ready", "ready marked" or "ready refused".
func startSidecarSenderWith(t *testing.T, ns *nstest.NS, mode, device, dest string, mark uint32) (*sidecarSender, string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// Not t.Context(): it is cancelled before the cleanup below waits.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	cmd := exec.CommandContext(ctx, "ip", "netns", "exec", ns.Name, exe, "-test.run=^TestSidecarCapabilityFreeSender$")
	cmd.Env = append(os.Environ(), "MOLEBRIDGE_NFT_SENDER="+mode, "MOLEBRIDGE_NFT_DEVICE="+device, "MOLEBRIDGE_NFT_DEST="+dest)
	if mark != 0 {
		cmd.Env = append(cmd.Env, fmt.Sprintf("MOLEBRIDGE_NFT_MARK=%d", mark))
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = in.Close()
		err := cmd.Wait()
		cancel()
		if err != nil {
			t.Errorf("sender: %v: %s", err, stderr.String())
		}
	})
	sender := &sidecarSender{in: in, out: bufio.NewReader(out)}
	ready, err := sender.out.ReadString('\n')
	if err != nil || !strings.HasPrefix(ready, "ready") {
		t.Fatalf("sender readiness: %q %v", ready, err)
	}
	return sender, strings.TrimSuffix(ready, "\n")
}

// Wait for actual send attempts, not just elapsed time, on a loaded runner.
func (s *sidecarSender) wait(t *testing.T, minimum int, dropped bool) int {
	t.Helper()
	for {
		if _, err := io.WriteString(s.in, "status\n"); err != nil {
			t.Fatal(err)
		}
		var sent, denied int
		if _, err := fmt.Fscanf(s.out, "sent %d denied %d\n", &sent, &denied); err != nil {
			t.Fatalf("sender status: %v", err)
		}
		if dropped && denied != sent || !dropped && denied != 0 {
			t.Fatalf("sender attempted %d, denied %d; dropped=%t", sent, denied, dropped)
		}
		if sent >= minimum {
			return sent
		}
		time.Sleep(20 * time.Millisecond)
	}
}
