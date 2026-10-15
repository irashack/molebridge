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
	if mode == "drop" {
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			return err
		}
		for cap := uintptr(0); ; cap++ {
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
		return unix.Exec(exe, os.Args, os.Environ())
	}
	if mode != "send" {
		return fmt.Errorf("unknown sender mode %q", mode)
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return err
	}
	for _, name := range []string{"CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"} {
		if !strings.Contains(string(status), name+"\t0000000000000000\n") {
			return fmt.Errorf("sender capability set %s is not empty", name)
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
	fmt.Println("ready")
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
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	cmd := exec.CommandContext(ctx, "ip", "netns", "exec", ns.Name, exe, "-test.run=^TestSidecarCapabilityFreeSender$")
	cmd.Env = append(os.Environ(), "MOLEBRIDGE_NFT_SENDER=drop", "MOLEBRIDGE_NFT_DEVICE="+device, "MOLEBRIDGE_NFT_DEST="+dest)
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
	if ready, err := sender.out.ReadString('\n'); err != nil || ready != "ready\n" {
		t.Fatalf("sender readiness: %q %v", ready, err)
	}
	return sender
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
