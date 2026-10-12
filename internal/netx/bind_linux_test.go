//go:build linux

package netx

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

// The socket options are read back from a connection made through the dialer
// hook. Binding to a device or marking a socket needs privileges on some
// kernels; the tests skip where the system refuses.
func dialWith(t *testing.T, iface string, mark uint32) (net.Conn, error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	dialer := &net.Dialer{Control: bindControl(iface, mark)}
	return dialer.DialContext(context.Background(), "tcp4", listener.Addr().String())
}

func TestBindToDeviceIsSetOnTheSocket(t *testing.T) {
	conn, err := dialWith(t, "lo", 0)
	if errors.Is(err, syscall.EPERM) {
		t.Skip("SO_BINDTODEVICE needs privileges here")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	raw, _ := conn.(*net.TCPConn).SyscallConn()
	var got string
	var errno syscall.Errno
	raw.Control(func(fd uintptr) {
		buf := make([]byte, 32)
		size := uint32(len(buf))
		_, _, errno = syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE,
			uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0)
		got = strings.TrimRight(string(buf[:size]), "\x00")
	})
	if errno != 0 || got != "lo" {
		t.Errorf("bound to %q (%v)", got, errno)
	}
}

func TestMarkIsSetOnTheSocket(t *testing.T) {
	conn, err := dialWith(t, "", 0x1bd0)
	if errors.Is(err, syscall.EPERM) {
		t.Skip("SO_MARK needs CAP_NET_ADMIN")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	raw, _ := conn.(*net.TCPConn).SyscallConn()
	var got int
	var getErr error
	raw.Control(func(fd uintptr) { got, getErr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK) })
	if getErr != nil || got != 0x1bd0 {
		t.Errorf("mark %#x (%v)", got, getErr)
	}
}

func TestNoBindingMeansNoHook(t *testing.T) {
	if bindControl("", 0) != nil {
		t.Error("a hook for nothing")
	}
}

func TestFetchBoundToAnInterfaceThatDoesNotExistFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer server.Close()
	if _, err := (Client{}).Fetch(context.Background(), Request{URL: server.URL, AllowHTTP: true, BindInterface: "nope0"}); !errors.Is(err, ErrTransport) {
		t.Errorf("%v", err)
	}
	response, err := Client{}.Fetch(context.Background(), Request{URL: server.URL, AllowHTTP: true, BindInterface: "lo"})
	if errors.Is(err, ErrTransport) {
		t.Skip("SO_BINDTODEVICE refused here")
	}
	if err != nil || string(response.Body) != "ok" {
		t.Errorf("%v %+v", err, response)
	}
}
