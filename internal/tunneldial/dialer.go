// Package tunneldial opens connections and resolves names through the tunnel
// interface only (docs/design/menu.md, "The tunnel dialer").
//
// A connection the exit's namespace opens itself follows the main table
// unless it is bound to the tunnel interface, so every socket the Dialer
// makes is bound to the interface with SO_BINDTODEVICE before it connects.
// A failed bind fails the dial: there is no unbound fallback. No capability
// is needed; since Linux 5.7 an unprivileged process may bind to a device.
//
// The Dialer takes address literals only. Names go through the Resolver,
// which sends its DNS queries through the same Dialer to one server, never
// the system resolver, /etc/hosts or a search list.
package tunneldial

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"time"
)

// DefaultTimeout is a Dialer's per-connection timeout when Timeout is zero.
const DefaultTimeout = 10 * time.Second

// Dialer opens connections bound to the tunnel interface.
type Dialer struct {
	Interface string        // the tunnel interface, from TUNNEL_INTERFACE
	Timeout   time.Duration // per connection, default 10s
}

// The dial refusals. They never carry the address.
var (
	ErrInterface = errors.New("tunneldial: invalid tunnel interface name")
	ErrNetwork   = errors.New("tunneldial: network must be tcp, tcp4, tcp6, udp, udp4 or udp6")
	ErrAddress   = errors.New("tunneldial: address must be an IP literal and a port")
	ErrBind      = errors.New("tunneldial: binding the socket to the tunnel interface failed")
)

// ValidInterfaceName reports whether name can be a Linux interface name: 1 to
// 15 bytes, not "." or "..", no '/', ':' or white space (the kernel's
// dev_valid_name, plus ':', which only alias labels use).
func ValidInterfaceName(name string) bool {
	if name == "" || len(name) > 15 || name == "." || name == ".." {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c <= ' ' || c >= 0x7f || c == '/' || c == ':' {
			return false
		}
	}
	return true
}

// parseLiteral splits address into an IP literal (no zone) and a port from 1
// to 65535.
func parseLiteral(address string) (netip.AddrPort, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return netip.AddrPort{}, ErrAddress
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" {
		return netip.AddrPort{}, ErrAddress
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return netip.AddrPort{}, ErrAddress
	}
	return netip.AddrPortFrom(ip.Unmap(), uint16(n)), nil
}

func validNetwork(network string) bool {
	switch network {
	case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6":
		return true
	}
	return false
}

// DialContext connects to address, an IP literal and port, with the socket
// bound to Interface before connect. It fails if the interface is missing,
// has been renamed, or the bind fails for any other reason.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if !ValidInterfaceName(d.Interface) {
		return nil, ErrInterface
	}
	if !validNetwork(network) {
		return nil, ErrNetwork
	}
	ap, err := parseLiteral(address)
	if err != nil {
		return nil, err
	}
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	iface := d.Interface
	nd := net.Dialer{
		Timeout: timeout,
		Control: func(_, _ string, c syscall.RawConn) error {
			var bindErr error
			if err := c.Control(func(fd uintptr) { bindErr = bindToDevice(fd, iface) }); err != nil {
				return fmt.Errorf("%w: %v", ErrBind, err)
			}
			if bindErr != nil {
				return fmt.Errorf("%w: %v", ErrBind, bindErr)
			}
			return nil
		},
	}
	return nd.DialContext(ctx, network, ap.String())
}
