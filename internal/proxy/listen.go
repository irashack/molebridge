package proxy

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
)

// CheckListen refuses a listen address the proxy must not take: it must be an
// IP literal and a port from 1 to 65535, and the IP must be loopback or one
// of the addresses of iface (NetBird's interface), as addrs reports them
// (nil: the system's). Any other address, including the unspecified one, is
// refused, so the proxy is never offered on the host's other networks.
func CheckListen(address, iface string, addrs func(name string) ([]net.Addr, error)) error {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("proxy: listen address %q: %w", address, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("proxy: listen address %q: the port must be 1 to 65535", address)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" {
		return fmt.Errorf("proxy: listen address %q: the host must be an IP address", address)
	}
	ip = ip.Unmap()
	if ip.IsLoopback() {
		return nil
	}
	if iface == "" {
		return fmt.Errorf("proxy: listen address %q is not loopback, and no NetBird interface is configured", address)
	}
	if addrs == nil {
		addrs = systemAddrs
	}
	list, err := addrs(iface)
	if err != nil {
		return fmt.Errorf("proxy: the addresses of %s: %w", iface, err)
	}
	for _, a := range list {
		var candidate net.IP
		switch v := a.(type) {
		case *net.IPNet:
			candidate = v.IP
		case *net.IPAddr:
			candidate = v.IP
		}
		if c, ok := netip.AddrFromSlice(candidate); ok && c.Unmap() == ip {
			return nil
		}
	}
	return fmt.Errorf("proxy: listen address %q is neither loopback nor an address of %s", address, iface)
}

func systemAddrs(name string) ([]net.Addr, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	return ifi.Addrs()
}

// isIPLiteral reports whether host is an IPv4 or IPv6 address, without a zone.
func isIPLiteral(host string) bool {
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.Zone() == ""
}
