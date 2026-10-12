// Package egress is tunnel-verified egress: the "tunnel" tier of egress
// confirmation (molebridge/egress.py).
//
// A provider with its own typed egress endpoint (Mullvad's am.i.mullvad.net,
// PIA's status call, NordVPN's insights) confirms egress at the "provider"
// tier. A provider without one can reach only the "tunnel" tier, and only when
// every one of these holds, per address family the tunnel carries:
//
//   - the handshake is fresh;
//   - two independent IP echo services, asked through the tunnel interface,
//     answer with the same public address;
//   - that address is not the host's own public address, measured off the
//     tunnel. A failed measurement fails the check, with one exception: IPv6 on
//     a namespace with independent evidence that it has no IPv6 of its own (no
//     IPv6 route in any table but the tunnel's, the overlay's, refusing,
//     link-local, multicast and loopback ones, and no global IPv6 address on any
//     interface but the tunnel and the overlay, loopback included). Such a host
//     has no IPv6 address to confuse with the tunnel's;
//   - where the catalogue lists exit addresses for the selected server (an
//     "exit_ips" list in its entry), the address is one of them.
//
// The applier runs the requests; this package only judges the answers. Echo
// answers are untrusted input. It offers EchoURLs, ParseEcho, ExitAddresses,
// HostLacksIPv6 and TunnelVerdict.
package egress

import (
	"errors"
	"net/netip"
	"strconv"
	"strings"

	"github.com/irashack/molebridge/internal/validate"
)

// EchoURLs are two operators per family, so one service cannot vouch for
// itself. Each answers with the caller's address as plain text.
var EchoURLs = map[int][2]string{
	4: {"https://api.ipify.org", "https://ipv4.icanhazip.com"},
	6: {"https://api6.ipify.org", "https://ipv6.icanhazip.com"},
}

// EchoMaxBytes bounds an echo answer.
const EchoMaxBytes = 256

// HostLacksFamily is the host address when the host was shown to have no
// address of its own in this family; distinct from "", which means the
// measurement failed and nothing is known.
const HostLacksFamily = "host-lacks-family"

var errEcho = errors.New("invalid echo response")

// ParseEcho is the address an echo service answered with, canonical, or an
// error. Only one usable address is accepted: surrounding blanks are stripped,
// anything with a blank inside, a wrong family, or a loopback, unspecified,
// multicast or link-local address is refused. (A scoped IPv6 address is
// refused too; Python's ipaddress would keep the scope.)
func ParseEcho(raw string, family int) (string, error) {
	if validate.RuneCount(raw) > EchoMaxBytes {
		return "", errEcho
	}
	text := strings.Trim(raw, " \t\r\n")
	if text == "" {
		return "", errEcho
	}
	for _, r := range text {
		if validate.IsSpace(r) {
			return "", errEcho
		}
	}
	address, err := netip.ParseAddr(text)
	if err != nil || address.Zone() != "" {
		return "", errors.New("invalid IP address")
	}
	if (family != 4 && family != 6) || address.Is4() != (family == 4) {
		return "", errors.New("wrong echo address family")
	}
	// An IPv4 address mapped into IPv6 is judged as the IPv4 address too.
	if reject(address) || (address.Is4In6() && reject(address.Unmap())) {
		return "", errors.New("echo address cannot be an egress address")
	}
	return address.String(), nil
}

func reject(a netip.Addr) bool {
	return a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() || a.IsLinkLocalUnicast()
}

// ExitAddresses are the selected server's exit addresses in this family from
// the catalogue entry's "exit_ips" list (decoded JSON), or nil when the entry
// lists none for it. Malformed members are ignored.
func ExitAddresses(relay any, family int) map[string]bool {
	entry, ok := relay.(map[string]any)
	if !ok {
		return nil
	}
	values, ok := entry["exit_ips"].([]any)
	if !ok {
		return nil
	}
	found := map[string]bool{}
	for _, value := range values {
		s, ok := value.(string)
		if !ok {
			continue
		}
		address, err := netip.ParseAddr(s)
		if err != nil || address.Zone() != "" || (family == 4) != address.Is4() || (family != 4 && family != 6) {
			continue
		}
		found[address.String()] = true
	}
	if len(found) == 0 {
		return nil
	}
	return found
}

var noPathTypes = []string{"unreachable", "blackhole", "prohibit", "throw"}

// routeGivesNoIPv6 is true for a route that cannot carry the host's own IPv6:
// one through the tunnel or the overlay, one that only refuses traffic, or a
// link-local, multicast or loopback one. Anything else, or anything
// unparseable, may.
func routeGivesNoIPv6(raw any, ignore map[string]bool) bool {
	route, ok := raw.(map[string]any)
	if !ok {
		return false
	}
	if dev, isString := route["dev"].(string); isString && ignore[dev] {
		return true
	}
	if kind, isString := route["type"].(string); isString {
		for _, t := range noPathTypes {
			if kind == t {
				_, gateway := route["gateway"]
				_, nexthops := route["nexthops"]
				_, via := route["via"]
				if !gateway && !nexthops && !via {
					return true
				}
			}
		}
	}
	destination, isString := route["dst"].(string)
	if !isString || destination == "default" {
		return false
	}
	address, bits, ok := parseIPv6Network(destination)
	if !ok {
		return false
	}
	bytes := address.As16()
	switch {
	case bits >= 10 && bytes[0] == 0xfe && bytes[1]&0xc0 == 0x80: // fe80::/10
		return true
	case bits >= 8 && bytes[0] == 0xff: // ff00::/8
		return true
	}
	return bits == 128 && address == netip.MustParseAddr("::1")
}

// parseIPv6Network reads "addr/prefix" or "addr" as Python's
// IPv6Network(strict=False) does: the host bits are cleared.
func parseIPv6Network(text string) (netip.Addr, int, bool) {
	addrText, prefixText, hasPrefix := strings.Cut(text, "/")
	bits := 128
	if hasPrefix {
		if prefixText == "" {
			return netip.Addr{}, 0, false
		}
		for _, c := range prefixText {
			if c < '0' || c > '9' {
				return netip.Addr{}, 0, false
			}
		}
		digits := strings.TrimLeft(prefixText, "0")
		if len(digits) > 3 {
			return netip.Addr{}, 0, false
		}
		bits = 0
		if digits != "" {
			bits, _ = strconv.Atoi(digits)
		}
		if bits > 128 {
			return netip.Addr{}, 0, false
		}
	}
	address, err := netip.ParseAddr(addrText)
	if err != nil || address.Zone() != "" || !address.Is6() {
		return netip.Addr{}, 0, false
	}
	masked, err := address.Prefix(bits)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	return masked.Addr(), bits, true
}

// HostLacksIPv6 is independent evidence that the namespace has no IPv6 of its
// own.
//
// routes is `ip -j -6 route show table all`, every table any rule can point
// to, and links is `ip -j -6 address show scope global`, both decoded; ignore
// names the tunnel and overlay interfaces. It is true only when no route but
// the tunnel's, the overlay's, refusing, link-local, multicast and loopback
// ones exists, and no interface but the tunnel and the overlay, loopback
// included, has a global IPv6 address (::1 is host scope, not global). Anything
// unexpected counts as evidence of IPv6.
func HostLacksIPv6(routes, links any, ignore map[string]bool) bool {
	routeList, ok1 := routes.([]any)
	linkList, ok2 := links.([]any)
	if !ok1 || !ok2 {
		return false
	}
	for _, route := range routeList {
		if !routeGivesNoIPv6(route, ignore) {
			return false
		}
	}
	for _, raw := range linkList {
		link, ok := raw.(map[string]any)
		if !ok {
			return false
		}
		name, isString := link["ifname"].(string)
		if !isString {
			return false
		}
		if ignore[name] {
			continue
		}
		var addresses []any
		if value, present := link["addr_info"]; !present {
			addresses = nil
		} else if addresses, ok = value.([]any); !ok {
			return false
		}
		for _, raw := range addresses {
			entry, ok := raw.(map[string]any)
			if !ok {
				return false
			}
			if entry["family"] == "inet6" && entry["scope"] != "host" && entry["scope"] != "link" {
				return false
			}
		}
	}
	return true
}

// TunnelVerdict is true only when every tunnel-tier condition holds for one
// family.
//
// echoes are the parsed answers through the tunnel (an empty string stands for
// an answer that wasn't text); hostAddress the host's own address measured off
// the tunnel, HostLacksFamily when the host provably has none in this family,
// or "" when the measurement failed, which fails the check; expected the
// catalogue's exit addresses or nil; handshakeAge nil when no handshake age is
// known.
func TunnelVerdict(echoes []string, hostAddress string, expected map[string]bool, handshakeAge *int, maxHandshakeAge int) bool {
	if handshakeAge == nil || *handshakeAge < 0 || *handshakeAge >= maxHandshakeAge {
		return false
	}
	if len(echoes) < 2 {
		return false
	}
	for _, e := range echoes {
		if e == "" || e != echoes[0] {
			return false
		}
	}
	address := echoes[0]
	if hostAddress == "" || address == hostAddress {
		return false
	}
	return expected == nil || expected[address]
}
