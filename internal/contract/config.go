package contract

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/irashack/molebridge/internal/rtnl"
)

// Backend is the tunnel backend.
type Backend string

// The two backends. The values are the TUNNEL_BACKEND settings.
const (
	Native  Backend = "wireguard"
	Gluetun Backend = "gluetun"
)

// Kind is the exit kind.
type Kind string

// The two kinds. A sidecar has no contract, no overlay and no NetBird.
const (
	Overlay Kind = "overlay"
	Sidecar Kind = "sidecar"
)

// Tables gluetun and NetBird use in a shared namespace; EXIT_TABLE and
// HOST_TABLE may not be either.
const (
	GluetunTable = 51820
	NetBirdTable = 7120
)

// GluetunMark is gluetun's WireGuard fwmark (0xca6c), fixed in v3.41.3.
const GluetunMark uint32 = 51820

// Defaults of the settings.
const (
	DefaultOverlayIf   = "wt0"
	DefaultExitIf      = "mullvad"
	DefaultExitTable   = 51821
	DefaultHostIf      = "eth0"
	DefaultHostTable   = 51822
	DefaultControlMark = "0x1bd00"
	DefaultInterval    = 30 * time.Second
)

// Config is the validated routing configuration (RoutingConfig).
type Config struct {
	Kind    Kind
	Backend Backend
	// Overlay and Overlay6 are the NetBird ranges; Overlay6 is the zero
	// Prefix when there is none. A host range (/32, /128) is allowed.
	Overlay, Overlay6 netip.Prefix
	OverlayIf, ExitIf string
	Table             uint32
	// The gluetun backend only.
	HostIf      string
	HostTable   uint32
	ControlMark uint32
}

// IsGluetun reports the gluetun backend.
func (c Config) IsGluetun() bool { return c.Backend == Gluetun }

// IsSidecar reports the sidecar kind.
func (c Config) IsSidecar() bool { return c.Kind == Sidecar }

// OverlayFor returns the overlay range of a family, or the zero Prefix.
func (c Config) OverlayFor(family rtnl.Family) netip.Prefix {
	if family == rtnl.V6 {
		return c.Overlay6
	}
	return c.Overlay
}

// Error is a refusal of a setting. Its text is the message the exit prints
// (the shell's fail() text), without the program prefix.
type Error string

func (e Error) Error() string { return string(e) }

func refuse(format string, a ...any) error { return Error(fmt.Sprintf(format, a...)) }

// Getenv reads a setting; an unset setting and an empty one are the same, as
// `${NAME:-default}` treated them.
type Getenv func(string) string

func (g Getenv) get(name, def string) string {
	if v := g(name); v != "" {
		return v
	}
	return def
}

func isUint(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// ValidInterfaceName is gr_valid_if / INTERFACE: one letter, digit or
// underscore, then up to fourteen of those or "." or "-".
func ValidInterfaceName(s string) bool {
	if s == "" || len(s) > 15 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		alnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
		if i == 0 && !alnum {
			return false
		}
		if !alnum && c != '.' && c != '-' {
			return false
		}
	}
	return true
}

// validGluetunInterface is gluetun's own rule: letters, digits, underscores.
func validGluetunInterface(s string) bool {
	if s == "" || len(s) > 15 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// parseTable is gr_valid_table: canonical decimal, 256..2147483647.
func parseTable(name, v string) (uint32, error) {
	if !isUint(v) {
		return 0, refuse("%s must be numeric", name)
	}
	if v[0] == '0' {
		return 0, refuse("%s must be canonical decimal", name)
	}
	if len(v) > 10 {
		return 0, refuse("%s must be 256..2147483647", name)
	}
	n, _ := strconv.ParseUint(v, 10, 64)
	if n < 256 || n > 2147483647 {
		return 0, refuse("%s must be 256..2147483647", name)
	}
	return uint32(n), nil
}

// parseOverlay4 is gr_shown_cidr4 plus the strict network check.
func parseOverlay4(v string) (netip.Prefix, error) {
	if !strings.Contains(v, "/") {
		return netip.Prefix{}, refuse("OVERLAY_CIDR must be an IPv4 CIDR")
	}
	slash := strings.Index(v, "/")
	prefix := v[slash+1:]
	if !isUint(prefix) {
		return netip.Prefix{}, refuse("invalid IPv4 prefix")
	}
	if prefix[0] == '0' {
		return netip.Prefix{}, refuse("IPv4 default routes and leading zeroes are forbidden")
	}
	bits, _ := strconv.Atoi(prefix)
	if len(prefix) > 2 || bits > 32 {
		return netip.Prefix{}, refuse("invalid IPv4 prefix")
	}
	address := v[:strings.LastIndex(v, "/")]
	octets := strings.Split(address, ".")
	if len(octets) != 4 {
		return netip.Prefix{}, refuse("IPv4 address needs four octets")
	}
	var number uint32
	var raw [4]byte
	for i, o := range octets {
		if !isUint(o) {
			return netip.Prefix{}, refuse("invalid IPv4 octet")
		}
		if o != "0" && o[0] == '0' {
			return netip.Prefix{}, refuse("IPv4 leading zeroes are forbidden")
		}
		n, _ := strconv.Atoi(o)
		if len(o) > 3 || n > 255 {
			return netip.Prefix{}, refuse("invalid IPv4 octet")
		}
		raw[i] = byte(n)
		number = number<<8 | uint32(n)
	}
	if bits < 32 && number%(1<<(32-bits)) != 0 {
		return netip.Prefix{}, refuse("OVERLAY_CIDR must use the network address")
	}
	return netip.PrefixFrom(netip.AddrFrom4(raw), bits), nil
}

// parseOverlay6 is the IPv6 half of gr_validate_common, with the network
// address check molebridge/routing.py makes (IPv6Network(strict=True)) and
// the shell does not.
func parseOverlay6(v string) (netip.Prefix, error) {
	// The shell's pattern *:*/* : a colon with a slash after it.
	colon := strings.Index(v, ":")
	if colon < 0 || !strings.Contains(v[colon:], "/") {
		return netip.Prefix{}, refuse("OVERLAY6_CIDR must be an IPv6 CIDR")
	}
	slash := strings.Index(v, "/")
	prefix := v[slash+1:]
	if !isUint(prefix) || len(prefix) > 3 {
		return netip.Prefix{}, refuse("invalid IPv6 prefix")
	}
	bits, _ := strconv.Atoi(prefix)
	if bits < 1 || bits > 128 {
		return netip.Prefix{}, refuse("invalid IPv6 prefix")
	}
	if strings.Count(v, "/") != 1 {
		return netip.Prefix{}, refuse("invalid OVERLAY6_CIDR")
	}
	addr, ok := parseIPv6Text(v[:slash])
	if !ok {
		return netip.Prefix{}, refuse("invalid OVERLAY6_CIDR")
	}
	p := netip.PrefixFrom(addr, bits)
	if p.Masked() != p {
		return netip.Prefix{}, refuse("OVERLAY6_CIDR must use the network address")
	}
	return p, nil
}

// parseIPv6Text accepts what canonical_cidr6 accepts: hexadecimal groups and
// colons only (any case), up to 39 characters, one "::" at most.
func parseIPv6Text(s string) (netip.Addr, bool) {
	if s == "" {
		return netip.Addr{}, false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c == ':' || c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return netip.Addr{}, false
		}
	}
	a, err := netip.ParseAddr(strings.ToLower(s))
	if err != nil || !a.Is6() {
		return netip.Addr{}, false
	}
	return a, true
}

// ControlMarkValue is control_mark_value: lowercase hexadecimal with a
// leading 0x and no leading zero, at most 32 bits, low byte zero (NetBird's
// requirement of NB_FWMARK_BASE, and how iproute2 prints it).
func ControlMarkValue(mark string) (uint32, error) {
	if len(mark) < 3 || len(mark) > 10 || mark[:2] != "0x" || mark[2] == '0' {
		return 0, refuse("CONTROL_MARK must be lowercase hexadecimal like 0x1bd00")
	}
	for i := 2; i < len(mark); i++ {
		c := mark[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return 0, refuse("CONTROL_MARK must be lowercase hexadecimal like 0x1bd00")
		}
	}
	n, err := strconv.ParseUint(mark[2:], 16, 32)
	if err != nil {
		return 0, refuse("CONTROL_MARK must be lowercase hexadecimal like 0x1bd00")
	}
	if n&0xff != 0 {
		return 0, refuse("CONTROL_MARK must be lowercase hexadecimal like 0x1bd00, low byte zero")
	}
	return uint32(n), nil
}

// ConfigFromEnv validates the routing settings: RoutingConfig.from_env with
// the checks and messages of gr_validate_common and gr_validate, which the
// exit's entry points ran first.
func ConfigFromEnv(getenv func(string) string) (Config, error) {
	env := Getenv(getenv)
	kind := Kind(env.get("EXIT_KIND", string(Overlay)))
	if kind != Overlay && kind != Sidecar {
		return Config{}, refuse("EXIT_KIND must be overlay or sidecar")
	}
	backend := Backend(env.get("TUNNEL_BACKEND", string(Native)))
	if kind == Sidecar {
		if backend != Gluetun {
			return Config{}, refuse("EXIT_KIND=sidecar needs TUNNEL_BACKEND=gluetun")
		}
		exitIf := env.get("EXIT_IF", "wg0")
		if !validGluetunInterface(exitIf) {
			return Config{}, refuse("with gluetun, EXIT_IF may hold only letters, digits and underscores")
		}
		// Nothing of the routing contract is configured or read.
		return Config{Kind: Sidecar, Backend: Gluetun, ExitIf: exitIf}, nil
	}
	if backend != Native && backend != Gluetun {
		return Config{}, refuse("TUNNEL_BACKEND must be wireguard or gluetun")
	}
	c := Config{
		Kind:      Overlay,
		Backend:   backend,
		OverlayIf: env.get("OVERLAY_IF", DefaultOverlayIf),
		ExitIf:    env.get("EXIT_IF", DefaultExitIf),
	}
	if !ValidInterfaceName(c.OverlayIf) || !ValidInterfaceName(c.ExitIf) {
		return Config{}, refuse("invalid interface name")
	}
	if c.OverlayIf == c.ExitIf {
		return Config{}, refuse("overlay and exit interfaces must differ")
	}
	var err error
	if c.Table, err = parseTable("EXIT_TABLE", env.get("EXIT_TABLE", strconv.Itoa(DefaultExitTable))); err != nil {
		return Config{}, err
	}
	if c.Overlay, err = parseOverlay4(getenv("OVERLAY_CIDR")); err != nil {
		return Config{}, err
	}
	if v := getenv("OVERLAY6_CIDR"); v != "" {
		if c.Overlay6, err = parseOverlay6(v); err != nil {
			return Config{}, err
		}
	}
	if backend == Native {
		return c, nil
	}
	if !validGluetunInterface(c.ExitIf) {
		return Config{}, refuse("with gluetun, EXIT_IF may hold only letters, digits and underscores")
	}
	c.HostIf = env.get("HOST_IF", DefaultHostIf)
	if !ValidInterfaceName(c.HostIf) {
		return Config{}, refuse("invalid HOST_IF")
	}
	if c.HostIf == "lo" || c.HostIf == c.OverlayIf || c.HostIf == c.ExitIf {
		return Config{}, refuse("HOST_IF must name the namespace's host interface, not lo, the overlay or the tunnel")
	}
	if c.HostTable, err = parseTable("HOST_TABLE", env.get("HOST_TABLE", strconv.Itoa(DefaultHostTable))); err != nil {
		return Config{}, err
	}
	if c.HostTable == c.Table {
		return Config{}, refuse("HOST_TABLE and EXIT_TABLE must differ")
	}
	for _, t := range []uint32{c.Table, c.HostTable} {
		if t == GluetunTable || t == NetBirdTable {
			return Config{}, refuse("tables 51820 (gluetun) and 7120 (NetBird) are taken")
		}
	}
	if c.ControlMark, err = ControlMarkValue(env.get("CONTROL_MARK", DefaultControlMark)); err != nil {
		return Config{}, err
	}
	return c, nil
}

// ReconcileInterval reads ROUTING_RECONCILE_INTERVAL: whole seconds, 2 to 60,
// default 30. It is the period of the full pass that backs the event watch.
func ReconcileInterval(getenv func(string) string) (time.Duration, error) {
	v := getenv("ROUTING_RECONCILE_INTERVAL")
	if v == "" {
		return DefaultInterval, nil
	}
	if !isUint(v) || v[0] == '0' || len(v) > 2 {
		return 0, errInterval
	}
	n, _ := strconv.Atoi(v)
	if n < 2 || n > 60 {
		return 0, errInterval
	}
	return time.Duration(n) * time.Second, nil
}

var errInterval = errors.New("ROUTING_RECONCILE_INTERVAL must be 2..60 seconds")
