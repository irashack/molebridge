// Package tunnelconf reads and validates the native exit's tunnel config.
//
// It is a port of the awk validator in routing/molebridge-exit (conf_validator
// and validate_conf) and of what tools/prepare-tunnel-config.py's wg-quick
// did with the file. Only what tools/prepare-tunnel-config.py (Mullvad, and
// PIA with --pia) and tools/nordvpn-key.py (NordVPN) write is accepted; see
// docs/configuration.md "The tunnel config". Anything else is refused before
// any network change, with one fixed message that names a line number and a
// field from the grammar's own list and carries none of the file's text.
//
// The file holds the private key. Nothing in this package prints any of its
// text. The PostUp and PreDown lines are never executed: the exact strings the
// generators write are accepted and translated into route operations
// (Conf.UpRoutes, Conf.DownRoutes).
package tunnelconf

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/irashack/molebridge/internal/rtnl"
)

// Provider selects the grammar: Mullvad's config carries a peer and an
// address; PIA's carries neither (the applier sets both when it registers the
// key); NordVPN's carries an address and no peer.
type Provider string

// The providers.
const (
	Mullvad Provider = "mullvad"
	PIA     Provider = "pia"
	NordVPN Provider = "nordvpn"
)

// MaxSize is the largest config accepted.
const MaxSize = 4096

// Peer is the first peer of a Mullvad config.
type Peer struct {
	PublicKey  [32]byte
	Endpoint   netip.AddrPort
	AllowedIPs []netip.Prefix
	// Keepalive is PersistentKeepalive in seconds, 0 when the line is absent.
	Keepalive int
}

// Conf is a validated tunnel config.
type Conf struct {
	Provider   Provider
	PrivateKey [32]byte
	// Addr4 and Addr6 are the interface addresses (always host addresses),
	// the zero Addr when the config has none in the family.
	Addr4, Addr6 netip.Addr
	MTU          int
	// Table is the exit table the hooks route into.
	Table uint32
	// Peer is set for Mullvad only.
	Peer *Peer
}

// String describes the config without any key material.
func (c *Conf) String() string {
	return fmt.Sprintf("tunnel config (%s, %s)", c.Provider, c.Families())
}

// GoString keeps the key out of %#v too.
func (c *Conf) GoString() string { return c.String() }

// Families names what the config carries, as `--check-config` prints it:
// families, never addresses.
func (c *Conf) Families() string {
	families := "no address (the applier sets it)"
	if c.Addr4.IsValid() {
		families = "an IPv4 address"
	}
	if c.Addr6.IsValid() {
		families += " and an IPv6 address"
	}
	return families
}

// RuleOwner is the owner record's third-from-last field: "conf" when the
// config carries an address (rules 94 and 98 follow from it), "applier" when
// it carries none and the applier owns those rules.
func (c *Conf) RuleOwner() string {
	if c.Addr4.IsValid() || c.Addr6.IsValid() {
		return "conf"
	}
	return "applier"
}

// RouteOp is one route operation the PostUp or PreDown line stands for.
type RouteOp struct {
	// Replace is `ip route replace default dev <if> table N`; otherwise it is
	// `ip route del default dev <if> table N`.
	Replace bool
	Family  rtnl.Family
	Table   uint32
}

// UpRoutes is PostUp: the default route through the tunnel in the exit table,
// IPv6 too when the config has an IPv6 address.
func (c *Conf) UpRoutes() []RouteOp { return c.routes(true) }

// DownRoutes is PreDown.
func (c *Conf) DownRoutes() []RouteOp { return c.routes(false) }

func (c *Conf) routes(replace bool) []RouteOp {
	ops := []RouteOp{{Replace: replace, Family: rtnl.V4, Table: c.Table}}
	if c.Addr6.IsValid() {
		ops = append(ops, RouteOp{Replace: replace, Family: rtnl.V6, Table: c.Table})
	}
	return ops
}

// Error is a refusal of the config's content: Message is the validator's
// fixed text, such as "MTU on line 6 is not valid".
type Error struct{ Message string }

func (e *Error) Error() string { return e.Message }

func reject(format string, a ...any) error { return &Error{Message: fmt.Sprintf(format, a...)} }

// ParseProvider validates the PROVIDER setting.
func ParseProvider(s string) (Provider, error) {
	switch Provider(s) {
	case Mullvad, PIA, NordVPN:
		return Provider(s), nil
	}
	return "", errors.New("PROVIDER must be mullvad, pia or nordvpn")
}

var errUnreadable = errors.New("it is unreadable")

// trim removes spaces and tabs, as the validator's trim() does and nothing else.
func trim(s string) string { return strings.Trim(s, " \t") }

// v4 is the validator's v4(): four dot-separated parts, each 0 or a number
// without leading zeroes, at most 255.
func v4(a string) (netip.Addr, bool) {
	parts := strings.Split(a, ".")
	if len(parts) != 4 {
		return netip.Addr{}, false
	}
	var raw [4]byte
	for i, p := range parts {
		if !(p == "0" || p != "" && p[0] >= '1' && p[0] <= '9' && len(p) <= 3) {
			return netip.Addr{}, false
		}
		n := 0
		for j := 0; j < len(p); j++ {
			if p[j] < '0' || p[j] > '9' {
				return netip.Addr{}, false
			}
			n = n*10 + int(p[j]-'0')
		}
		if n > 255 {
			return netip.Addr{}, false
		}
		raw[i] = byte(n)
	}
	return netip.AddrFrom4(raw), true
}

func hexGroup(g string) bool {
	if g == "" || len(g) > 4 {
		return false
	}
	for i := 0; i < len(g); i++ {
		c := g[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// v6 is the validator's v6(): hexadecimal groups and colons only, 39
// characters at most, one "::" at most, eight groups in all.
func v6(a string) (netip.Addr, bool) {
	if a == "" || len(a) > 39 {
		return netip.Addr{}, false
	}
	for i := 0; i < len(a); i++ {
		c := a[i]
		if !(c == ':' || c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return netip.Addr{}, false
		}
	}
	if d := strings.Index(a, "::"); d >= 0 {
		head, tail := a[:d], a[d+2:]
		if strings.Contains(tail, "::") {
			return netip.Addr{}, false
		}
		var left, right []string
		if head != "" {
			left = strings.Split(head, ":")
		}
		if tail != "" {
			right = strings.Split(tail, ":")
		}
		if len(left)+len(right) > 7 {
			return netip.Addr{}, false
		}
		for _, g := range append(left, right...) {
			if !hexGroup(g) {
				return netip.Addr{}, false
			}
		}
	} else {
		groups := strings.Split(a, ":")
		if len(groups) != 8 {
			return netip.Addr{}, false
		}
		for _, g := range groups {
			if !hexGroup(g) {
				return netip.Addr{}, false
			}
		}
	}
	addr, err := netip.ParseAddr(strings.ToLower(a))
	if err != nil || !addr.Is6() {
		return netip.Addr{}, false
	}
	return addr, true
}

// key reports and decodes a WireGuard key: 32 bytes in base64, so 42
// characters, one whose low two bits are zero, and the padding.
func key(v string) ([32]byte, bool) {
	var out [32]byte
	if len(v) != 44 || v[43] != '=' || !strings.ContainsRune("AEIMQUYcgkosw048", rune(v[42])) {
		return out, false
	}
	for i := 0; i < 42; i++ {
		c := v[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/') {
			return out, false
		}
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(v)
	if err != nil || len(raw) != 32 {
		return out, false
	}
	copy(out[:], raw)
	return out, true
}

// number is the validator's number(): no leading zero, at most five digits,
// within [lo, hi].
func number(v string, lo, hi int) (int, bool) {
	if v == "" || v[0] < '1' || v[0] > '9' || len(v) > 5 {
		return 0, false
	}
	n := 0
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return 0, false
		}
		n = n*10 + int(v[i]-'0')
	}
	return n, n >= lo && n <= hi
}

var sectionOf = map[string]string{
	"PrivateKey": "interface", "Address": "interface", "MTU": "interface", "Table": "interface",
	"PostUp": "interface", "PreDown": "interface",
	"PublicKey": "peer", "Endpoint": "peer", "AllowedIPs": "peer", "PersistentKeepalive": "peer",
}

// Parse validates the text of a tunnel config for a provider and an exit
// table. It never returns text taken from the config in its error.
//
// The field names are spelled exactly as the generators write them: wg-quick
// and wg read field names in any case, but the routing reads Address as
// spelled here, so any other spelling is an unsupported field. The first
// problem found while reading lines is the one reported.
func Parse(text string, provider Provider, table uint32) (*Conf, error) {
	if _, err := ParseProvider(string(provider)); err != nil {
		return nil, err
	}
	var lines []string
	if text != "" {
		lines = strings.Split(text, "\n")
		if strings.HasSuffix(text, "\n") {
			lines = lines[:len(lines)-1]
		}
	}
	var (
		interfaces, peers int
		section           string
		msg               string
		seen              = map[string]int{}
		value             = map[string]string{}
	)
	say := func(m string) {
		if msg == "" {
			msg = m
		}
	}
	for i, raw := range lines {
		nr := i + 1
		line := trim(raw)
		if line == "" || line[0] == '#' {
			continue
		}
		if line == "[Interface]" {
			old := interfaces
			interfaces++
			if old != 0 || peers != 0 {
				say(fmt.Sprintf("[Interface] on line %d is not supported; it must come once, first", nr))
			}
			section = "interface"
			continue
		}
		if line == "[Peer]" {
			if interfaces == 0 {
				say(fmt.Sprintf("[Peer] on line %d is not supported", nr))
			} else {
				old := peers
				peers++
				if old != 0 {
					say(fmt.Sprintf("[Peer] on line %d is not supported", nr))
				}
			}
			section = "peer"
			continue
		}
		eq := strings.Index(line, "=")
		k := ""
		if eq >= 0 {
			k = trim(line[:eq])
		}
		if eq < 0 || sectionOf[k] == "" || sectionOf[k] != section {
			say(fmt.Sprintf("unsupported field on line %d", nr))
			continue
		}
		if _, dup := seen[k]; dup {
			say(k + " appears more than once")
			continue
		}
		seen[k] = nr
		value[k] = trim(line[eq+1:])
	}
	if msg != "" {
		return nil, &Error{Message: msg}
	}
	if interfaces == 0 {
		return nil, reject("[Interface] is missing")
	}
	wantPeer := provider == Mullvad
	if peers > 0 && !wantPeer {
		return nil, reject("[Peer] is not supported for this provider")
	}
	if peers == 0 && wantPeer {
		return nil, reject("[Peer] is missing")
	}
	for _, f := range []string{"PrivateKey", "MTU", "Table", "PostUp", "PreDown"} {
		if _, ok := seen[f]; !ok {
			return nil, reject("%s is missing", f)
		}
	}
	_, hasAddress := seen["Address"]
	if provider != PIA && !hasAddress {
		return nil, reject("Address is missing")
	}
	if provider == PIA && hasAddress {
		return nil, reject("Address on line %d is not supported for PIA", seen["Address"])
	}
	if wantPeer {
		for _, f := range []string{"PublicKey", "Endpoint", "AllowedIPs"} {
			if _, ok := seen[f]; !ok {
				return nil, reject("%s is missing", f)
			}
		}
	}
	conf := &Conf{Provider: provider, Table: table}
	var ok bool
	if conf.PrivateKey, ok = key(value["PrivateKey"]); !ok {
		return nil, reject("PrivateKey on line %d is not valid", seen["PrivateKey"])
	}
	if hasAddress {
		for _, part := range strings.Split(value["Address"], ",") {
			a, p := trim(part), ""
			if slash := strings.Index(a, "/"); slash >= 0 {
				a, p = a[:slash], a[slash+1:]
			}
			if addr, ok := v4(a); ok && (p == "" || p == "32") && !conf.Addr4.IsValid() {
				conf.Addr4 = addr
			} else if addr, ok := v6(a); ok && (p == "" || p == "128") && !conf.Addr6.IsValid() {
				conf.Addr6 = addr
			} else {
				return nil, reject("Address on line %d is not valid", seen["Address"])
			}
		}
		if !conf.Addr4.IsValid() || conf.Addr6.IsValid() && provider != Mullvad {
			return nil, reject("Address on line %d is not valid", seen["Address"])
		}
	}
	if conf.MTU, ok = number(value["MTU"], 1280, 1500); !ok {
		return nil, reject("MTU on line %d is not valid", seen["MTU"])
	}
	if value["Table"] != "off" {
		return nil, reject("Table on line %d is not valid", seen["Table"])
	}
	t := strconv.FormatUint(uint64(table), 10)
	up := "ip route replace default dev %i table " + t
	down := "ip route del default dev %i table " + t
	if conf.Addr6.IsValid() {
		up += "; ip -6 route replace default dev %i table " + t
		down += "; ip -6 route del default dev %i table " + t
	}
	if value["PostUp"] != up {
		return nil, reject("PostUp on line %d is not valid", seen["PostUp"])
	}
	if value["PreDown"] != down {
		return nil, reject("PreDown on line %d is not valid", seen["PreDown"])
	}
	if !wantPeer {
		return conf, nil
	}
	peer := &Peer{}
	if peer.PublicKey, ok = key(value["PublicKey"]); !ok {
		return nil, reject("PublicKey on line %d is not valid", seen["PublicKey"])
	}
	endpoint := value["Endpoint"]
	colon := strings.Index(endpoint, ":")
	if colon < 0 {
		return nil, reject("Endpoint on line %d is not valid", seen["Endpoint"])
	}
	host, hostOK := v4(endpoint[:colon])
	port, portOK := number(endpoint[colon+1:], 1, 65535)
	if !hostOK || !portOK {
		return nil, reject("Endpoint on line %d is not valid", seen["Endpoint"])
	}
	peer.Endpoint = netip.AddrPortFrom(host, uint16(port))
	var got []string
	for _, part := range strings.Split(value["AllowedIPs"], ",") {
		got = append(got, trim(part))
	}
	want := "0.0.0.0/0"
	peer.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	if conf.Addr6.IsValid() {
		want = "0.0.0.0/0,::/0"
		peer.AllowedIPs = append(peer.AllowedIPs, netip.MustParsePrefix("::/0"))
	}
	if strings.Join(got, ",") != want {
		return nil, reject("AllowedIPs on line %d is not valid", seen["AllowedIPs"])
	}
	if _, has := seen["PersistentKeepalive"]; has {
		n, ok := number(value["PersistentKeepalive"], 1, 65535)
		if !ok {
			return nil, reject("PersistentKeepalive on line %d is not valid", seen["PersistentKeepalive"])
		}
		peer.Keepalive = n
	}
	conf.Peer = peer
	return conf, nil
}

// Hint is the "regenerate" advice that ends a refusal of the file.
func Hint(p Provider) string {
	switch p {
	case Mullvad:
		return "regenerate it with tools/prepare-tunnel-config.py (docs/setup.md)"
	case PIA:
		return "regenerate it with tools/prepare-tunnel-config.py --pia (docs/setup.md)"
	case NordVPN:
		return "regenerate it with tools/nordvpn-key.py (docs/setup.md)"
	}
	return ""
}

// FileError is a refusal of the file itself or of its content; its text is
// the message routing/molebridge-exit printed, without the program prefix.
type FileError struct {
	Message string
	// Content is the validator's own error when the content was refused.
	Content error
}

func (e *FileError) Error() string { return e.Message }
func (e *FileError) Unwrap() error { return e.Content }

func fileErr(format string, a ...any) error { return &FileError{Message: fmt.Sprintf(format, a...)} }

// Load reads dir/<exitIf>.conf and validates it (validate_conf): the file
// must exist, be a regular file and not a symbolic link, be readable and at
// most 4 KiB, hold no NUL or carriage-return bytes, and parse.
func Load(dir, exitIf string, provider Provider, table uint32) (*Conf, error) {
	path := dir + "/" + exitIf + ".conf"
	hint := Hint(provider)
	fi, err := os.Lstat(path)
	if err != nil {
		// A directory this process may not search hides the file: on rootful
		// Docker that is a missing DAC_READ_SEARCH, not a missing config.
		if errors.Is(err, syscall.EACCES) {
			return nil, fileErr("the tunnel config directory %s can't be searched (on Docker the container needs DAC_READ_SEARCH; see docs/setup.md)", dir)
		}
		return nil, fileErr("the tunnel config %s is missing; %s", path, hint)
	}
	if !fi.Mode().IsRegular() {
		return nil, fileErr("the tunnel config %s is not a regular file", path)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fileErr("the tunnel config %s is not a regular file", path)
		}
		return nil, fileErr("the tunnel config %s can't be read (on Docker the container needs DAC_READ_SEARCH; see docs/setup.md)", path)
	}
	defer f.Close()
	// One byte past the limit says "too large" without reading a huge file.
	data, err := io.ReadAll(io.LimitReader(f, MaxSize+1))
	if err != nil {
		return nil, fileErr("the tunnel config %s can't be read", path)
	}
	if len(data) > MaxSize {
		return nil, fileErr("the tunnel config %s is larger than 4 KiB; %s", path, hint)
	}
	if strings.ContainsAny(string(data), "\x00\r") {
		return nil, fileErr("the tunnel config %s has NUL or carriage-return bytes; %s", path, hint)
	}
	conf, err := Parse(string(data), provider, table)
	if err != nil {
		var ce *Error
		verdict := errUnreadable.Error()
		if errors.As(err, &ce) {
			verdict = ce.Message
		}
		return nil, &FileError{Message: fmt.Sprintf("the tunnel config %s is not supported: %s; %s", path, verdict, hint), Content: err}
	}
	return conf, nil
}

// OtherConfs counts the .conf files in dir besides <exitIf>.conf, which the
// exit ignores and warns about.
func OtherConfs(dir, exitIf string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, ".conf") && name != exitIf+".conf" && !e.IsDir() {
			n++
		}
	}
	return n
}
