// Package prepareconfig is the prepare-config role: tools/prepare-tunnel-config.py
// as a container tool. It turns a WireGuard config downloaded from Mullvad or
// NordVPN into Molebridge's tunnel config, or creates a new PIA tunnel config
// with a fresh key. It prints no key material.
package prepareconfig

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/irashack/molebridge/internal/panel/pystr"
	"github.com/irashack/molebridge/internal/providers"
	"github.com/irashack/molebridge/internal/tools/privfile"
)

// DefaultTable is EXIT_TABLE when the environment does not set one.
const DefaultTable = "51821"

// MaxInput bounds the downloaded file. (The Python tool read it whole; a
// Mullvad config is a few hundred bytes.)
const MaxInput = 64 * 1024

// ConfigError is a refusal with a fixed, key-free message.
type ConfigError string

func (e ConfigError) Error() string { return string(e) }

func refuse(format string, a ...any) error { return ConfigError(fmt.Sprintf(format, a...)) }

// Help is the usage text; it documents the mounts.
const Help = `Usage: molebridge prepare-config DOWNLOADED.conf OUTPUT
       molebridge prepare-config --nordvpn DOWNLOADED.conf OUTPUT
       molebridge prepare-config --pia OUTPUT

Turns a WireGuard config downloaded from Mullvad (or, with --nordvpn, from
NordVPN) into Molebridge's tunnel config, or (--pia) creates a new PIA tunnel
config. The paths are inside the container, so mount them. OUTPUT is written
mode 0600 and atomically. With --pia a new private key is generated and the
config has no address or peer (the applier registers the key with PIA and
sets both per region); an existing OUTPUT is never overwritten. From a
Mullvad file the downloaded server becomes the starting peer; the panel
changes it later. Only the private key, tunnel addresses and first peer are
kept. From a NordVPN file only the private key is kept: the config has
NordLynx's tunnel address (10.5.0.2/32) and no peer, and the applier sets the
peer when you pick a server, so any NordVPN server's file will do. The DNS
line is dropped on purpose, and routing is handed to the exit through
"Table = off" plus a default route in the exit table (EXIT_TABLE, default
51821, passed with -e if changed). Prints no key material. Delete the
downloaded file once this succeeds.

Run it as yourself so the output is not owned by root:

  docker run --rm --user "$(id -u):$(id -g)" \
    -v "$PWD/tunnel/wg_confs:/out" -v "$HOME/Downloads/mullvad.conf:/in.conf:ro" \
    ghcr.io/irashack/molebridge:<tag> prepare-config /in.conf /out/mullvad.conf

  docker run --rm --user "$(id -u):$(id -g)" \
    -v "$PWD/tunnel/wg_confs:/out" -v "$HOME/Downloads/nordvpn.conf:/in.conf:ro" \
    ghcr.io/irashack/molebridge:<tag> prepare-config --nordvpn /in.conf /out/nordvpn.conf

  docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/tunnel/wg_confs:/out" \
    ghcr.io/irashack/molebridge:<tag> prepare-config --pia /out/pia.conf

On rootless Podman drop --user: the default mapping makes the container's root
you, so the files are yours.
`

// -- parsing ---------------------------------------------------------------

// splitLines is str.splitlines(): it also splits at \v, \f, \x1c-\x1e, \x85,
// U+2028 and U+2029, and treats \r\n as one break.
func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch r {
		case '\n', '\v', '\f', 0x1c, 0x1d, 0x1e, 0x85, 0x2028, 0x2029:
			lines = append(lines, s[start:i])
			i += size
			start = i
		case '\r':
			lines = append(lines, s[start:i])
			i += size
			if i < len(s) && s[i] == '\n' {
				i++
			}
			start = i
		default:
			i += size
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

// section is one INI section; the first value of a key wins.
type section map[string]string

func (s section) setDefault(key, value string) {
	if _, ok := s[key]; !ok {
		s[key] = value
	}
}

// parseWireguardConf is parse_wireguard_conf: only the first [Peer] is kept,
// the first value of a key wins and any other section is ignored.
func parseWireguardConf(text string) (iface, peer section) {
	iface, peer = section{}, section{}
	var current section
	for _, raw := range splitLines(text) {
		line, _, _ := strings.Cut(raw, "#")
		line = pystr.Strip(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			name := pystr.Strip(line[1 : len(line)-1])
			switch {
			case name == "Peer" && len(peer) > 0:
				current = nil // keep only the first peer
			case name == "Interface":
				current = iface
			case name == "Peer":
				current = peer
			default:
				current = nil
			}
			continue
		}
		if current != nil {
			if k, v, ok := strings.Cut(line, "="); ok {
				current.setDefault(pystr.Strip(k), pystr.Strip(v))
			}
		}
	}
	return iface, peer
}

// requireKey is require_key. The key must be the canonical base64 of 32
// bytes: the exit's validator refuses any other spelling (the Python tool
// also accepted a final character with stray low bits; see the deviations in
// the report).
func requireKey(value, field string) (string, error) {
	if len(value) == 44 && !strings.ContainsAny(value, "\r\n") {
		if raw, err := base64.StdEncoding.Strict().DecodeString(value); err == nil && len(raw) == 32 {
			return value, nil
		}
	}
	return "", refuse("%s is missing or is not a WireGuard key", field)
}

var tableRE = regexp.MustCompile(`^[1-9][0-9]{0,9}$`)

// CheckTable is check_table: an unreserved routing table number.
func CheckTable(table string) error {
	if !tableRE.MatchString(table) {
		return refuse("EXIT_TABLE must be an unreserved table number (256..2147483647)")
	}
	if n, err := strconv.ParseInt(table, 10, 64); err != nil || n < 256 || n > 2147483647 {
		return refuse("EXIT_TABLE must be an unreserved table number (256..2147483647)")
	}
	return nil
}

// hostPrefixLen is the prefix length ipaddress.ip_interface reads from the
// text after the slash: digits, or (IPv4) a netmask or a hostmask.
func prefixLen(a netip.Addr, text string) (int, bool) {
	max := a.BitLen()
	if text != "" && strings.Trim(text, "0123456789") == "" {
		if len(text) > 3 {
			return 0, false
		}
		n, _ := strconv.Atoi(text)
		return n, n <= max
	}
	if !a.Is4() {
		return 0, false
	}
	m, err := netip.ParseAddr(text)
	if err != nil || !m.Is4() {
		return 0, false
	}
	bits := m.As4()
	v := uint32(bits[0])<<24 | uint32(bits[1])<<16 | uint32(bits[2])<<8 | uint32(bits[3])
	contiguous := func(x uint32) (int, bool) { // leading ones then zeros
		n := 0
		for n < 32 && x&(1<<(31-n)) != 0 {
			n++
		}
		return n, n == 32 || x<<n == 0
	}
	if n, ok := contiguous(v); ok {
		return n, true
	}
	if n, ok := contiguous(^v); ok { // a hostmask
		return 32 - n, true
	}
	return 0, false
}

// iface is one parsed Interface Address: ipaddress.ip_interface.
type ifaceAddr struct {
	addr   netip.Addr
	prefix int
}

func (a ifaceAddr) String() string { return a.addr.String() + "/" + strconv.Itoa(a.prefix) }

func parseInterface(text string) (ifaceAddr, bool) {
	host, rest, hasSlash := strings.Cut(text, "/")
	if strings.Contains(host, "%") {
		return ifaceAddr{}, false
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return ifaceAddr{}, false
	}
	n := a.BitLen()
	if hasSlash {
		var ok bool
		if n, ok = prefixLen(a, rest); !ok {
			return ifaceAddr{}, false
		}
	}
	return ifaceAddr{addr: a, prefix: n}, true
}

var portRE = regexp.MustCompile(`^[0-9]{1,5}$`)

// BuildTunnelConf is build_tunnel_conf.
func BuildTunnelConf(text, table string) (string, error) {
	ifc, peer := parseWireguardConf(text)
	privateKey, err := requireKey(ifc["PrivateKey"], "Interface PrivateKey")
	if err != nil {
		return "", err
	}
	publicKey, err := requireKey(peer["PublicKey"], "Peer PublicKey")
	if err != nil {
		return "", err
	}

	var parsed []ifaceAddr
	for _, part := range strings.Split(ifc["Address"], ",") {
		part = pystr.Strip(part)
		if part == "" {
			continue
		}
		a, ok := parseInterface(part)
		if !ok {
			return "", refuse("Interface Address is not valid")
		}
		parsed = append(parsed, a)
	}
	var n4, n6 int
	for _, a := range parsed {
		if a.addr.Is4() {
			n4++
		} else {
			n6++
		}
	}
	if n4 == 0 {
		return "", refuse("Interface Address has no IPv4 tunnel address")
	}
	for _, a := range parsed {
		if a.addr == nordHost {
			return "", refuse("this is a NordVPN config; use prepare-config --nordvpn")
		}
	}
	// What the exit accepts (docs/configuration.md#the-tunnel-config): one
	// host address per family.
	if n4 > 1 || n6 > 1 {
		return "", refuse("Interface Address has more than one address in a family")
	}
	for _, a := range parsed {
		if a.prefix != a.addr.BitLen() {
			return "", refuse("Interface Address must be host addresses (/32 and /128)")
		}
	}

	endpoint := peer["Endpoint"]
	var host, port string
	if i := strings.LastIndex(endpoint, ":"); i >= 0 {
		host, port = endpoint[:i], endpoint[i+1:]
	} else {
		port = endpoint
	}
	if h, err := netip.ParseAddr(host); err != nil || !h.Is4() {
		return "", refuse("Peer Endpoint must be an IPv4 address and port")
	}
	if p, _ := strconv.Atoi(port); !portRE.MatchString(port) || p < 1 || p > 65535 {
		return "", refuse("Peer Endpoint port must be 1..65535")
	}
	if err := CheckTable(table); err != nil {
		return "", err
	}

	postUp := "ip route replace default dev %i table " + table
	preDown := "ip route del default dev %i table " + table
	allowed := "0.0.0.0/0"
	if n6 > 0 {
		postUp += "; ip -6 route replace default dev %i table " + table
		preDown += "; ip -6 route del default dev %i table " + table
		allowed += ", ::/0"
	}
	addrs := make([]string, len(parsed))
	for i, a := range parsed {
		addrs[i] = a.String()
	}
	return strings.Join([]string{
		"# Generated by molebridge prepare-config. Keep mode 0600; never commit.",
		"[Interface]",
		"PrivateKey = " + privateKey,
		"Address = " + strings.Join(addrs, ", "),
		"MTU = 1420",
		"Table = off",
		"PostUp = " + postUp,
		"PreDown = " + preDown,
		"",
		"[Peer]",
		"PublicKey = " + publicKey,
		"Endpoint = " + host + ":" + port,
		"AllowedIPs = " + allowed,
		"PersistentKeepalive = 25",
		"",
	}, "\n"), nil
}

// nordHost is NordLynx's tunnel address. NordVPN's downloaded configs write it
// as 10.5.0.2/16; the exit uses it as a host address.
var nordHost = netip.MustParsePrefix(providers.NordAddress).Addr()

// BuildNordVPNTunnelConf turns a WireGuard config downloaded from NordVPN into
// the same tunnel config nordvpn-key writes. The account's key is the same in
// every server's file, so only the key is kept; the peer is dropped because
// the applier sets it when a server is chosen.
func BuildNordVPNTunnelConf(text, table string) (string, error) {
	ifc, _ := parseWireguardConf(text)
	privateKey, err := requireKey(ifc["PrivateKey"], "Interface PrivateKey")
	if err != nil {
		return "", err
	}
	// Exactly NordLynx's address, at any prefix length. An IPv6 address is
	// refused: NordLynx carries no IPv6 (docs/providers.md#how-nordvpn-differs).
	var parts []string
	for _, part := range strings.Split(ifc["Address"], ",") {
		if part = pystr.Strip(part); part != "" {
			parts = append(parts, part)
		}
	}
	if len(parts) != 1 {
		return "", refuse("Interface Address must be NordLynx's 10.5.0.2 and nothing else")
	}
	if a, ok := parseInterface(parts[0]); !ok || a.addr != nordHost {
		return "", refuse("Interface Address must be NordLynx's 10.5.0.2 and nothing else")
	}
	return BuildNordConf(privateKey, table, "prepare-config --nordvpn")
}

// BuildNordConf is the NordVPN tunnel config both prepare-config --nordvpn and
// nordvpn-key write; tool names the generator in the header comment.
func BuildNordConf(privateKey, table, tool string) (string, error) {
	if _, err := requireKey(privateKey, "PrivateKey"); err != nil {
		return "", err
	}
	if err := CheckTable(table); err != nil {
		return "", err
	}
	// IPv4 only: NordLynx carries no IPv6, so IPv6 stays on the unreachable fallback.
	return strings.Join([]string{
		"# Generated by molebridge " + tool + ". Keep mode 0600; never commit.",
		"# No peer: the applier sets it when a server is chosen.",
		"[Interface]",
		"PrivateKey = " + privateKey,
		"Address = " + providers.NordAddress,
		"MTU = 1420",
		"Table = off",
		"PostUp = ip route replace default dev %i table " + table,
		"PreDown = ip route del default dev %i table " + table,
		"",
	}, "\n"), nil
}

// NewPrivateKey is new_private_key: a Curve25519 private key as `wg genkey`
// makes it, random and clamped.
func NewPrivateKey(random io.Reader) (string, error) {
	var raw [32]byte
	if _, err := io.ReadFull(random, raw[:]); err != nil {
		return "", err
	}
	raw[0] &= 248
	raw[31] = (raw[31] & 127) | 64
	return base64.StdEncoding.EncodeToString(raw[:]), nil
}

// BuildPIAConf is build_pia_conf.
func BuildPIAConf(privateKey, table string) (string, error) {
	if _, err := requireKey(privateKey, "PrivateKey"); err != nil {
		return "", err
	}
	if err := CheckTable(table); err != nil {
		return "", err
	}
	// IPv4 only: PIA carries no IPv6, so IPv6 stays on the unreachable fallback.
	return strings.Join([]string{
		"# Generated by molebridge prepare-config --pia. Keep mode 0600; never commit.",
		"# No tunnel address or peer: the applier sets both when it registers this key with PIA.",
		"[Interface]",
		"PrivateKey = " + privateKey,
		"MTU = 1420",
		"Table = off",
		"PostUp = ip route replace default dev %i table " + table,
		"PreDown = ip route del default dev %i table " + table,
		"",
	}, "\n"), nil
}

// -- the role --------------------------------------------------------------

// Options are what Main needs from its surroundings; the zero value is wrong,
// use Defaults.
type Options struct {
	// Env is the process environment as a map (EXIT_TABLE is read from it).
	Env    map[string]string
	Random io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// Defaults returns Options for the real process.
func Defaults(env map[string]string, stdout, stderr io.Writer) Options {
	return Options{Env: env, Random: rand.Reader, Stdout: stdout, Stderr: stderr}
}

func (o Options) table() string {
	if v, ok := o.Env["EXIT_TABLE"]; ok {
		return v
	}
	return DefaultTable
}

// readInput reads the downloaded config: bounded and valid UTF-8.
func readInput(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxInput+1))
	if err != nil {
		return "", err
	}
	if len(data) > MaxInput {
		return "", refuse("the downloaded config is larger than 64 KiB")
	}
	if !utf8.Valid(data) {
		return "", refuse("the downloaded config is not valid UTF-8")
	}
	return string(data), nil
}

// Main runs the role and returns the exit status: 0 on success, 1 on a
// refusal, 2 on a usage error.
func Main(args []string, o Options) int {
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		io.WriteString(o.Stdout, Help)
		return 0
	}
	if (len(args) == 1 || len(args) == 2) && args[0] == "--pia" {
		if len(args) != 2 {
			return usage(o)
		}
		output := args[1]
		if _, err := os.Stat(output); err == nil {
			fmt.Fprintf(o.Stderr, "error: %s exists; keep it, or remove it deliberately to make a new key\n", output)
			return 1
		}
		key, err := NewPrivateKey(o.Random)
		if err == nil {
			var content string
			if content, err = BuildPIAConf(key, o.table()); err == nil {
				err = privfile.Write(output, []byte(content), 0o600)
			}
		}
		if err != nil {
			return fail(o, err)
		}
		fmt.Fprintf(o.Stdout, "wrote %s (mode 0600)\n", output)
		return 0
	}
	build := BuildTunnelConf
	if len(args) > 0 && args[0] == "--nordvpn" {
		build, args = BuildNordVPNTunnelConf, args[1:]
	}
	if len(args) != 2 {
		return usage(o)
	}
	source, output := args[0], args[1]
	text, err := readInput(source)
	if err == nil {
		var content string
		if content, err = build(text, o.table()); err == nil {
			err = privfile.Write(output, []byte(content), 0o600)
		}
	}
	if err != nil {
		return fail(o, err)
	}
	fmt.Fprintf(o.Stdout, "wrote %s (mode 0600); delete %s now\n", output, source)
	return 0
}

func usage(o Options) int {
	fmt.Fprintln(o.Stderr, "usage: molebridge prepare-config DOWNLOADED.conf OUTPUT")
	fmt.Fprintln(o.Stderr, "       molebridge prepare-config --nordvpn DOWNLOADED.conf OUTPUT")
	fmt.Fprintln(o.Stderr, "       molebridge prepare-config --pia OUTPUT")
	return 2
}

// fail prints a refusal. A ConfigError carries its fixed message; an I/O
// error is shown as the operating system words it (it names only paths the
// caller gave).
func fail(o Options, err error) int {
	var ce ConfigError
	if errors.As(err, &ce) {
		fmt.Fprintf(o.Stderr, "error: %s\n", ce)
	} else {
		fmt.Fprintf(o.Stderr, "error: %s\n", ioMessage(err))
	}
	return 1
}

func ioMessage(err error) string {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Op + " " + pe.Path + ": " + pe.Err.Error()
	}
	return "the tunnel config could not be written"
}
