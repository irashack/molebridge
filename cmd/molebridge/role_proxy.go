package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/irashack/molebridge/internal/exit"
	"github.com/irashack/molebridge/internal/panel"
	"github.com/irashack/molebridge/internal/proxy"
	"github.com/irashack/molebridge/internal/relayproxy"
	"github.com/irashack/molebridge/internal/tunneldial"
	"github.com/irashack/molebridge/internal/verdict"
)

func init() {
	register("proxy", "the proxy way in: SOCKS5 and HTTP CONNECT whose every connection leaves through the tunnel, or fails (experimental; no capabilities, non-root)",
		func(args []string) int {
			if len(args) != 0 {
				fmt.Fprintln(os.Stderr, "usage: molebridge proxy (settings come from the environment)")
				return 2
			}
			// The first line names the build, before any refusal.
			fmt.Fprintf(os.Stderr, "molebridge proxy: molebridge %s\n", version)
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
			defer stop()
			return proxyMain(ctx, exit.EnvMap(os.Environ()), systemIdentity(), os.Stderr)
		})
}

// The proxy's settings (docs/proxy.md). Each is read from the environment;
// an empty value is the same as an unset one, as Compose's ${NAME:-} passes it.
const (
	defaultProxyOverlayIf = "wt0" // the exit's OVERLAY_IF default (compose.yaml)
	maxProxyConns         = 65535
)

// defaultProxyDNS is the resolver the proxy asks, through the tunnel, for
// the names it resolves itself, when PROXY_DNS is unset: each provider's own
// resolver inside its tunnel (PIA's and Mullvad's as docs/native-sidecar.md
// names them), and the first of the resolvers NordVPN publishes for its
// customers.
var defaultProxyDNS = map[string]string{
	"mullvad": "10.64.0.1:53",
	"pia":     "10.0.0.243:53",
	"nordvpn": "103.86.96.100:53",
}

// proxySettings are the proxy's settings, checked.
type proxySettings struct {
	StateDir        string // STATE_DIR: applier/ is the exit's, proxy/ the proxy's own
	Provider        string // PROVIDER: mullvad, pia or nordvpn
	TunnelInterface string // TUNNEL_INTERFACE: every connection is bound to it
	Listen          string // PROXY_LISTEN
	MaxConns        int    // PROXY_MAX_CONNS
	PasswordFile    string // PROXY_PASSWORD_FILE
	OverlayIf       string // OVERLAY_IF: NetBird's interface, whose addresses PROXY_LISTEN may use
	DNS             string // PROXY_DNS: "ip:port"
}

// proxySettingsFrom reads and checks the settings. Every refusal names the
// setting; none repeats a value that could be a secret (there is none here:
// the password stays in its file). Every setting is checked, and the error
// joins one refusal per bad setting (errors.Join), so a hand-written
// configuration is corrected in one pass rather than one field at a time.
func proxySettingsFrom(env map[string]string) (proxySettings, error) {
	s := proxySettings{
		StateDir:        orDefault(env["STATE_DIR"], exit.DefaultStateDir),
		Provider:        env["PROVIDER"],
		TunnelInterface: env["TUNNEL_INTERFACE"],
		Listen:          orDefault(env["PROXY_LISTEN"], proxy.DefaultListen),
		MaxConns:        proxy.DefaultMaxConns,
		PasswordFile:    env["PROXY_PASSWORD_FILE"],
		OverlayIf:       orDefault(env["OVERLAY_IF"], defaultProxyOverlayIf),
	}
	var refusals []error
	refuse := func(err error) { refusals = append(refusals, err) }
	if !filepath.IsAbs(s.StateDir) || filepath.Clean(s.StateDir) != s.StateDir {
		refuse(errors.New("STATE_DIR must be a clean absolute path"))
	}
	if env["PROVIDERS"] != "" {
		// The proxy's PROVIDER would be wrong after a provider change (the
		// design's decision 6); its result gate also closes on any
		// multi-provider record, which names providers.
		refuse(errors.New("PROVIDERS is set: the proxy is not supported on a multi-provider exit"))
	}
	switch s.Provider {
	case "mullvad", "pia", "nordvpn":
	case "":
		refuse(errors.New("PROVIDER is required: mullvad, pia or nordvpn"))
	default:
		refuse(fmt.Errorf("PROVIDER %q: the proxy supports mullvad, pia and nordvpn (a native exit or native sidecar), nothing else", s.Provider))
	}
	tunnelOK := false
	switch {
	case s.TunnelInterface == "":
		refuse(errors.New("TUNNEL_INTERFACE is required: the exit's tunnel interface (its EXIT_IF)"))
	case !tunneldial.ValidInterfaceName(s.TunnelInterface):
		refuse(errors.New("TUNNEL_INTERFACE is not a valid interface name"))
	default:
		tunnelOK = true
	}
	overlayOK := tunneldial.ValidInterfaceName(s.OverlayIf)
	if !overlayOK {
		refuse(errors.New("OVERLAY_IF is not a valid interface name"))
	}
	if tunnelOK && overlayOK && s.OverlayIf == s.TunnelInterface {
		refuse(errors.New("OVERLAY_IF and TUNNEL_INTERFACE name the same interface; the proxy must never listen on the tunnel"))
	}
	if _, err := proxy.ParseListen(s.Listen); err != nil {
		// Its form only: whether the address is loopback or one of
		// OVERLAY_IF's is proxy.CheckListen's, against the live interface.
		refuse(fmt.Errorf("PROXY_LISTEN: %v (for example 127.0.0.1:1080)", err))
	}
	if v := env["PROXY_MAX_CONNS"]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxProxyConns || strconv.Itoa(n) != v {
			refuse(fmt.Errorf("PROXY_MAX_CONNS must be a whole number from 1 to %d", maxProxyConns))
		} else {
			s.MaxConns = n
		}
	}
	switch {
	case s.PasswordFile == "":
		refuse(errors.New("PROXY_PASSWORD_FILE is required"))
	case !filepath.IsAbs(s.PasswordFile):
		refuse(errors.New("PROXY_PASSWORD_FILE must be an absolute path"))
	}
	if dns, err := parseProxyDNS(env["PROXY_DNS"], s.Provider); err != nil {
		refuse(err)
	} else {
		s.DNS = dns
	}
	return s, errors.Join(refusals...)
}

// proxyStartRefusals are the refusals before the proxy serves, one line
// each: every bad setting (settingsErr, from proxySettingsFrom), then, where
// the settings they need are good, the password file (proxy.ReadPassword)
// and the listen address against OVERLAY_IF's live addresses
// (proxy.CheckListen, with addrs; nil is the system's). proxy.Serve checks
// those two again.
func proxyStartRefusals(s proxySettings, settingsErr error, addrs func(string) ([]net.Addr, error)) []string {
	var refusals []string
	add := func(err error) {
		if err == nil {
			return
		}
		errs := []error{err}
		if joined, ok := err.(interface{ Unwrap() []error }); ok {
			errs = joined.Unwrap()
		}
		for _, e := range errs {
			refusals = append(refusals, strings.TrimPrefix(e.Error(), "proxy: "))
		}
	}
	add(settingsErr)
	if s.PasswordFile != "" && filepath.IsAbs(s.PasswordFile) {
		_, err := proxy.ReadPassword(s.PasswordFile)
		add(err)
	}
	if _, err := proxy.ParseListen(s.Listen); err == nil &&
		tunneldial.ValidInterfaceName(s.OverlayIf) && s.OverlayIf != s.TunnelInterface {
		add(proxy.CheckListen(s.Listen, s.OverlayIf, addrs))
	}
	return refusals
}

// parseProxyDNS is PROXY_DNS as "ip:port": an IP literal (no zone) with an
// optional port, 53 when it is left out; empty is the provider's default.
func parseProxyDNS(v, provider string) (string, error) {
	if v == "" {
		return defaultProxyDNS[provider], nil
	}
	if ip, err := netip.ParseAddr(v); err == nil && ip.Zone() == "" {
		return netip.AddrPortFrom(ip.Unmap(), 53).String(), nil
	}
	ap, err := netip.ParseAddrPort(v)
	if err != nil || ap.Addr().Zone() != "" || ap.Port() == 0 {
		return "", errors.New("PROXY_DNS must be an IP address, optionally with a port (192.0.2.53 or 192.0.2.53:53, [2001:db8::53]:53)")
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()).String(), nil
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// identity is what the proxy learns about its own process: its user and its
// effective capability set.
type identity struct {
	UID, EUID int
	CapEff    uint64
	CapKnown  bool
}

func systemIdentity() identity {
	id := identity{UID: os.Getuid(), EUID: os.Geteuid()}
	if f, err := os.Open("/proc/self/status"); err == nil {
		id.CapEff, id.CapKnown = panel.ParseCapEff(f)
		f.Close()
	}
	return id
}

// The isolation refusals, fixed text. As with the panel and the exchange,
// root is refused unless PANEL_ALLOW_ROOT is exactly "1": a rootless engine
// maps the container's uid 0 to the unprivileged user who runs it.
const (
	refuseProxyRoot       = "the proxy must not run as root (uid 0); set PANEL_USER to the uid:gid that owns state/proxy and secrets/proxy (on a rootless engine, 0:0 with PANEL_ALLOW_ROOT=1)"
	refuseProxyCaps       = "the proxy must run with no capabilities (cap_drop: [ALL]); its effective capability set is not empty"
	refuseProxyCapUnknown = "the proxy cannot read its capability set from /proc/self/status, so it cannot show it has none"
)

// checkProxyIsolation returns the refusals that apply, in a stable order.
// allowRoot is PANEL_ALLOW_ROOT from the environment ("" when unset).
func checkProxyIsolation(id identity, allowRoot string) []string {
	var refusals []string
	if (id.UID == 0 || id.EUID == 0) && allowRoot != "1" {
		refusals = append(refusals, refuseProxyRoot)
	}
	switch {
	case !id.CapKnown:
		refusals = append(refusals, refuseProxyCapUnknown)
	case id.CapEff != 0:
		refusals = append(refusals, refuseProxyCaps)
	}
	return refusals
}

// proxyMain checks the process and the settings, then serves until ctx ends.
// Exit status 0 after a clean stop, 1 for a refusal or a failure.
func proxyMain(ctx context.Context, env map[string]string, id identity, stderr io.Writer) int {
	if refusals := checkProxyIsolation(id, env["PANEL_ALLOW_ROOT"]); len(refusals) > 0 {
		for _, r := range refusals {
			fmt.Fprintf(stderr, "molebridge proxy: refusing to start: %s\n", r)
		}
		return 1
	}
	s, err := proxySettingsFrom(env)
	if refusals := proxyStartRefusals(s, err, nil); len(refusals) > 0 {
		for _, r := range refusals {
			fmt.Fprintf(stderr, "molebridge proxy: refusing to start: %s\n", r)
		}
		return 1
	}
	return runProxy(ctx, s, stderr)
}

// runProxy wires the proxy: the tunnel dialer and resolver, the relay
// proxies over them, the exit's verdict as the gate, and proxy.Serve.
func runProxy(ctx context.Context, s proxySettings, stderr io.Writer) int {
	logf := func(format string, args ...any) { fmt.Fprintf(stderr, "molebridge "+format+"\n", args...) }
	logf("proxy: every connection the proxy opens leaves through %s, or fails; it promises nothing about traffic not sent to it", s.TunnelInterface)
	applier := filepath.Join(s.StateDir, "applier")
	dialer := &tunneldial.Dialer{Interface: s.TunnelInterface}
	upstream, err := relayproxy.New(relayproxy.Config{
		Provider:    s.Provider,
		CatalogPath: filepath.Join(applier, "relays.json"),
		ResultPath:  filepath.Join(applier, "result.json"),
		Dialer:      dialer,
		Resolver:    &tunneldial.Resolver{Dialer: dialer, Server: s.DNS},
	})
	if err != nil {
		fmt.Fprintf(stderr, "molebridge proxy: refusing to start: %v\n", err)
		return 1
	}
	err = proxy.Serve(ctx, proxy.Config{
		Listen:       s.Listen,
		Interface:    s.OverlayIf,
		PasswordFile: s.PasswordFile,
		MaxConns:     s.MaxConns,
		Upstream:     upstream,
		// No kind: the exit's record states it (an overlay exit or a native
		// sidecar), and the provider is held to PROVIDER.
		Tunnel:     proxy.ResultGate(filepath.Join(applier, "result.json"), verdict.ExitConfig{Provider: s.Provider}, nil),
		Provider:   s.Provider,
		StatusPath: proxyStatusPath(s.StateDir),
		Logf:       logf,
	})
	if err != nil {
		fmt.Fprintf(stderr, "molebridge proxy: %v\n", err)
		return 1
	}
	logf("proxy: stopped")
	return 0
}

// proxyStatusPath is where the proxy writes proxy.json and status and health
// read it.
func proxyStatusPath(stateDir string) string {
	return filepath.Join(stateDir, "proxy", "proxy.json")
}
