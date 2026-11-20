//go:build drill && systemrig && linux

package exit

// The system rig: the release build of molebridge, the exit and the panel as
// separate processes, against fake Mullvad servers in network namespaces of
// one machine. Nothing leaves the machine and no real provider, relay or
// NetBird is involved.
//
//	client ──WireGuard──▶ exit (wt0 … mullvad) ──WireGuard──▶ relayA | relayB ──SNAT──▶ internet
//	                       │ eth0 (the host path)                                        ▲
//	                       └──────────────────────────────────────────────────────────────┘
//
// "internet" holds the fake Mullvad relay API and one HTTPS server for
// am.i.mullvad.net and the IP echo names; the exit's namespace resolves those
// names to them through /etc/netns/<exit>/hosts, which `ip netns exec`
// bind-mounts over /etc/hosts, and trusts the rig's certificate authority
// through SSL_CERT_FILE. The echo server answers by the source address it
// sees, and says mullvad_exit_ip only for a relay's SNAT address, so a
// verified result needs real routing through a relay. Each relay is a kernel
// WireGuard interface with a key made at run time and the exit's public key
// as its peer. The client reaches the exit over a second WireGuard pair, the
// overlay the fake NetBird creates as wt0 (the exit's netbird check and its
// switch gate require a kernel WireGuard overlay). The panel is
// `molebridge panel` as uid 65534 with no capabilities and the exit's applier
// directory mounted read-only, as Compose runs it.
//
// It needs root, kernel WireGuard, nftables, util-linux (setpriv, mount) and
// iproute2. CI runs it in the "System rig" job:
//
//	go test -count=1 -tags drill,systemrig -run TestSystemRig ./internal/exit/

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/irashack/molebridge/internal/egress"
	"github.com/irashack/molebridge/internal/nstest"
	"github.com/irashack/molebridge/internal/providers"
	"github.com/irashack/molebridge/internal/tunnel/wgnl"
)

const (
	// rigVersion is stamped into the release build the rig runs.
	rigVersion = "v0.0.0-systemrig"

	rigCheck4, rigCheck6 = "203.0.113.100", "2001:db8:f::100" // am.i.mullvad.net and the echo names
	rigAPI4, rigAPI6     = "203.0.113.101", "2001:db8:f::101" // api.mullvad.net
	rigTunnel4           = "203.0.113.2"                      // the exit's tunnel addresses
	rigTunnel6           = "2001:db8:c::2"
	rigHost4             = "198.51.100.1" // the exit's host path
	rigClient4           = "192.0.2.2"    // the client behind the overlay
	rigClient6           = "2001:db8:1::2"
	// rigClientPort is the port only the client's probes use, so the
	// internet's counters can tell them from the exit's own requests.
	rigClientPort = "8443"
	rigLocation   = "zz-tst"
	rigCity       = "Example City"
	rigCountry    = "Example"
	rigPanelUID   = 65534
)

var (
	rigOnce   sync.Once
	rigBinDir string
	rigErr    error
)

// rigBinaries builds molebridge as the release builds it
// (tools/check-reproducible.sh's flags, no drill tag) and the fake netbird as
// drillBinaries builds it.
func rigBinaries(t *testing.T) string {
	t.Helper()
	rigOnce.Do(func() {
		rigBinDir, rigErr = os.MkdirTemp("", "mb-rig-bin")
		if rigErr != nil {
			return
		}
		// The panel runs the binary as uid 65534.
		if rigErr = os.Chmod(rigBinDir, 0o755); rigErr != nil {
			return
		}
		env := append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=-mod=vendor", "GOTOOLCHAIN=local")
		for _, b := range []struct {
			pkg  string
			args []string
		}{
			{"github.com/irashack/molebridge/cmd/molebridge", []string{"build", "-trimpath", "-buildvcs=false",
				"-ldflags=-s -w -X main.version=" + rigVersion, "-o", filepath.Join(rigBinDir, "molebridge")}},
			// The failover drills' binary: the same, with the drill hooks
			// (failover_hook_drill.go shortens the policy's timings).
			{"github.com/irashack/molebridge/cmd/molebridge", []string{"build", "-tags", "drill", "-trimpath", "-buildvcs=false",
				"-ldflags=-s -w -X main.version=" + rigVersion, "-o", filepath.Join(rigBinDir, "molebridge-drill")}},
			{"github.com/irashack/molebridge/internal/exit/testdata/fakenetbird", []string{"build", "-tags", "drill",
				"-o", filepath.Join(rigBinDir, "netbird")}},
		} {
			cmd := exec.Command("go", append(b.args, b.pkg)...)
			cmd.Env = env
			if out, err := cmd.CombinedOutput(); err != nil {
				rigErr = fmt.Errorf("go build %s: %v\n%s", b.pkg, err, out)
				return
			}
		}
	})
	if rigErr != nil {
		t.Fatal(rigErr)
	}
	return rigBinDir
}

// rigRelay is one fake Mullvad relay: a namespace with a WireGuard interface
// and an SNAT to its own egress addresses.
type rigRelay struct {
	host             string // the catalog's hostname
	ns               *nstest.NS
	key              wgtypes.Key
	endpoint         string // ipv4_addr_in
	egress4, egress6 string
	link             string // its interface in "internet"
}

type systemRig struct {
	*lab
	internet *nstest.NS
	relays   []*rigRelay
	exitKey  wgtypes.Key
	roots    *x509.CertPool
	caPath   string
	cert     tls.Certificate
	// retired are the relays the fake relay API leaves out.
	retired map[string]bool
	// catalogExtra are relays the fake relay API lists besides the rig's
	// two, which no WireGuard answers for (the proxy drill's other
	// locations).
	catalogExtra []rigCatalogRelay
	// The overlay's keys, kept to key the overlay again after a restart.
	wt0Key, clientKey wgtypes.Key

	panelNS  *nstest.NS
	panelOut *syncBuf
	// The panel's settings when they differ from a single exit sharing the
	// exit's state directory (the network exchange's rig): its environment,
	// the applier directory it gets read-only, the directory it writes its
	// request in, the query naming its exit, and the request file.
	panelEnv                        []string
	panelApplier, panelOwn, panelQS string
	desiredPath                     string
	// exitExtra is added to the exit's environment.
	exitExtra []string
	// certPath and keyPath are the rig's server certificate and key as PEM
	// files, for a server the test doesn't run itself (the exchange).
	certPath, keyPath string

	mu     sync.Mutex
	served []string
	// nordAPI, when set, answers for api.nordvpn.com (the multi-provider
	// drill's fake NordVPN network); the name resolves to the check server.
	nordAPI http.Handler
	// hold, while not nil, keeps Mullvad check answers on port 443 (the
	// exit's, never the client's probes) waiting until it is closed.
	hold chan struct{}
}

// holdChecks makes the exit's Mullvad check requests wait; the returned
// function releases them.
func (r *systemRig) holdChecks() func() {
	ch := make(chan struct{})
	r.mu.Lock()
	r.hold = ch
	r.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			r.mu.Lock()
			r.hold = nil
			r.mu.Unlock()
			close(ch)
		})
	}
}

func (r *systemRig) logServed(format string, a ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.served) < 2000 {
		r.served = append(r.served, time.Now().UTC().Format("15:04:05.000 ")+fmt.Sprintf(format, a...))
	}
}

func rigKey(t *testing.T) wgtypes.Key {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func rigPrefixes(t *testing.T, cidrs ...string) []net.IPNet {
	t.Helper()
	var out []net.IPNet
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, *n)
	}
	return out
}

// wgSet configures a WireGuard interface of ns through netlink.
func wgSet(t *testing.T, ns *nstest.NS, name string, cfg wgtypes.Config) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := wgnl.Dial(ctx, ns.Fd())
	if err != nil {
		t.Fatalf("wgnl: %v", err)
	}
	defer c.Close()
	if err := c.Configure(ctx, name, cfg); err != nil {
		t.Fatalf("configure %s in %s: %v", name, ns.Name, err)
	}
}

// addrUp gives an interface its addresses and brings it up.
func addrUp(ns *nstest.NS, dev string, addrs ...string) {
	for _, a := range addrs {
		if strings.Contains(a, ":") {
			ns.IP("-6", "addr", "add", a, "dev", dev, "nodad")
		} else {
			ns.IP("addr", "add", a, "dev", dev)
		}
	}
	ns.IP("link", "set", dev, "up")
}

func rigSysctls(ns *nstest.NS) {
	ns.Sysctl("net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.default.rp_filter=0", "net.ipv6.conf.default.accept_dad=0",
		"net.ipv6.conf.all.disable_ipv6=0", "net.ipv6.conf.default.disable_ipv6=0")
}

// newSystemRig builds the namespaces, the relays, the fake servers and the
// exit's state, configuration and name overrides. Nothing runs yet.
func newSystemRig(t *testing.T) *systemRig {
	t.Helper()
	skipWithoutWireGuard(t)
	for _, tool := range []string{"nft", "setpriv", "mount", "sh"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("the system rig needs %s: %v", tool, err)
		}
	}
	bin := rigBinaries(t)
	// Not t.TempDir: that is mode 0700, and the panel runs as uid 65534.
	dir, err := os.MkdirTemp("", "mb-rig")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	l := &lab{t: t, dir: dir, bin: filepath.Join(bin, "molebridge")}
	l.client = nstest.New(t, "client")
	l.exit = nstest.New(t, "exit")
	l.outside = nstest.New(t, "internet")
	r := &systemRig{lab: l, internet: l.outside, exitKey: rigKey(t)}
	in := r.internet
	for _, ns := range []*nstest.NS{l.client, l.exit, in} {
		rigSysctls(ns)
	}
	in.Sysctl("net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1")

	// The exit's host path.
	l.exit.Veth("eth0", in, "exit0")
	addrUp(l.exit, "eth0", rigHost4+"/30", "2001:db8:2::1/64")
	addrUp(in, "exit0", "198.51.100.2/30", "2001:db8:2::2/64")
	l.exit.IP("route", "add", "default", "via", "198.51.100.2")
	l.exit.IP("-6", "route", "add", "default", "via", "2001:db8:2::2")
	l.exit.Sysctl("net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1", "net.ipv4.icmp_errors_use_inbound_ifaddr=1")

	// The servers' addresses.
	for _, a := range []string{rigCheck4 + "/32", rigAPI4 + "/32", rigCheck6 + "/128", rigAPI6 + "/128"} {
		addrUp(in, "lo", a)
	}

	// The relays.
	for _, s := range []struct{ label, host, link, v4, gw4, v6, gw6, eg4, eg6 string }{
		{"relaya", "zz-tst-wg-001", "relaya0", "198.51.100.5", "198.51.100.6", "2001:db8:5::1", "2001:db8:5::2", "203.0.113.10", "2001:db8:a::10"},
		{"relayb", "zz-tst-wg-002", "relayb0", "198.51.100.9", "198.51.100.10", "2001:db8:9::1", "2001:db8:9::2", "203.0.113.20", "2001:db8:b::20"},
	} {
		rl := &rigRelay{host: s.host, ns: nstest.New(t, s.label), key: rigKey(t), endpoint: s.v4, egress4: s.eg4, egress6: s.eg6, link: s.link}
		ns := rl.ns
		rigSysctls(ns)
		ns.Sysctl("net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1")
		ns.Veth("eth0", in, s.link)
		addrUp(ns, "eth0", s.v4+"/30", s.v6+"/64")
		addrUp(in, s.link, s.gw4+"/30", s.gw6+"/64")
		ns.IP("route", "add", "default", "via", s.gw4)
		ns.IP("-6", "route", "add", "default", "via", s.gw6)
		in.IP("route", "add", s.eg4+"/32", "via", s.v4)
		in.IP("-6", "route", "add", s.eg6+"/128", "via", s.v6)
		ns.IP("link", "add", "wg0", "type", "wireguard")
		port := 51820
		wgSet(t, ns, "wg0", wgtypes.Config{PrivateKey: &rl.key, ListenPort: &port, ReplacePeers: true, Peers: []wgtypes.PeerConfig{{
			PublicKey: r.exitKey.PublicKey(), ReplaceAllowedIPs: true,
			// The tunnel addresses, and the overlay's: the fake NetBird does
			// not masquerade the client's traffic as NetBird's routing peer would.
			AllowedIPs: rigPrefixes(t, rigTunnel4+"/32", rigTunnel6+"/128", "192.0.2.0/24", "2001:db8:1::/64"),
		}}})
		addrUp(ns, "wg0", "203.0.113.1/32", "2001:db8:c::1/128")
		for _, c := range []string{rigTunnel4 + "/32", "192.0.2.0/24"} {
			ns.IP("route", "add", c, "dev", "wg0")
		}
		for _, c := range []string{rigTunnel6 + "/128", "2001:db8:1::/64"} {
			ns.IP("-6", "route", "add", c, "dev", "wg0")
		}
		nat := `table inet relay {
  chain post {
    type nat hook postrouting priority srcnat; policy accept;
    iifname "wg0" oifname "eth0" meta nfproto ipv4 snat ip to ` + s.eg4 + `
    iifname "wg0" oifname "eth0" meta nfproto ipv6 snat ip6 to ` + s.eg6 + `
  }
}
`
		if out, err := ns.ExecInput(nat, "nft", "-f", "-"); err != nil {
			t.Fatalf("nft in %s: %v\n%s", s.label, err, out)
		}
		r.relays = append(r.relays, rl)
	}

	// What reaches the internet: anything from the client by the host path
	// (unmasqueraded, or a probe port from the exit's own address), and the
	// client's probes by each relay (nord0 is the multi-provider drill's
	// fake NordVPN server, absent from the other drills).
	counters := `table inet rig {
  counter leak {}
  counter via_relaya0 {}
  counter via_relayb0 {}
  counter via_nord0 {}
  chain pre {
    type filter hook prerouting priority raw; policy accept;
    ip saddr 192.0.2.0/24 counter name leak
    ip6 saddr 2001:db8:1::/64 counter name leak
    iifname "exit0" tcp dport ` + rigClientPort + ` counter name leak
    iifname "relaya0" tcp dport ` + rigClientPort + ` counter name via_relaya0
    iifname "relayb0" tcp dport ` + rigClientPort + ` counter name via_relayb0
    iifname "nord0" tcp dport ` + rigClientPort + ` counter name via_nord0
  }
}
`
	if out, err := in.ExecInput(counters, "nft", "-f", "-"); err != nil {
		t.Fatalf("nft: %v\n%s", err, out)
	}

	// The client: a WireGuard peer of the overlay, over a link of its own.
	l.exit.Veth("under0", l.client, "under0")
	addrUp(l.exit, "under0", "198.51.100.13/30")
	addrUp(l.client, "under0", "198.51.100.14/30")

	l.stateDir, l.runDir, l.nbDir = l.path("state"), l.path("run"), l.path("netbird")
	l.fakeDir, l.confDir = l.path("fake"), l.path("wg_confs")
	for _, d := range []string{l.stateDir, filepath.Join(l.stateDir, "applier"), l.runDir, l.nbDir, l.fakeDir, l.confDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// The exit starts on relay A, as prepare-config would have written it.
	a := r.relays[0]
	conf := "[Interface]\nPrivateKey = " + r.exitKey.String() + "\nAddress = " + rigTunnel4 + "/32," + rigTunnel6 + "/128\nMTU = 1420\nTable = off\n" +
		"PostUp = ip route replace default dev %i table 51821; ip -6 route replace default dev %i table 51821\n" +
		"PreDown = ip route del default dev %i table 51821; ip -6 route del default dev %i table 51821\n\n" +
		"[Peer]\nPublicKey = " + a.key.PublicKey().String() + "\nEndpoint = " + a.endpoint + ":51820\nAllowedIPs = 0.0.0.0/0,::/0\n"
	if err := os.WriteFile(filepath.Join(l.confDir, dExit+".conf"), []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}

	r.writeHosts()
	r.makeCerts()
	r.startServers()
	return r
}

// rigNames are the names the exit asks for, with the family each resolves
// in: the relay API (both), Mullvad's per-family check names (the applier's
// egress check; am.i.mullvad.net itself has no AAAA record) and the IP echo
// services of internal/egress.
func rigNames(t *testing.T) map[string][]int {
	t.Helper()
	names := map[string][]int{"am.i.mullvad.net": {4}, "ipv4.am.i.mullvad.net": {4}, "ipv6.am.i.mullvad.net": {6}}
	host := func(raw string) string {
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" {
			t.Fatalf("URL %q", raw)
		}
		return u.Hostname()
	}
	names[host(providers.MullvadRelaysURL)] = []int{4, 6}
	// The fake NordVPN network's API, IPv4 only like NordVPN's tunnel; only
	// the multi-provider drill serves it.
	names[host(providers.NordServersURL)] = []int{4}
	for family, urls := range egress.EchoURLs {
		for _, u := range urls {
			names[host(u)] = append(names[host(u)], family)
		}
	}
	return names
}

// writeHosts writes /etc/netns/<exit>/hosts, which `ip netns exec`
// bind-mounts over /etc/hosts for the exit and its children.
func (r *systemRig) writeHosts() {
	t := r.t
	dir := filepath.Join("/etc/netns", r.exit.Name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	var b strings.Builder
	b.WriteString("127.0.0.1 localhost\n::1 localhost\n")
	api := providers.MullvadRelaysURL
	for name, families := range rigNames(t) {
		for _, f := range families {
			addr := map[int]string{4: rigCheck4, 6: rigCheck6}[f]
			if strings.Contains(api, "//"+name+"/") {
				addr = map[int]string{4: rigAPI4, 6: rigAPI6}[f]
			}
			fmt.Fprintf(&b, "%s %s\n", addr, name)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "hosts"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

// makeCerts makes a certificate authority and one server certificate for
// every name and server address, and writes the authority for SSL_CERT_FILE.
func (r *systemRig) makeCerts() {
	t := r.t
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Molebridge system rig CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dns := []string{"echo.example.net", rigExchangeName}
	for name := range rigNames(t) {
		dns = append(dns, name)
	}
	var ips []net.IP
	for _, a := range []string{rigCheck4, rigCheck6, rigAPI4, rigAPI6} {
		ips = append(ips, net.ParseIP(a))
	}
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "echo.example.net"},
		DNSNames: dns, IPAddresses: ips, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	r.cert = tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	r.certPath, r.keyPath = r.path("server.pem"), r.path("server-key.pem")
	if err := os.WriteFile(r.certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r.keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	r.roots = x509.NewCertPool()
	r.roots.AddCert(ca)
	r.caPath = r.path("ca.pem")
	if err := os.WriteFile(r.caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o644); err != nil {
		t.Fatal(err)
	}
}

// relayBySNAT is the relay whose egress address a source is, or nil.
func (r *systemRig) relayBySNAT(a netip.Addr) *rigRelay {
	for _, rl := range r.relays {
		if a.String() == rl.egress4 || a.String() == rl.egress6 {
			return rl
		}
	}
	return nil
}

// rigCatalogRelay is a relay the fake relay API lists without a WireGuard
// relay behind it.
type rigCatalogRelay struct {
	host, location, city, country, endpoint string
	key                                     wgtypes.Key
}

// catalogJSON is the fake relay API's answer: every relay not retired, and
// the extra ones.
func (r *systemRig) catalogJSON() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	var relays []any
	entry := func(host, location, endpoint string, key wgtypes.Key) map[string]any {
		return map[string]any{
			"hostname": host, "location": location, "active": true, "owned": true, "stboot": true,
			"provider": "Example Hosting", "ipv4_addr_in": endpoint, "public_key": key.PublicKey().String(),
		}
	}
	locations := map[string]any{rigLocation: map[string]any{"city": rigCity, "country": rigCountry}}
	for _, rl := range r.relays {
		if r.retired[rl.host] {
			continue
		}
		relays = append(relays, entry(rl.host, rigLocation, rl.endpoint, rl.key))
	}
	for _, x := range r.catalogExtra {
		relays = append(relays, entry(x.host, x.location, x.endpoint, x.key))
		locations[x.location] = map[string]any{"city": x.city, "country": x.country}
	}
	catalog, err := json.Marshal(map[string]any{
		"locations": locations,
		"wireguard": map[string]any{"relays": relays},
	})
	if err != nil {
		r.t.Fatal(err)
	}
	return catalog
}

// retire takes a relay out of the fake relay API's list, or puts it back.
func (r *systemRig) retire(host string, retired bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.retired == nil {
		r.retired = map[string]bool{}
	}
	r.retired[host] = retired
}

func (r *systemRig) startServers() {
	relayPath := strings.TrimPrefix(providers.MullvadRelaysURL, "https://api.mullvad.net")
	api := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.logServed("api %s %s%s from %s", req.Method, req.Host, req.URL.Path, req.RemoteAddr)
		if req.URL.Path != relayPath {
			http.NotFound(w, req)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(r.catalogJSON())
	})
	check := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		nord := r.nordAPI
		r.mu.Unlock()
		if nord != nil && req.Host == "api.nordvpn.com" {
			nord.ServeHTTP(w, req)
			return
		}
		host, _, _ := net.SplitHostPort(req.RemoteAddr)
		src, err := netip.ParseAddr(host)
		if err != nil {
			http.Error(w, "bad source", http.StatusInternalServerError)
			return
		}
		src = src.Unmap()
		rl := r.relayBySNAT(src)
		r.logServed("check %s%s from %s (relay %v)", req.Host, req.URL.Path, src, rl != nil)
		if local, _ := req.Context().Value(http.LocalAddrContextKey).(net.Addr); local != nil && req.URL.Path == "/json" &&
			!strings.HasSuffix(local.String(), ":"+rigClientPort) {
			r.mu.Lock()
			hold := r.hold
			r.mu.Unlock()
			if hold != nil {
				r.logServed("check held")
				select {
				case <-hold:
				case <-req.Context().Done():
					return
				}
			}
		}
		if req.URL.Path != "/json" {
			// An IP echo service: the caller's address as plain text.
			fmt.Fprintln(w, src.String())
			return
		}
		answer := map[string]any{"ip": src.String(), "city": rigCity, "country": rigCountry, "mullvad_exit_ip": rl != nil}
		if rl != nil {
			answer["mullvad_exit_ip_hostname"] = rl.host
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(answer)
	})
	for _, s := range []struct {
		addr string
		h    http.Handler
	}{
		{net.JoinHostPort(rigAPI4, "443"), api}, {net.JoinHostPort(rigAPI6, "443"), api},
		{net.JoinHostPort(rigCheck4, "443"), check}, {net.JoinHostPort(rigCheck6, "443"), check},
		{net.JoinHostPort(rigCheck4, rigClientPort), check}, {net.JoinHostPort(rigCheck6, rigClientPort), check},
	} {
		r.serve(s.addr, s.h)
	}
}

// serve runs an HTTPS server in the test process on a listener opened in
// "internet".
func (r *systemRig) serve(addr string, h http.Handler) {
	var ln net.Listener
	if err := r.internet.Do(func() error {
		var err error
		ln, err = net.Listen("tcp", addr)
		return err
	}); err != nil {
		r.t.Fatalf("listen %s: %v", addr, err)
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second, ErrorLog: log.New(io.Discard, "", 0),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{r.cert}, MinVersion: tls.VersionTLS12}}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	r.t.Cleanup(func() { _ = srv.Close() })
}

// nsClient is an HTTP client whose connections are opened in ns.
func nsClient(ns *nstest.NS, roots *x509.CertPool, serverName string, timeout time.Duration) *http.Client {
	d := &net.Dialer{Timeout: timeout}
	tr := &http.Transport{
		Proxy:             nil,
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{RootCAs: roots, ServerName: serverName, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var c net.Conn
			err := ns.Do(func() error {
				var err error
				c, err = d.DialContext(ctx, network, addr)
				return err
			})
			return c, err
		},
	}
	return &http.Client{Transport: tr, Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// start runs the release build's exit with the rig's environment.
func (r *systemRig) start() *exitProc {
	var env []string
	for _, kv := range r.env("SSL_CERT_FILE=" + r.caPath) {
		if !strings.HasPrefix(kv, "PATH=") {
			env = append(env, kv)
		}
	}
	env = append(env, "PATH="+rigBinDir+":/usr/sbin:/usr/bin:/sbin:/bin")
	env = append(env, r.exitExtra...)
	p := r.startEnv(env)
	r.t.Cleanup(func() {
		if r.t.Failed() {
			r.mu.Lock()
			r.t.Logf("fake servers:\n%s", strings.Join(r.served, "\n"))
			r.mu.Unlock()
			if r.panelOut != nil {
				r.t.Logf("panel output:\n%s", r.panelOut.String())
			}
			for _, rl := range r.relays {
				out, _ := rl.ns.Exec("wg", "show")
				r.t.Logf("%s wg show:\n%s", rl.host, out)
			}
			out, _ := r.exit.Exec("wg", "show")
			r.t.Logf("exit wg show:\n%s", out)
		}
	})
	return p
}

// connectOverlay keys the overlay interface the fake NetBird created and the
// client's end of it, as NetBird would have connected a peer.
func (r *systemRig) connectOverlay() {
	t := r.t
	r.wt0Key, r.clientKey = rigKey(t), rigKey(t)
	wt0Key, clientKey := r.wt0Key, r.clientKey
	exitPort, clientPort, keepalive := 51830, 51831, 5*time.Second
	r.keyOverlay()

	c := r.client
	c.IP("link", "add", "wgc", "type", "wireguard")
	wgSet(t, c, "wgc", wgtypes.Config{PrivateKey: &clientKey, ListenPort: &clientPort, ReplacePeers: true, Peers: []wgtypes.PeerConfig{{
		PublicKey: wt0Key.PublicKey(), Endpoint: &net.UDPAddr{IP: net.ParseIP("198.51.100.13"), Port: exitPort},
		ReplaceAllowedIPs: true, AllowedIPs: rigPrefixes(t, "0.0.0.0/0", "::/0"), PersistentKeepaliveInterval: &keepalive,
	}}})
	addrUp(c, "wgc", rigClient4+"/24", rigClient6+"/64")
	c.IP("route", "add", "default", "dev", "wgc")
	c.IP("-6", "route", "add", "default", "dev", "wgc")
}

// keyOverlay keys the exit's end of the overlay with the keys connectOverlay
// made: once, and again after the exit restarts and the fake NetBird
// creates the interface anew.
func (r *systemRig) keyOverlay() {
	t := r.t
	exitPort, clientPort, keepalive := 51830, 51831, 5*time.Second
	wgSet(t, r.exit, dOverlay, wgtypes.Config{PrivateKey: &r.wt0Key, ListenPort: &exitPort, ReplacePeers: true, Peers: []wgtypes.PeerConfig{{
		PublicKey: r.clientKey.PublicKey(), Endpoint: &net.UDPAddr{IP: net.ParseIP("198.51.100.14"), Port: clientPort},
		ReplaceAllowedIPs: true, AllowedIPs: rigPrefixes(t, rigClient4+"/32", rigClient6+"/128"), PersistentKeepaliveInterval: &keepalive,
	}}})
	r.exit.IP("addr", "add", "192.0.2.1/24", "dev", dOverlay)
	r.exit.IP("-6", "addr", "add", "2001:db8:1::1/64", "dev", dOverlay, "nodad")
	r.exit.IP("link", "set", dOverlay, "up")
}

// startPanel runs `molebridge panel` in a namespace of its own, as uid 65534
// with no capabilities, the applier directory bind-mounted read-only over
// itself and the panel directory its own, as Compose mounts them.
func (r *systemRig) startPanel() {
	t := r.t
	panelDir, applierDir := r.panelOwn, r.panelApplier
	if panelDir == "" {
		panelDir, applierDir = filepath.Join(r.stateDir, "panel"), filepath.Join(r.stateDir, "applier")
	}
	if err := os.MkdirAll(panelDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(panelDir, rigPanelUID, rigPanelUID); err != nil {
		t.Fatal(err)
	}
	if r.panelNS == nil {
		r.panelNS = nstest.New(t, "panel")
	}
	// `ip netns exec` runs it in a mount namespace of its own, so the
	// read-only bind stays the panel's.
	script := `mount --bind "$1" "$1" && mount -o remount,bind,ro "$1" &&
exec setpriv --reuid=` + fmt.Sprint(rigPanelUID) + ` --regid=` + fmt.Sprint(rigPanelUID) +
		` --clear-groups --inh-caps=-all --bounding-set=-all --no-new-privs "$2" panel`
	cmd := exec.Command("ip", "netns", "exec", r.panelNS.Name, "sh", "-c", script, "sh", applierDir, r.bin)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "STATE_DIR=" + r.stateDir, "PROVIDER=mullvad", "EXIT_KIND=overlay", "TZ=UTC"}
	if r.panelEnv != nil {
		cmd.Env = r.panelEnv
	}
	r.panelOut = &syncBuf{}
	cmd.Stdout, cmd.Stderr = r.panelOut, r.panelOut
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	t.Cleanup(func() {
		select {
		case <-done:
		default:
			killTree(r.panelNS)
			<-done
		}
	})
	client := nsClient(r.panelNS, nil, "", 5*time.Second)
	r.waitFor(30*time.Second, "the panel to answer", func() bool {
		select {
		case <-done:
			t.Fatalf("the panel stopped:\n%s", r.panelOut.String())
		default:
		}
		resp, err := client.Get("http://127.0.0.1:8080/healthz")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == 200
	})
	if strings.Contains(r.panelOut.String(), "self-check is switched off") {
		t.Fatal("the panel ran without its isolation check")
	}
}

var rigHidden = regexp.MustCompile(`<input type="hidden" name="([a-z_]+)" value="([^"]*)">`)

// panelGet fetches a panel path and returns the status and body.
func (r *systemRig) panelGet(path string) (int, []byte, *http.Response) {
	r.t.Helper()
	resp, err := nsClient(r.panelNS, nil, "", 10*time.Second).Get("http://127.0.0.1:8080" + path)
	if err != nil {
		r.t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body, resp
}

// panelPayload is the panel's /api/status: desired, result and verdict.
func (r *systemRig) panelPayload() map[string]any {
	r.t.Helper()
	code, body, _ := r.panelGet("/api/status" + r.panelQS)
	var payload map[string]any
	if code != 200 || json.Unmarshal(body, &payload) != nil {
		r.t.Fatalf("/api/status: %d %s", code, body)
	}
	return payload
}

// panelStatus is the panel's /api/status verdict.
func (r *systemRig) panelStatus() map[string]any {
	r.t.Helper()
	v, _ := r.panelPayload()["verdict"].(map[string]any)
	return v
}

// panelResult is the record the panel reads, as /api/status shows it.
func (r *systemRig) panelResult() map[string]any {
	r.t.Helper()
	res, _ := r.panelPayload()["result"].(map[string]any)
	return res
}

// panelVerified is whether the panel shows the exit ok on rl with requestID
// verified, from the record it reads.
func (r *systemRig) panelVerified(rl *rigRelay, requestID string) bool {
	r.t.Helper()
	payload := r.panelPayload()
	res, _ := payload["result"].(map[string]any)
	v, _ := payload["verdict"].(map[string]any)
	sel, _ := res["selection"].(map[string]any)
	return v["state"] == "ok" && res["status"] == "ok" && res["server"] == rl.host && res["request_id"] == requestID && sel["outcome"] == "verified"
}

// waitPanelVerified waits for panelVerified.
func (r *systemRig) waitPanelVerified(rl *rigRelay, requestID string, d time.Duration) {
	r.t.Helper()
	r.waitFor(d, "the panel to show "+rl.host+" verified (request "+requestID+")", func() bool { return r.panelVerified(rl, requestID) })
}

// panelPost submits the page's server form as a browser would: the page's
// CSRF cookie and the form's hidden fields, with server set to host (a
// server's button, or Retry, which names the server the same way). It
// returns the answer's status and body, when it came, and the page it posted
// from.
func (r *systemRig) panelPost(host string) (int, string, time.Time, string) {
	t := r.t
	code, page, resp := r.panelGet("/" + r.panelQS)
	var nonce string
	for _, c := range resp.Cookies() {
		if c.Name == "csrf_nonce" {
			nonce = c.Value
		}
	}
	form := url.Values{}
	if start := bytes.Index(page, []byte(`id="select-form">`)); start >= 0 {
		for _, m := range rigHidden.FindAllSubmatch(page[start:], 3) {
			form.Set(string(m[1]), html.UnescapeString(string(m[2])))
		}
	}
	if code != 200 || nonce == "" || form.Get("csrf_token") == "" {
		t.Fatalf("panel page: %d, nonce %q, form %v", code, nonce, form)
	}
	form.Set("server", host)
	req, err := http.NewRequest("POST", "http://127.0.0.1:8080/select", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_nonce", Value: nonce})
	resp, err = nsClient(r.panelNS, nil, "", 10*time.Second).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp.StatusCode, string(body), time.Now(), string(page)
}

// panelSwitch asks the panel for a server and requires the 303. It returns
// the request id the panel wrote and when the post was answered.
func (r *systemRig) panelSwitch(host string) (string, time.Time) {
	t := r.t
	code, body, at, _ := r.panelPost(host)
	if code != http.StatusSeeOther {
		t.Fatalf("switch to %s: %d %s", host, code, body)
	}
	return r.requestID(host), at
}

// requestID is the request id of the panel's desired.json, which must name
// host.
func (r *systemRig) requestID(host string) string {
	t := r.t
	path := r.desiredPath
	if path == "" {
		path = filepath.Join(r.stateDir, "panel", "desired.json")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var desired map[string]any
	if err := json.Unmarshal(raw, &desired); err != nil || desired["server"] != host {
		t.Fatalf("desired.json: %s", raw)
	}
	id, _ := desired["request_id"].(string)
	return id
}

// bringUp starts the exit, keys the overlay, starts the panel and waits for
// the exit to be verified on relay A.
func (r *systemRig) bringUp() *exitProc {
	p := r.start()
	r.waitReady(p)
	r.connectOverlay()
	r.startPanel()
	started := time.Now()
	r.waitVerified(p, r.relays[0], "", 120*time.Second)
	r.t.Logf("verified on %s %v after NetBird was up; selection %s", r.relays[0].host, time.Since(started).Round(time.Millisecond), jsonText(r.result()["selection"]))
	return p
}

// waitVerified waits for verified (see verified) while the exit runs.
func (r *systemRig) waitVerified(p *exitProc, rl *rigRelay, requestID string, d time.Duration) {
	r.t.Helper()
	r.waitFor(d, "result.json verified on "+rl.host+" (request "+requestID+")", func() bool {
		if !p.running() {
			r.t.Fatalf("the exit stopped (%d):\n%s", p.code, p.out.String())
		}
		return r.verified(rl, requestID)
	})
}

// verified reports whether result.json is ok on host with a provider-tier
// egress pass from host's own addresses, for requestID when it is set.
func (r *systemRig) verified(rl *rigRelay, requestID string) bool {
	res := r.result()
	if res == nil || res["status"] != "ok" || res["server"] != rl.host {
		return false
	}
	if requestID != "" {
		sel, _ := res["selection"].(map[string]any)
		if res["request_id"] != requestID || sel["outcome"] != "verified" {
			return false
		}
	}
	checks, _ := res["checks"].(map[string]any)
	eg, _ := checks["egress"].(map[string]any)
	if eg["state"] != "pass" || eg["server"] != rl.host || eg["tier"] != "provider" {
		return false
	}
	ips, _ := res["egress_ips"].(map[string]any)
	return ips["4"] == rl.egress4 && ips["6"] == rl.egress6
}

// probe asks the internet's echo server, from the client, which address its
// traffic in one family comes from.
func (r *systemRig) probe(client *http.Client, family int) (string, bool, error) {
	addr := map[int]string{4: rigCheck4, 6: rigCheck6}[family]
	resp, err := client.Get("https://" + net.JoinHostPort(addr, rigClientPort) + "/json")
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()
	var answer struct {
		IP   string `json:"ip"`
		Exit bool   `json:"mullvad_exit_ip"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&answer); err != nil {
		return "", false, err
	}
	return answer.IP, answer.Exit, nil
}

// clientVia waits until the client's traffic in both families leaves by rl.
func (r *systemRig) clientVia(rl *rigRelay, d time.Duration) time.Time {
	r.t.Helper()
	client := nsClient(r.client, r.roots, "echo.example.net", 3*time.Second)
	deadline := time.Now().Add(d)
	for {
		var last []string
		ok := true
		for _, f := range []int{4, 6} {
			ip, exit, err := r.probe(client, f)
			last = append(last, fmt.Sprintf("IPv%d: %s mullvad_exit_ip=%v err=%v", f, ip, exit, err))
			want := map[int]string{4: rl.egress4, 6: rl.egress6}[f]
			ok = ok && err == nil && exit && ip == want
		}
		if ok {
			return time.Now()
		}
		if time.Now().After(deadline) {
			r.t.Fatalf("the client's traffic did not leave by %s within %v; last: %s", rl.host, d, strings.Join(last, "; "))
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// probeLoop keeps the client probing both families until stop closes, and
// records which relay each answer came by ("" for a failure).
type probeSample struct {
	at  time.Time
	via string
}

func (r *systemRig) probeLoop(stop <-chan struct{}) <-chan []probeSample {
	out := make(chan []probeSample, 1)
	client := nsClient(r.client, r.roots, "echo.example.net", 2*time.Second)
	go func() {
		var samples []probeSample
		for {
			select {
			case <-stop:
				out <- samples
				return
			default:
			}
			for _, f := range []int{4, 6} {
				ip, _, err := r.probe(client, f)
				via := ""
				if a, perr := netip.ParseAddr(ip); err == nil && perr == nil {
					if rl := r.relayBySNAT(a); rl != nil {
						via = rl.host
					} else {
						via = "other:" + ip
					}
				}
				samples = append(samples, probeSample{time.Now(), via})
			}
			time.Sleep(200 * time.Millisecond)
		}
	}()
	return out
}

// counted reads one of the internet's counters.
func (r *systemRig) counted(name string) int {
	r.t.Helper()
	out, err := r.internet.Exec("nft", "list", "counter", "inet", "rig", name)
	if err != nil {
		r.t.Fatalf("nft: %v\n%s", err, out)
	}
	fields := strings.Fields(out)
	for i, f := range fields {
		if f == "packets" && i+1 < len(fields) {
			var n int
			fmt.Sscan(fields[i+1], &n)
			return n
		}
	}
	return 0
}

// jsonText is v as compact JSON for a log line.
func jsonText(v any) string {
	var b bytes.Buffer
	_ = json.NewEncoder(&b).Encode(v)
	return strings.TrimSpace(b.String())
}
