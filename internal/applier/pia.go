package applier

// PIA: a key registered per server, a tunnel address per server, and an
// optional forwarded port (applier/pia.py).
//
// PIA has no account-wide WireGuard key. Each connection asks the chosen
// server to accept the interface's public key (addKey, authenticated by a
// token that the account login mints) and answers with that server's key and a
// tunnel address valid only there. The applier therefore holds the PIA login
// and, on a switch, sets the interface address and the priority-94
// return-path rule as well as the peer. The private key still never leaves the
// tunnel interface: registration needs only the public key.
//
// The login, token and port-forwarding payload travel only in HTTPS requests
// built in memory, never in argv, logs or state files (netx errors carry no
// URL). Registration and port forwarding verify the server's TLS name against
// PIA's bundled CA, so a tampered region list can name an address but not
// impersonate a PIA server.

import (
	"bytes"
	"context"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"errors"
	"io"
	"math/rand/v2"
	"mime/multipart"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/irashack/molebridge/internal/jsonfile"
	"github.com/irashack/molebridge/internal/netx"
	"github.com/irashack/molebridge/internal/providers"
	"github.com/irashack/molebridge/internal/validate"
)

const (
	PIATokenURL = "https://www.privateinternetaccess.com/api/client/v2/token"
	// PIAStatusURL answers from PIA's side whether the caller's address is a
	// PIA exit.
	PIAStatusURL   = "https://www.privateinternetaccess.com/api/client/status"
	addKeyPort     = 1337
	forwardAPIPort = 19999
	// TokenMaxAgeSec: PIA tokens last 24 hours; a new one is minted well before
	// that.
	TokenMaxAgeSec = 12 * 60 * 60
	// BindIntervalSec: PIA drops a forwarded port that is not re-bound within
	// 15 minutes.
	BindIntervalSec  = 10 * 60
	ForwardRetrySec  = 60
	secretMaxBytes   = 512
	piaAnswerMaxSize = 16384
)

// SignatureMaxAgeSec: a signature is valid for about two months; renew it
// long before.
const SignatureMaxAgeSec = 7 * 24 * 60 * 60

//go:embed pia-ca.rsa.4096.crt
var piaCA []byte

var (
	piaCNRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,62}$`)
	// privateV4 are the tunnel-internal addresses PIA assigns; anything else is
	// refused.
	privateV4 = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16")}
)

// validToken is TOKEN_RE of applier/pia.py, [A-Za-z0-9._~+/=-]{1,1024} in
// full: Go's regexp stops at repeat counts of 1000.
func validToken(s string) bool {
	if len(s) < 1 || len(s) > 1024 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("._~+/=-", c) >= 0) {
			return false
		}
	}
	return true
}

// PIARootCAs is PIA's own certificate authority, the only one registration and
// port forwarding trust.
func PIARootCAs() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(piaCA)
	return pool
}

// PIAConfig are the PIA provider's settings.
type PIAConfig struct {
	// SecretsDir holds the username and password files (/run/secrets/pia).
	SecretsDir string
	// PortForward turns the optional forwarded port on; ForwardTarget is the
	// overlay address it reaches, empty for a sidecar's namespace.
	PortForward   bool
	ForwardTarget string
	// Choose picks the index of the region's server to register on; random when
	// nil.
	Choose func(n int) int
	// RootCAs replaces PIA's certificate authority (tests only).
	RootCAs *x509.CertPool
}

// parseFlag reads an on/off setting.
func parseFlag(value, name string) (bool, error) {
	word := strings.ToLower(strings.TrimFunc(value, validate.IsSpace))
	switch word {
	case "1", "true", "on", "yes":
		return true, nil
	case "", "0", "false", "off", "no":
		return false, nil
	}
	return false, errors.New(name + " must be on or off")
}

// NewPIAFromEnv is the PIA provider for this exit's settings (PIA_SECRETS_DIR,
// PIA_PORT_FORWARD, PIA_PORT_FORWARD_TARGET).
func NewPIAFromEnv(exit Exit, getenv func(string) string) (Provider, error) {
	forward, err := parseFlag(getenv("PIA_PORT_FORWARD"), "PIA_PORT_FORWARD")
	if err != nil {
		return nil, err
	}
	target := getenv("PIA_PORT_FORWARD_TARGET")
	if exit.Kind == "sidecar" {
		if target != "" {
			return nil, errors.New("PIA_PORT_FORWARD_TARGET is for the overlay kind; a sidecar's forwarded port reaches the namespace itself")
		}
	} else if forward {
		// A forwarded port is useful only when it reaches a device, and a port
		// with no destination would answer from the exit namespace.
		address, perr := netip.ParseAddr(target)
		overlay, oerr := netip.ParsePrefix(exit.Overlay)
		if !validate.ValidIPv4(target) || perr != nil || oerr != nil || !overlay.Contains(address) {
			return nil, errors.New("PIA_PORT_FORWARD needs PIA_PORT_FORWARD_TARGET, an overlay IPv4 address")
		}
	} else if target != "" {
		return nil, errors.New("PIA_PORT_FORWARD_TARGET is set but PIA_PORT_FORWARD is off")
	}
	dir := getenv("PIA_SECRETS_DIR")
	if dir == "" {
		dir = "/run/secrets/pia"
	}
	return NewPIA(PIAConfig{SecretsDir: dir, PortForward: forward, ForwardTarget: target}), nil
}

// forwardState is one forwarded port's signature and whether it is bound.
type forwardState struct {
	serverKey, payload, signature string
	port                          int
	signedAt                      float64
	bound                         bool
}

type piaProvider struct {
	BaseProvider
	cfg PIAConfig

	token             string
	tokenAt           float64
	lastResult        *Record
	forward           *forwardState
	forwardError      string
	nextForward       float64
	nftPort           int
	forwardReconciled bool
	guardInstalled    bool
}

// NewPIA is the PIA provider.
func NewPIA(cfg PIAConfig) Provider {
	if cfg.Choose == nil {
		cfg.Choose = rand.IntN
	}
	if cfg.RootCAs == nil {
		cfg.RootCAs = PIARootCAs()
	}
	return &piaProvider{BaseProvider: BaseProvider{Name: "pia"}, cfg: cfg}
}

// tunnelPath is state/applier/tunnel.json.
func tunnelPath(a *Applier) string { return filepath.Join(a.directory, "tunnel.json") }

// MakeCatalog: with port forwarding on, only forwarding regions are selectable.
func (p *piaProvider) MakeCatalog(a *Applier) Catalog {
	return NativeCatalog(a.directory, "pia", p.cfg.PortForward, a.wall)
}

// ResultDefaults: the forwarded port, once bound.
func (p *piaProvider) ResultDefaults() validate.Obj {
	var port any
	if p.forward != nil && p.forward.bound {
		port = p.forward.port
	}
	fields := validate.Members("port_forward", p.cfg.PortForward, "forwarded_port", port)
	if p.cfg.PortForward {
		fields = append(fields, validate.Pair{Key: "port_forward_error", Value: orNull(p.forwardError)})
	}
	return fields
}

// Published remembers the last record, which port forwarding is judged by.
func (p *piaProvider) Published(rec *Record) { p.lastResult = rec }

// NoPeerMessage asks for a region on a fresh exit.
func (p *piaProvider) NoPeerMessage(a *Applier, keys []string) string {
	if len(keys) == 0 && a.target == nil {
		return "No PIA region is registered yet; choose one in the panel."
	}
	return p.BaseProvider.NoPeerMessage(a, keys)
}

// -- secrets ---------------------------------------------------------------------------

// readSecret reads one credential per file; one trailing newline is tolerated,
// nothing else. A file that cannot be opened or read is an I/O failure.
func readSecret(path string) (string, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", wrapIO(err)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, secretMaxBytes+1))
	if err != nil {
		return "", wrapIO(err)
	}
	if len(raw) > secretMaxBytes {
		return "", errors.New("credential file too large")
	}
	if !utf8.Valid(raw) {
		return "", errors.New("invalid credential file")
	}
	value := string(raw)
	value = strings.TrimSuffix(value, "\n")
	value = strings.TrimSuffix(value, "\r")
	if value == "" {
		return "", errors.New("invalid credential file")
	}
	for _, r := range value {
		if r < 32 || r == 127 {
			return "", errors.New("invalid credential file")
		}
	}
	return value, nil
}

// -- PIA API ------------------------------------------------------------------------------

// getJSON asks an HTTPS endpoint and returns the decoded JSON object.
func (p *piaProvider) decodeObject(response netx.Response) (map[string]any, error) {
	decoded, err := validate.DecodeJSON(response.Body)
	if err != nil {
		return nil, err
	}
	data, ok := decoded.(map[string]any)
	if !ok {
		return nil, errors.New("invalid PIA response")
	}
	return data, nil
}

// piaToken is a token minted from the account login, reused for
// TokenMaxAgeSec. A login PIA refuses (HTTP 401 or 403) is a definite
// credential rejection: ErrCredentialRejected. Any other failure is uncertain
// and retried.
func (p *piaProvider) piaToken(ctx context.Context, a *Applier) (string, error) {
	if p.token != "" && a.clock()-p.tokenAt < TokenMaxAgeSec {
		return p.token, nil
	}
	username, err := readSecret(filepath.Join(p.cfg.SecretsDir, "username"))
	if err != nil {
		return "", err
	}
	password, err := readSecret(filepath.Join(p.cfg.SecretsDir, "password"))
	if err != nil {
		return "", err
	}
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	form.WriteField("username", username)
	form.WriteField("password", password)
	form.Close()
	response, err := a.sys.Fetch(ctx, netx.Request{URL: PIATokenURL, Method: "POST",
		Header: map[string]string{"Content-Type": form.FormDataContentType()}, Body: body.Bytes(),
		MaxBytes: piaAnswerMaxSize, Timeout: 15 * time.Second, AnyStatus: true})
	if err != nil {
		return "", err
	}
	if response.Status == 401 || response.Status == 403 {
		return "", ErrCredentialRejected
	}
	if response.Status != 200 {
		return "", errors.New("PIA token request failed")
	}
	data, err := p.decodeObject(response)
	if err != nil {
		return "", err
	}
	token, ok := data["token"].(string)
	if !ok || !validToken(token) {
		return "", errors.New("invalid PIA token response")
	}
	p.token, p.tokenAt = token, a.clock()
	return token, nil
}

func publicKey(ctx context.Context, a *Applier) (string, error) {
	key, err := a.sys.PublicKey(ctx)
	if err != nil {
		return "", err
	}
	key = strings.TrimFunc(key, validate.IsSpace)
	if !validate.ValidKey(key) {
		return "", errors.New("invalid interface public key")
	}
	return key, nil
}

type query []string

func (q query) encode() string {
	var parts []string
	for i := 0; i+1 < len(q); i += 2 {
		parts = append(parts, url.QueryEscape(q[i])+"="+url.QueryEscape(q[i+1]))
	}
	return strings.Join(parts, "&")
}

// pinned is a GET to a PIA server by TLS name, connecting to address.
func (p *piaProvider) pinned(ctx context.Context, a *Applier, cn, address string, port int, path string, fields query, bind bool) (map[string]any, error) {
	if !piaCNRE.MatchString(cn) || !validate.ValidIPv4(address) {
		return nil, errors.New("invalid PIA server")
	}
	request := netx.Request{URL: "https://" + cn + ":" + strconv.Itoa(port) + "/" + path + "?" + fields.encode(),
		RootCAs: p.cfg.RootCAs, ConnectAddr: address + ":" + strconv.Itoa(port), MaxBytes: piaAnswerMaxSize,
		Timeout: 15 * time.Second}
	if bind {
		request.BindInterface = a.exit.ExitIf
	}
	response, err := a.sys.Fetch(ctx, request)
	if err != nil {
		return nil, err
	}
	return p.decodeObject(response)
}

// registration is what a server answered a key registration with, and what
// tunnel.json records.
type registration struct {
	Region, CN, ServerIP string
	ServerPort           int
	ServerKey, PeerIP    string
	ServerVIP            string
}

func (r registration) object() validate.Obj {
	return validate.Members("region", r.Region, "cn", r.CN, "server_ip", r.ServerIP, "server_port", r.ServerPort,
		"server_key", r.ServerKey, "peer_ip", r.PeerIP, "server_vip", r.ServerVIP)
}

func privateAddress(address netip.Addr) bool {
	for _, network := range privateV4 {
		if network.Contains(address) {
			return true
		}
	}
	return false
}

// register registers the interface key on one of the region's servers. An
// expired or revoked token looks like any other refusal, so a refusal with a
// reused token is asked once more with a freshly minted one.
func (p *piaProvider) register(ctx context.Context, a *Applier, region *providers.Relay) (registration, error) {
	if len(region.Servers) == 0 {
		return registration{}, errors.New("region has no servers")
	}
	server := region.Servers[p.cfg.Choose(len(region.Servers))]
	key, err := publicKey(ctx, a)
	if err != nil {
		return registration{}, err
	}
	var data map[string]any
	for try := 0; try < 2; try++ {
		reused := p.token != ""
		data, err = p.addKey(ctx, a, server, key)
		if err == nil {
			break
		}
		if errors.Is(err, ErrCredentialRejected) {
			p.token = ""
			return registration{}, err
		}
		if !caught(err) {
			return registration{}, err
		}
		p.token = ""
		if try > 0 || !reused {
			return registration{}, err
		}
	}
	port, isInt := validate.IsInt(data["server_port"])
	if !isInt || !(0 < port && port < 65536) || data["server_ip"] != server.IP {
		return registration{}, errors.New("invalid PIA registration response")
	}
	if peer, present := data["peer_pubkey"]; present && peer != key {
		return registration{}, errors.New("PIA registered a different key")
	}
	var addresses [2]netip.Addr
	for i, field := range []string{"peer_ip", "server_vip"} {
		value := data[field]
		if !validate.ValidIPv4(value) {
			return registration{}, errors.New("invalid PIA tunnel address")
		}
		address := netip.MustParseAddr(value.(string))
		if !privateAddress(address) {
			return registration{}, errors.New("invalid PIA tunnel address")
		}
		addresses[i] = address
	}
	peer, vip := addresses[0], addresses[1]
	var taken []netip.Prefix
	if !a.nativeSidecar() {
		overlay, err := netip.ParsePrefix(a.exit.Overlay)
		if err != nil {
			return registration{}, errors.New("invalid overlay network")
		}
		taken = append(taken, overlay)
	}
	namespace, err := a.sys.NamespaceIPv4Prefixes(ctx, a.exit.ExitIf)
	if err != nil {
		return registration{}, err
	}
	taken = append(taken, namespace...)
	collides := peer == vip
	for _, address := range addresses {
		for _, network := range taken {
			collides = collides || network.Contains(address)
		}
	}
	if collides {
		return registration{}, errors.New("PIA tunnel address collides with this namespace")
	}
	return registration{Region: region.Hostname, CN: server.CN, ServerIP: server.IP, ServerPort: int(port),
		ServerKey: data["server_key"].(string), PeerIP: peer.String(), ServerVIP: vip.String()}, nil
}

// addKey is one registration request with a token (minted if need be).
func (p *piaProvider) addKey(ctx context.Context, a *Applier, server providers.Server, key string) (map[string]any, error) {
	token, err := p.piaToken(ctx, a)
	if err != nil {
		return nil, err
	}
	data, err := p.pinned(ctx, a, server.CN, server.IP, addKeyPort, "addKey", query{"pt", token, "pubkey", key}, false)
	if err != nil {
		return nil, err
	}
	if data["status"] != "OK" || !validate.ValidKey(data["server_key"]) {
		return nil, errors.New("PIA refused the key registration")
	}
	return data, nil
}

// -- return-path rules 94 and 98 ----------------------------------------------------------

func sourcesAt(ctx context.Context, k PIAKernel, priority int) ([]string, error) {
	rules, err := k.IPv4Rules(ctx, priority)
	if err != nil {
		return nil, err
	}
	var sources []string
	for _, r := range rules {
		if r.Src != "" {
			sources = append(sources, r.Src)
		}
	}
	return sources, nil
}

func contains(list []string, value string) bool {
	for _, s := range list {
		if s == value {
			return true
		}
	}
	return false
}

// ChangePIAAddress is PIA's address-change transaction over the kernel
// primitives, in the order that keeps the tunnel's address covered by its
// return-path rules (94) and their backstop (98) at every step. The exit
// worker's System.ChangePIAAddress runs it as one job on the mutation owner.
//
// The rules for the new address go in first, and are confirmed, before the
// address changes; the old pair comes out last, 94 before 98, so the exit's
// ICMP errors always have a rule sending them into the tunnel or dropping
// them. A failure stops there, with the old address and its pair in place. The
// new address is added before the old one goes: when an interface loses its
// last IPv4 address the kernel deletes every route through it, the tunnel
// default included, which is re-asserted afterwards. old is invalid when the
// tunnel has no IPv4 address.
func ChangePIAAddress(ctx context.Context, k PIAKernel, old, new netip.Addr) error {
	old94, err := sourcesAt(ctx, k, 94)
	if err != nil {
		return err
	}
	old98, err := sourcesAt(ctx, k, 98)
	if err != nil {
		return err
	}
	if !contains(old94, new.String()) {
		if err := k.AddReturnPathRule(ctx, 94, new); err != nil {
			return err
		}
	}
	if !contains(old98, new.String()) {
		if err := k.AddReturnPathRule(ctx, 98, new); err != nil {
			return err
		}
	}
	now94, err := sourcesAt(ctx, k, 94)
	if err != nil {
		return err
	}
	now98, err := sourcesAt(ctx, k, 98)
	if err != nil {
		return err
	}
	if !contains(now94, new.String()) || !contains(now98, new.String()) {
		return errors.New("the return-path rules for the new address are not in place")
	}
	if err := k.ReplaceTunnelAddress(ctx, new); err != nil {
		return err
	}
	if old.IsValid() && old != new {
		if err := k.DeleteTunnelAddress(ctx, old); err != nil {
			return err
		}
	}
	if err := k.ReplaceExitDefaultRoute(ctx); err != nil {
		return err
	}
	for _, group := range []struct {
		priority int
		sources  []string
	}{{94, old94}, {98, old98}} {
		for _, source := range group.sources {
			if source == new.String() {
				continue
			}
			address, err := netip.ParseAddr(source)
			if err != nil {
				return errors.New("invalid rule source")
			}
			if err := k.DeleteReturnPathRule(ctx, group.priority, address); err != nil {
				return err
			}
		}
	}
	return nil
}

// returnPathExact is true when rule is exactly this exit's rule 94 or 98 for
// address.
func returnPathExact(rule Rule, priority int, address string, table int) bool {
	if rule.IPProto != 1 || rule.Src != address {
		return false
	}
	if rule.SrcLen != -1 && rule.SrcLen != 32 {
		return false
	}
	if rule.Other {
		return false
	}
	if priority == 94 {
		return rule.Table == table && rule.Action == ""
	}
	return rule.Action == "unreachable" && rule.Table == 0
}

// -- provider seam ---------------------------------------------------------------------------

// ApplyRelay registers first, so a refused registration changes nothing. Then
// it replaces the peer, the tunnel address and its return-path rule.
func (p *piaProvider) ApplyRelay(ctx context.Context, a *Applier, relay *providers.Relay, keys []string) error {
	reg, err := p.register(ctx, a, relay)
	if err != nil {
		return err
	}
	var remove []string
	for _, key := range keys {
		if key != reg.ServerKey {
			remove = append(remove, key)
		}
	}
	if len(remove) > 0 {
		if err := a.sys.ReplacePeer(ctx, remove, PeerConfig{}); err != nil {
			return err
		}
	}
	p.forward, p.nextForward = nil, 0
	_ = p.removeForwardRules(ctx, a) // a failure here is not the switch's
	existing, err := a.tunnelAddresses(ctx, false)
	if err != nil {
		return err
	}
	var old netip.Addr
	if text, ok := existing[4]; ok {
		old = netip.MustParseAddr(text)
	}
	if err := a.sys.ChangePIAAddress(ctx, old, netip.MustParseAddr(reg.PeerIP)); err != nil {
		return err
	}
	// IPv4 only: PIA carries no IPv6, which stays on the unreachable fallback.
	if err := a.sys.ReplacePeer(ctx, nil, PeerConfig{PublicKey: reg.ServerKey,
		Endpoint: reg.ServerIP + ":" + strconv.Itoa(reg.ServerPort), AllowedIPs: []string{"0.0.0.0/0"}, KeepaliveSec: 25}); err != nil {
		return err
	}
	members := append(reg.object(), validate.Pair{Key: "registered_at", Value: a.nowISO()})
	if err := jsonfile.Write(tunnelPath(a), members, jsonfile.Options{Public: true}); err != nil {
		return wrapIO(err)
	}
	return nil
}

// recordedRegistration is the recorded registration, only while it matches the
// live peer. keys nil reads the live peers.
func (p *piaProvider) recordedRegistration(ctx context.Context, a *Applier, keys []string, haveKeys bool) (map[string]any, error) {
	data, ok := jsonfile.ReadObject(tunnelPath(a), 4096)
	if !ok || !validate.ValidKey(data["server_key"]) {
		return nil, nil
	}
	if !haveKeys {
		var err error
		if keys, err = a.peers(ctx); err != nil {
			return nil, err
		}
	}
	if len(keys) == 1 && keys[0] == data["server_key"] {
		return data, nil
	}
	return nil, nil
}

// ServerFor is the recorded region, while the registration matches the live
// peer.
func (p *piaProvider) ServerFor(ctx context.Context, a *Applier, keys []string) (string, error) {
	if len(keys) != 1 {
		return "", nil
	}
	data, err := p.recordedRegistration(ctx, a, keys, true)
	if err != nil || data == nil {
		return "", err
	}
	region, _ := data["region"].(string)
	if region != "" && a.catalog.Relays().Has(region) {
		return region, nil
	}
	return "", nil
}

// Egress is PIA's own check of the caller's address.
func (p *piaProvider) Egress(ctx context.Context, a *Applier) (EgressResult, error) {
	if _, err := a.tunnelAddresses(ctx, true); err != nil {
		return EgressResult{}, err
	}
	response, err := a.sys.Fetch(ctx, netx.Request{URL: PIAStatusURL, Family: 4, BindInterface: a.exit.ExitIf,
		MaxBytes: piaAnswerMaxSize, Timeout: 10 * time.Second})
	if err != nil {
		return EgressResult{}, err
	}
	data, err := p.decodeObject(response)
	if err != nil {
		return EgressResult{}, err
	}
	connected, isBool := data["connected"].(bool)
	if !isBool || !validate.ValidIPv4(data["ip"]) {
		return EgressResult{}, errors.New("invalid egress response")
	}
	state := "fail"
	if connected {
		state = "pass"
	}
	ip := data["ip"].(string)
	return EgressResult{EgressIP: ip, ExitConfirmed: connected, EgressIPs: validate.Members("4", ip),
		Families: validate.Members("4", state)}, nil
}

// EgressFor is PIA's check whatever the server.
func (p *piaProvider) EgressFor(ctx context.Context, a *Applier, _ string, _ *int) (EgressResult, error) {
	return p.Egress(ctx, a)
}

// ReleaseSignature: a refused login waits for the credential files to change
// (their identity and times, never their content), or for Retry.
func (p *piaProvider) ReleaseSignature(a *Applier, why string) (string, bool) {
	if why != "credentials" {
		return "", false
	}
	found := make([]any, 2)
	for i, name := range []string{"username", "password"} {
		info, err := os.Stat(filepath.Join(p.cfg.SecretsDir, name))
		if err != nil {
			continue
		}
		ino, mtime, ctime := statIdentity(info)
		found[i] = []any{ino, info.Size(), mtime, ctime}
	}
	raw, _ := validate.MarshalJSON(found)
	return string(raw), true
}

// BeforeTick keeps the tunnel's address and rules consistent, installs the
// ingress guard and clears a leftover forwarding table on an overlay, or
// clears the native sidecar firewall's forwarded port. Each is retried every
// tick until it succeeds.
func (p *piaProvider) BeforeTick(ctx context.Context, a *Applier) {
	_ = p.reconcileTunnel(ctx, a)
	if a.nativeSidecar() {
		// The exit installs the sidecar firewall before starting the applier.
		p.guardInstalled = true
	} else if !p.guardInstalled {
		if err := a.sys.InstallIngressGuard(ctx); err == nil {
			p.guardInstalled = true
		}
	}
	if !p.forwardReconciled {
		// A namespace that outlived the applier can still admit the port from
		// an earlier run, perhaps one with forwarding on. Retried every tick
		// until it succeeds.
		if err := p.removeForwardRules(ctx, a); err == nil {
			p.forwardReconciled = true
		}
	}
}

// AfterTick maintains the forwarded port.
func (p *piaProvider) AfterTick(ctx context.Context, a *Applier, _ *Record) {
	if !p.cfg.PortForward {
		return
	}
	if p.guardInstalled && p.forwardReconciled {
		p.maintainForward(ctx, a)
	} else {
		// Never forward a port before the ingress guard is in place, nor before
		// the leftover cleanup that would delete new rules.
		p.forwardError = "Waiting for the ingress guard; port forwarding is not started."
	}
}

// BeforeGate repairs first: it is what lets a damaged exit pass the gates.
func (p *piaProvider) BeforeGate(ctx context.Context, a *Applier) { _ = p.reconcileTunnel(ctx, a) }

// reconcileTunnel keeps the tunnel's address and its rules 94 and 98
// consistent, every pass (tick) and before every switch: the routing contract
// leaves both rules to this provider, since PIA's address changes per server.
// It repairs what an interrupted switch, or a deletion, leaves behind: more
// than one IPv4 address on the tunnel, a missing half of the kept address's
// pair, and rules at 94 or 98 for addresses no longer on it or not in their
// exact form. The recorded registration's address is kept when present. A
// missing half goes in before anything is removed, and 94 and 98 are handled
// one after the other, so the kept address never loses both. Without this, the
// routing check would refuse every later switch.
func (p *piaProvider) reconcileTunnel(ctx context.Context, a *Applier) error {
	table, _ := strconv.Atoi(a.exit.Table)
	addrs, err := a.sys.TunnelAddresses(ctx)
	if err != nil {
		return err
	}
	var addresses []netip.Addr
	for _, address := range addrs {
		if address.Is4() {
			addresses = append(addresses, address)
		}
	}
	recorded := ""
	if data, ok := jsonfile.ReadObject(tunnelPath(a), 4096); ok {
		recorded, _ = data["peer_ip"].(string)
	}
	var keep netip.Addr
	for _, address := range addresses {
		if address.String() == recorded {
			keep = address
		}
	}
	if !keep.IsValid() && len(addresses) > 0 {
		keep = addresses[0]
	}
	if keep.IsValid() {
		for _, priority := range []int{94, 98} {
			rules, err := a.sys.IPv4Rules(ctx, priority)
			if err != nil {
				return err
			}
			exact := false
			for _, r := range rules {
				exact = exact || returnPathExact(r, priority, keep.String(), table)
			}
			if !exact {
				if err := a.sys.AddReturnPathRule(ctx, priority, keep); err != nil {
					return err
				}
			}
		}
	}
	extra := false
	for _, address := range addresses {
		if address != keep {
			extra = true
			if err := a.sys.DeleteTunnelAddress(ctx, address); err != nil {
				return err
			}
		}
	}
	if extra {
		if err := a.sys.ReplaceExitDefaultRoute(ctx); err != nil {
			return err
		}
	}
	for _, priority := range []int{94, 98} {
		rules, err := a.sys.IPv4Rules(ctx, priority)
		if err != nil {
			return err
		}
		// Rules for other addresses go one by one, by source, which can't match
		// the kept address's rule.
		for _, r := range rules {
			if r.Src != "" && r.Src != keep.String() {
				source, err := netip.ParseAddr(r.Src)
				if err != nil {
					return errors.New("invalid rule source")
				}
				if err := a.sys.DeleteReturnPathRule(ctx, priority, source); err != nil {
					return err
				}
			}
		}
		if rules, err = a.sys.IPv4Rules(ctx, priority); err != nil {
			return err
		}
		allExact := true
		for _, r := range rules {
			allExact = allExact && returnPathExact(r, priority, keep.String(), table)
		}
		if len(rules) <= 1 && allExact {
			continue
		}
		// The kept address's rule isn't exact, or is doubled: clear the priority
		// and put it back. The other half of the pair holds meanwhile.
		for range rules {
			if err := a.sys.DeleteReturnPathRule(ctx, priority, netip.Addr{}); err != nil {
				return err
			}
		}
		if keep.IsValid() {
			if err := a.sys.AddReturnPathRule(ctx, priority, keep); err != nil {
				return err
			}
		}
	}
	return nil
}

// -- optional port forwarding ------------------------------------------------------------------

// maintainForward keeps one forwarded port bound on the current server and
// admitted in the sidecar namespace or pointed at the configured overlay
// address. It runs only while the verdict on the last published record is ok.
func (p *piaProvider) maintainForward(ctx context.Context, a *Applier) {
	var last any
	if p.lastResult != nil {
		last = p.lastResult.Decoded()
	}
	if a.clock() < p.nextForward || a.assess(last).State != "ok" {
		return
	}
	err := func() error {
		current, err := p.recordedRegistration(ctx, a, nil, false)
		if err != nil {
			return err
		}
		if current == nil {
			return errors.New("no current registration")
		}
		serverKey, _ := current["server_key"].(string)
		forward := p.forward
		if forward == nil || forward.serverKey != serverKey || a.clock()-forward.signedAt >= SignatureMaxAgeSec {
			if forward, err = p.getSignature(ctx, a, current); err != nil {
				return err
			}
			p.forward = forward
		}
		if err := p.bindPort(ctx, a, current, forward); err != nil {
			return err
		}
		forward.bound = true
		if err := p.applyForwardRules(ctx, a, forward.port); err != nil {
			return err
		}
		p.forwardError = ""
		p.nextForward = a.clock() + BindIntervalSec
		return nil
	}()
	if err != nil {
		p.forward = nil
		p.forwardError = "Port forwarding is unavailable; retrying."
		_ = p.removeForwardRules(ctx, a)
		p.nextForward = a.clock() + ForwardRetrySec
		a.log("applier: port forwarding failed")
	}
}

func (p *piaProvider) getSignature(ctx context.Context, a *Applier, current map[string]any) (*forwardState, error) {
	token, err := p.piaToken(ctx, a)
	if err != nil {
		return nil, err
	}
	cn, _ := current["cn"].(string)
	vip, _ := current["server_vip"].(string)
	data, err := p.pinned(ctx, a, cn, vip, forwardAPIPort, "getSignature", query{"token", token}, true)
	if err != nil {
		return nil, err
	}
	payload, isString1 := data["payload"].(string)
	signature, isString2 := data["signature"].(string)
	if data["status"] != "OK" || !isString1 || !isString2 {
		return nil, errors.New("PIA refused port forwarding")
	}
	if !validToken(payload) || !validToken(signature) {
		return nil, errors.New("invalid port forwarding response")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(payload)
	if err != nil {
		return nil, errors.New("invalid port forwarding payload")
	}
	decoded, err := validate.DecodeJSON(raw)
	if err != nil {
		return nil, err
	}
	var port int64
	var isInt bool
	if m, ok := decoded.(map[string]any); ok {
		port, isInt = validate.IsInt(m["port"])
	}
	if !isInt || !(1024 <= port && port < 65536) {
		return nil, errors.New("invalid forwarded port")
	}
	serverKey, _ := current["server_key"].(string)
	return &forwardState{serverKey: serverKey, payload: payload, signature: signature, port: int(port),
		signedAt: a.clock()}, nil
}

func (p *piaProvider) bindPort(ctx context.Context, a *Applier, current map[string]any, forward *forwardState) error {
	cn, _ := current["cn"].(string)
	vip, _ := current["server_vip"].(string)
	data, err := p.pinned(ctx, a, cn, vip, forwardAPIPort, "bindPort", query{"payload", forward.payload, "signature", forward.signature}, true)
	if err != nil {
		return err
	}
	if data["status"] != "OK" {
		return errors.New("PIA refused to bind the forwarded port")
	}
	return nil
}

func (p *piaProvider) applyForwardRules(ctx context.Context, a *Applier, port int) error {
	if p.nftPort == port {
		return nil
	}
	var err error
	if a.nativeSidecar() {
		err = a.sys.SetForwardedPort(ctx, port)
	} else {
		err = a.sys.ApplyForwardRules(ctx, port, netip.MustParseAddr(p.cfg.ForwardTarget))
	}
	if err != nil {
		return err
	}
	p.nftPort = port
	return nil
}

// removeForwardRules removes the forwarding table or clears the native
// sidecar firewall's forwarded port whether or not forwarding is on now.
func (p *piaProvider) removeForwardRules(ctx context.Context, a *Applier) error {
	p.nftPort = 0
	if a.nativeSidecar() {
		return a.sys.SetForwardedPort(ctx, 0)
	}
	return a.sys.RemoveForwardRules(ctx)
}
