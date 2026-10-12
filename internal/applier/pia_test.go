// Tests ported from tools/test_pia.py: the PIA provider with a fake kernel and
// a fake PIA API. No account, tunnel or host routes are touched. The pinned
// requests (addKey, getSignature, bindPort) go through the real internal/netx
// client to a loopback TLS server whose certificate a throwaway authority
// signed, so the CA pinning, the TLS name and the connect address are really
// exercised; the unpinned calls (login, status) are answered in memory.
//
// Not ported: the catalogue and request-name tests (internal/providers and
// internal/state), the status model (internal/verdict), the scratch files
// (credentials travel in memory now; test_credentials_never_reach_argv_or_state
// checks the state files and the requests instead), the tunnel-config tool and
// the routing-init script.
package applier

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/jsonfile"
	"github.com/irashack/molebridge/internal/netx"
	"github.com/irashack/molebridge/internal/providers"
	"github.com/irashack/molebridge/internal/validate"
)

const (
	piaOurKey    = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	piaServerKey = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
	piaOtherKey  = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM="
	piaUsername  = "p0000000"
	piaPassword  = "correct horse"
	piaToken     = "tok-EXAMPLE-0123456789"
	piaRegion    = "ex_example"
)

// piaAPI is PIA's HTTPS API.
type piaAPI struct {
	t         testing.TB
	k         *kernel
	addkey    map[string]any
	addkeyBad bool // answers with an HTTP error
	tokenFail bool
	status    int // the login endpoint's HTTP status
	port      int
	bindFail  bool
	connected bool
	server    *httptest.Server
	pool      *x509.CertPool
}

func throwawayAuthority(t testing.TB, name string) (*x509.CertPool, tls.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Example Test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return pool, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func newPIAAPI(t testing.TB, k *kernel) *piaAPI {
	api := &piaAPI{t: t, k: k, status: 200, port: 43210, connected: true,
		addkey: map[string]any{"status": "OK", "server_key": piaServerKey, "server_port": 1337, "server_ip": "198.51.100.20",
			"server_vip": "10.0.0.1", "peer_ip": "10.0.0.2", "peer_pubkey": piaOurKey, "dns_servers": []any{"10.0.0.243"}}}
	pool, cert := throwawayAuthority(t, "example401")
	api.pool = pool
	api.server = httptest.NewUnstartedServer(http.HandlerFunc(api.serve))
	api.server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	api.server.StartTLS()
	t.Cleanup(api.server.Close)
	k.handler = api.fetch
	return api
}

func (api *piaAPI) serve(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	write := func(v any) {
		raw, _ := validate.MarshalJSON(v)
		w.Write(raw)
	}
	switch r.URL.Path {
	case "/addKey":
		if q.Get("pt") != piaToken || q.Get("pubkey") != piaOurKey {
			api.t.Errorf("addKey query %v", q)
		}
		if api.addkeyBad {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		write(api.addkey)
	case "/getSignature":
		if q.Get("token") != piaToken {
			api.t.Errorf("getSignature query %v", q)
		}
		payload, _ := validate.MarshalJSON(map[string]any{"token": "x", "port": api.port, "expires_at": "2026-12-01T00:00:00Z"})
		write(map[string]any{"status": "OK", "payload": base64.StdEncoding.EncodeToString(payload), "signature": "SIG"})
	case "/bindPort":
		if q.Get("payload") == "" || q.Get("signature") == "" {
			api.t.Errorf("bindPort query %v", q)
		}
		state := "OK"
		if api.bindFail {
			state = "ERROR"
		}
		write(map[string]any{"status": state, "message": "x"})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (api *piaAPI) fetch(req netx.Request) (netx.Response, error) {
	t := api.t
	switch req.URL {
	case PIATokenURL:
		if api.tokenFail {
			return netx.Response{}, errInjected
		}
		mediaType, params, err := mime.ParseMediaType(req.Header["Content-Type"])
		if err != nil || mediaType != "multipart/form-data" || req.Method != "POST" || !req.AnyStatus {
			t.Errorf("login request: %v %s %v", err, req.Method, req.AnyStatus)
		}
		form, err := multipart.NewReader(bytes.NewReader(req.Body), params["boundary"]).ReadForm(1 << 20)
		if err != nil || form.Value["username"][0] != piaUsername || form.Value["password"][0] != piaPassword {
			t.Errorf("login form: %v", err)
		}
		if api.status != 200 {
			return netx.Response{Status: api.status, Body: []byte(`{"message": "unauthorized"}`)}, nil
		}
		return jsonBody(map[string]any{"token": piaToken}), nil
	case PIAStatusURL:
		if req.BindInterface != "pia" || req.Family != 4 {
			t.Errorf("status request %+v", req)
		}
		return jsonBody(map[string]any{"connected": api.connected, "ip": "203.0.113.30"}), nil
	}
	if req.ConnectAddr == "" {
		return netx.Response{}, fmt.Errorf("unexpected request %s", req.URL)
	}
	// A pinned request: the throwaway authority, the TLS name, the address.
	if req.RootCAs == nil {
		t.Errorf("unpinned request to %s", req.URL)
	}
	switch {
	case strings.HasPrefix(req.URL, "https://example401:1337/addKey?"):
		if req.ConnectAddr != "198.51.100.20:1337" || req.BindInterface != "" {
			t.Errorf("addKey connects to %s via %q", req.ConnectAddr, req.BindInterface)
		}
	case strings.HasPrefix(req.URL, "https://example401:19999/"):
		if req.ConnectAddr != "10.0.0.1:19999" || req.BindInterface != "pia" {
			t.Errorf("%s connects to %s via %q", req.URL, req.ConnectAddr, req.BindInterface)
		}
	default:
		t.Errorf("unexpected pinned request %s", req.URL)
	}
	req.ConnectAddr = api.server.Listener.Addr().String()
	req.BindInterface = "" // the test namespace has no such interface (netx's own tests cover binding)
	return netx.Client{}.Fetch(context.Background(), req)
}

func piaRegionJSON(changes map[string]any) map[string]any {
	region := map[string]any{"id": piaRegion, "name": "EX Example City", "country": "EX", "offline": false,
		"port_forward": true, "geo": false, "auto_region": true, "dns": "example.test",
		"servers": map[string]any{"wg": []any{map[string]any{"ip": "198.51.100.20", "cn": "example401"}},
			"meta": []any{map[string]any{"ip": "198.51.100.21", "cn": "example401"}}}}
	for k, v := range changes {
		region[k] = v
	}
	return region
}

func piaServerlist(regions ...map[string]any) []byte {
	if len(regions) == 0 {
		regions = []map[string]any{piaRegionJSON(nil)}
	}
	list := make([]any, len(regions))
	for i, r := range regions {
		list[i] = r
	}
	raw, _ := validate.MarshalJSON(map[string]any{"groups": map[string]any{}, "regions": list})
	return append(raw, []byte("\n\nSIGNATURE-NOT-JSON")...)
}

func piaEntries(t testing.TB) *providers.Entries {
	t.Helper()
	entries, err := providers.ParsePIACatalog(piaServerlist(), false)
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

// piaSetup is the Python `make`: a PIA applier, its fake kernel and API.
func piaSetup(t testing.TB, forward bool) (*Applier, *kernel, *piaAPI, string, string) {
	t.Helper()
	return piaSetupFor(t, forward, "")
}

// piaSetupFor is piaSetup with the SERVER setting.
func piaSetupFor(t testing.TB, forward bool, server string) (*Applier, *kernel, *piaAPI, string, string) {
	t.Helper()
	dir := t.TempDir()
	secrets := filepath.Join(dir, "secrets")
	writeFile(t, filepath.Join(secrets, "username"), piaUsername+"\n", 0o600)
	writeFile(t, filepath.Join(secrets, "password"), piaPassword, 0o600)
	writeSnapshot(t, dir, "pia", piaEntries(t))
	k := newKernel(t)
	k.exit.ExitIf = "pia"
	k.addrs = nil
	k.rules = map[int][]Rule{}
	k.keys = nil
	k.publicKey = piaOurKey
	k.expectedSource = "10.0.0.2"
	k.namespaceNets = []netip.Prefix{netip.MustParsePrefix("10.89.0.0/24")}
	api := newPIAAPI(t, k)
	cfg := PIAConfig{SecretsDir: secrets, PortForward: forward, Choose: func(int) int { return 0 }, RootCAs: api.pool}
	if forward {
		cfg.ForwardTarget = "192.0.2.10"
	}
	a := newApplier(t, k, dir, NewPIA(cfg), server)
	return a, k, api, dir, secrets
}

func piaOf(a *Applier) *piaProvider { return a.hooks.(*piaProvider) }

func piaRequest(changes map[string]any) map[string]any {
	r := requestAt(piaRegion, map[string]any{"request_id": strings.Repeat("1", 32)})
	for k, v := range changes {
		r[k] = v
	}
	return r
}

func piaDesire(t testing.TB, a *Applier) { desire(t, a, piaRequest(nil)) }

func (k *kernel) tokenRequests() int { return len(k.requestsTo(PIATokenURL)) }
func (k *kernel) addKeys() int       { return len(k.requestsTo("/addKey?")) }

func (k *kernel) sources94() []string { return sortedSources(k.sources(4, 94)) }
func (k *kernel) sources98() []string { return sortedSources(k.sources(4, 98)) }

func sortedSources(m map[string]bool) []string {
	var out []string
	for s := range m {
		out = append(out, s)
	}
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func addrStrings(k *kernel) []string {
	var out []string
	for _, a := range k.addrs {
		out = append(out, a.String())
	}
	return out
}

func same(a, b []string) bool { return strings.Join(a, ",") == strings.Join(b, ",") }

func (k *kernel) index(prefix string, from int) int {
	for i := from; i < len(k.calls); i++ {
		if strings.HasPrefix(k.calls[i], prefix) {
			return i
		}
	}
	return -1
}

// -- secrets ---------------------------------------------------------------------------

func TestPIAMalformedCredentialsRefused(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{"empty": "", "newline": "\n", "two lines": "a\nb", "NUL": "a\x00",
		"too long": strings.Repeat("x", 600), "bad UTF-8": "a\xff"} {
		path := filepath.Join(dir, "c")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readSecret(path); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for content, want := range map[string]string{"user\n": "user", "user": "user", "user\r\n": "user"} {
		path := filepath.Join(dir, "ok")
		os.WriteFile(path, []byte(content), 0o600)
		if got, err := readSecret(path); err != nil || got != want {
			t.Errorf("%q: %q %v", content, got, err)
		}
	}
	// A symlink is never followed, a missing file is an I/O failure.
	os.Symlink(filepath.Join(dir, "ok"), filepath.Join(dir, "link"))
	if _, err := readSecret(filepath.Join(dir, "link")); err == nil {
		t.Error("followed a symlink")
	}
	if _, err := readSecret(filepath.Join(dir, "missing")); err == nil || caught(err) {
		t.Errorf("missing file: %v", err)
	}
}

func TestPIACredentialsNeverReachStateOrURLs(t *testing.T) {
	a, k, _, dir, _ := piaSetup(t, false)
	a.switchTo(t, piaRequest(nil))
	entries, err := os.ReadDir(filepath.Join(dir, "applier"))
	if err != nil || len(entries) == 0 {
		t.Fatal(err)
	}
	for _, e := range entries {
		raw, _ := os.ReadFile(filepath.Join(dir, "applier", e.Name()))
		for _, secret := range []string{piaPassword, piaToken, piaUsername} {
			if strings.Contains(string(raw), secret) {
				t.Errorf("%s holds a credential", e.Name())
			}
		}
	}
	for _, req := range k.reqs {
		if strings.Contains(req.URL, piaPassword) || strings.Contains(req.URL, piaUsername) {
			t.Errorf("login in a URL: %s", req.URL)
		}
		for name, value := range req.Header {
			if strings.Contains(value, piaPassword) || strings.Contains(value, piaToken) {
				t.Errorf("secret in header %s", name)
			}
		}
	}
	for _, c := range k.calls {
		// The token is PIA's query parameter by design (the fake logs URLs);
		// the password is sent once, in the login's form body.
		if strings.Contains(c, piaPassword) {
			t.Errorf("password in call log: %s", c)
		}
	}
}

// -- switching ---------------------------------------------------------------------------

func TestPIASwitchRegistersThenSetsAddressRuleAndPeer(t *testing.T) {
	a, k, _, dir, _ := piaSetup(t, false)
	r := a.switchTo(t, piaRequest(nil))
	if status(r) != "ok" || r.Get("server") != piaRegion || checkState(r, "egress") != "pass" || checkField(r, "egress", "tier") != "provider" ||
		r.Get("provider") != "pia" || r.Decoded()["mullvad_exit_ip"] != nil {
		t.Fatalf("%s %s", status(r), message(r))
	}
	if !same(k.keys, []string{piaServerKey}) || !same(addrStrings(k), []string{"10.0.0.2"}) || !same(k.sources94(), []string{"10.0.0.2"}) ||
		len(k.sources(6, 94)) != 0 {
		t.Fatalf("keys %v addresses %v rules %v", k.keys, addrStrings(k), k.sources94())
	}
	tunnel, _ := jsonfile.ReadObject(filepath.Join(dir, "applier", "tunnel.json"), 4096)
	if tunnel["region"] != piaRegion || tunnel["server_key"] != piaServerKey || tunnel["peer_ip"] != "10.0.0.2" {
		t.Errorf("tunnel.json %v", tunnel)
	}
	register := k.index("Fetch https://example401:1337/addKey", 0)
	change := k.index("ChangePIAAddress", 0)
	set := -1
	for i, c := range k.calls {
		if c == "ReplacePeer" {
			set = i
		}
	}
	if !(0 <= register && register < change && change < set) {
		t.Errorf("order: register %d, address %d, peer %d", register, change, set)
	}
	if !k.hasMutation("set " + piaServerKey + " endpoint 198.51.100.20:1337 allowed-ips 0.0.0.0/0 keepalive 25") {
		t.Errorf("mutations %v", k.mutations)
	}
}

func (k *kernel) hasMutation(m string) bool {
	for _, got := range k.mutations {
		if got == m {
			return true
		}
	}
	return false
}

func TestPIASwitchReplacesPreviousServerAndAddress(t *testing.T) {
	a, k, api, _, _ := piaSetup(t, false)
	a.switchTo(t, piaRequest(nil))
	api.addkey["server_key"], api.addkey["peer_ip"] = piaOtherKey, "10.0.0.3"
	k.expectedSource = "10.0.0.3"
	r := a.switchTo(t, piaRequest(map[string]any{"request_id": strings.Repeat("2", 32)}))
	if status(r) != "ok" || !same(k.keys, []string{piaOtherKey}) || !same(addrStrings(k), []string{"10.0.0.3"}) ||
		!same(k.sources94(), []string{"10.0.0.3"}) || k.routeMissing[4] {
		t.Fatalf("%s %s keys %v addresses %v", status(r), message(r), k.keys, addrStrings(k))
	}
	if k.index("address replace 10.0.0.3/32", 0) > k.index("address del 10.0.0.2/32", 0) || k.index("address del 10.0.0.2/32", 0) < 0 {
		t.Errorf("the new address must be added before the old one goes: %v", k.calls)
	}
}

func TestPIABadRegistrationChangesNothing(t *testing.T) {
	for name, change := range map[string]map[string]any{
		"status": {"status": "ERROR"}, "bad key": {"server_key": "bad"}, "port a string": {"server_port": "1337"},
		"port a bool": {"server_port": true}, "port too big": {"server_port": 70000}, "other server ip": {"server_ip": "198.51.100.99"},
		"public peer ip": {"peer_ip": "203.0.113.5"}, "documentation peer ip": {"peer_ip": "192.0.2.5"}, "bad vip": {"server_vip": "x"},
		"other pubkey": {"peer_pubkey": piaOtherKey}, "peer is vip": {"peer_ip": "10.0.0.1"},
		"peer in namespace": {"peer_ip": "10.89.0.7"}, "vip in namespace": {"server_vip": "10.89.0.1"}} {
		a, k, api, _, _ := piaSetup(t, false)
		for key, v := range change {
			api.addkey[key] = v
		}
		r := a.switchTo(t, piaRequest(nil))
		if status(r) != "failed" || len(k.mutations) != 0 || len(k.keys) != 0 || len(k.addrs) != 0 ||
			k.index("rule add", 0) >= 0 || k.index("address replace", 0) >= 0 {
			t.Errorf("%s: %s %v %v", name, status(r), k.mutations, k.calls)
		}
	}
}

func TestPIAJSONRefusalAlsoDropsTheToken(t *testing.T) {
	a, k, api, _, _ := piaSetup(t, false)
	api.addkey["status"] = "ERROR"
	a.switchTo(t, piaRequest(nil))
	if piaOf(a).token != "" || len(k.mutations) != 0 {
		t.Fatalf("token %q mutations %v", piaOf(a).token, k.mutations)
	}
}

func TestPIAReregistrationNeverLeavesTheAddressWithoutAReturnPath(t *testing.T) {
	a, k, api, _, _ := piaSetup(t, false)
	a.switchTo(t, piaRequest(nil))
	a.switchTo(t, piaRequest(map[string]any{"request_id": strings.Repeat("2", 32)}))
	api.addkey["server_key"], api.addkey["peer_ip"] = piaOtherKey, "10.0.0.3"
	k.expectedSource = "10.0.0.3"
	a.switchTo(t, piaRequest(map[string]any{"request_id": strings.Repeat("3", 32)}))
	if k.returnGaps != 0 || !same(k.sources94(), []string{"10.0.0.3"}) {
		t.Fatalf("gaps %d rules %v", k.returnGaps, k.sources94())
	}
	// The same address again adds and removes no rule.
	before := k.countCalls("rule ")
	a.switchTo(t, piaRequest(map[string]any{"request_id": strings.Repeat("4", 32)}))
	if k.countCalls("rule ") != before {
		t.Errorf("rule changes for an unchanged address: %v", k.calls[before:])
	}
}

func TestPIARefusedRegistrationDropsTheToken(t *testing.T) {
	a, k, api, _, _ := piaSetup(t, false)
	api.addkeyBad = true
	a.switchTo(t, piaRequest(nil))
	if piaOf(a).token != "" || len(k.mutations) != 0 {
		t.Fatalf("token %q %v", piaOf(a).token, k.mutations)
	}
	api.addkeyBad = false
	tokens := k.tokenRequests()
	a.switchTo(t, piaRequest(map[string]any{"request_id": strings.Repeat("2", 32)}))
	if k.tokenRequests() != tokens+1 {
		t.Errorf("tokens %d -> %d", tokens, k.tokenRequests())
	}
}

func TestPIATokenIsReusedUntilItAges(t *testing.T) {
	a, k, _, _, _ := piaSetup(t, false)
	a.switchTo(t, piaRequest(nil))
	a.switchTo(t, piaRequest(map[string]any{"request_id": strings.Repeat("2", 32)}))
	if k.tokenRequests() != 1 {
		t.Fatalf("%d token requests", k.tokenRequests())
	}
	k.now += TokenMaxAgeSec
	a.switchTo(t, piaRequest(map[string]any{"request_id": strings.Repeat("3", 32)}))
	if k.tokenRequests() != 2 {
		t.Fatalf("%d token requests", k.tokenRequests())
	}
}

func TestPIALoginFailureChangesNothing(t *testing.T) {
	a, k, api, _, _ := piaSetup(t, false)
	api.tokenFail = true
	if r := a.switchTo(t, piaRequest(nil)); status(r) != "failed" || len(k.mutations) != 0 {
		t.Fatalf("%s %v", status(r), k.mutations)
	}
}

func TestPIAUnlistedRegionRefused(t *testing.T) {
	a, k, _, _, _ := piaSetup(t, false)
	r := a.switchTo(t, piaRequest(map[string]any{"server": "ex_other"}))
	if status(r) != "failed" || !strings.Contains(message(r), "not in a fresh") || k.addKeys() != 0 {
		t.Fatalf("%s %s %d", status(r), message(r), k.addKeys())
	}
}

func TestPIAEgressMustBeConfirmedByPIA(t *testing.T) {
	a, _, api, _, _ := piaSetup(t, false)
	api.connected = false
	r := a.switchTo(t, piaRequest(nil))
	if status(r) != "failed" || checkState(r, "egress") != "fail" {
		t.Fatalf("%s", status(r))
	}
	// Applied, not verified: re-checked, not registered again (D7).
	if message(r) != "Tunnel egress is not confirmed as PIA." || a.attempt.State != "unverified" {
		t.Fatalf("%s %s", message(r), a.attempt.State)
	}
}

func TestPIAUnregisteredExitSaysSo(t *testing.T) {
	a, _, _, _, _ := piaSetup(t, false)
	r := a.inspect(t)
	if status(r) != "failed" || !strings.Contains(message(r), "No PIA region") {
		t.Fatalf("%s %s", status(r), message(r))
	}
}

func TestPIASavedRegionIsRegisteredAfterTunnelRecreation(t *testing.T) {
	a, k, _, _, _ := piaSetup(t, false)
	piaDesire(t, a)
	if r := mustTick(t, a); status(r) != "ok" {
		t.Fatalf("%s", status(r))
	}
	// The tunnel was recreated: no peer, no address, no rule 94. Without a new
	// owner generation (tested in pipeline_test.go), a missing peer is waited
	// out like any drift.
	k.keys, k.addrs, k.rules = nil, nil, map[int][]Rule{}
	k.now++
	mustTick(t, a)
	if len(k.keys) != 0 {
		t.Fatal("registered at once")
	}
	k.now += 90
	if r := mustTick(t, a); status(r) != "ok" || !same(k.keys, []string{piaServerKey}) {
		t.Fatalf("%s %s %v", status(r), message(r), k.keys)
	}
}

func TestPIAStaleHandshakeReregistersTheSameRegionOnTheBackoff(t *testing.T) {
	// D15: PIA can forget a registration while the peer stays; a handshake
	// stale for 180 s re-registers the same region, paced by the backoff.
	a, k, _, _, _ := piaSetup(t, false)
	piaDesire(t, a)
	mustTick(t, a)
	if k.addKeys() != 1 {
		t.Fatalf("%d", k.addKeys())
	}
	k.age = 10_000
	k.now += 30
	a.nextHealth = 0
	if r := mustTick(t, a); status(r) != "failed" {
		t.Fatalf("%s", status(r))
	}
	k.now += 29
	mustTick(t, a)
	if k.addKeys() != 1 {
		t.Fatalf("%d", k.addKeys())
	}
	k.now++
	mustTick(t, a)
	// Re-registered one minute after the last registration; still stale, so
	// applied but unverified.
	if k.addKeys() != 2 || a.attempt.State != "unverified" || a.attempt.BackoffStep != 1 {
		t.Fatalf("addKeys %d %s step %d", k.addKeys(), a.attempt.State, a.attempt.BackoffStep)
	}
	mutated := *a.attempt.LastMutationAt
	for k.now < mutated+119 {
		k.now = min(k.now+10, mutated+119)
		mustTick(t, a)
	}
	if k.addKeys() != 2 {
		t.Fatalf("%d", k.addKeys())
	}
	k.now = mutated + 120
	mustTick(t, a)
	if k.addKeys() != 3 {
		t.Fatalf("%d", k.addKeys())
	}
	for _, m := range k.adds() {
		if !strings.HasPrefix(m, "set "+piaServerKey) {
			t.Errorf("another peer set: %s", m)
		}
	}
	// The handshake comes back: verified, the backoff starts over.
	k.age = 1
	k.now += 60
	a.nextHealth = 0
	if r := mustTick(t, a); status(r) != "ok" || a.attempt.BackoffStep != 0 {
		t.Fatalf("%s step %d", status(r), a.attempt.BackoffStep)
	}
}

func TestPIAAnEgressFailureAloneNeverReregisters(t *testing.T) {
	a, k, api, _, _ := piaSetup(t, false)
	piaDesire(t, a)
	mustTick(t, a)
	api.connected = false
	for i := 0; i < 30; i++ {
		k.now += 60
		mustTick(t, a)
	}
	if k.addKeys() != 1 || a.attempt.State != "unverified" {
		t.Fatalf("%d %s", k.addKeys(), a.attempt.State)
	}
}

func TestPIAFailedRegistrationOnAFreshTunnelIsRetriedWithBackoff(t *testing.T) {
	// A recreated tunnel has no peer and no address; PIA's API was down for the
	// first registration. Once it answers, the applier registers on its own,
	// after the backoff.
	a, k, api, _, _ := piaSetup(t, false)
	piaDesire(t, a)
	api.tokenFail = true
	r := mustTick(t, a)
	if status(r) != "failed" || !strings.HasPrefix(message(r), "Peer update failed") || a.attempt.State != "failed" || a.attempt.NextAction != "reapply" {
		t.Fatalf("%s %s %s", status(r), message(r), a.attempt.State)
	}
	api.tokenFail = false
	k.now += 30
	mustTick(t, a)
	if len(k.keys) != 0 {
		t.Fatal("registered before the backoff")
	}
	k.now += 30
	if r := mustTick(t, a); status(r) != "ok" || !same(k.keys, []string{piaServerKey}) {
		t.Fatalf("%s %s", status(r), message(r))
	}
}

func TestPIARefusedLoginIsRejectedUntilTheCredentialsChange(t *testing.T) {
	a, k, api, _, secrets := piaSetup(t, false)
	piaDesire(t, a)
	api.status = 401
	r := mustTick(t, a)
	if status(r) != "failed" || !strings.HasPrefix(message(r), "PIA refused the login") ||
		r.Decoded()["selection"].(map[string]any)["outcome"] != "rejected" {
		t.Fatalf("%s %s %v", status(r), message(r), r.Decoded()["selection"])
	}
	tokens := k.tokenRequests()
	for i := 0; i < 20; i++ {
		k.now += 60
		mustTick(t, a)
	}
	if k.tokenRequests() != tokens {
		t.Fatalf("asked again: %d -> %d", tokens, k.tokenRequests())
	}
	// Corrected credentials are tried again.
	api.status = 200
	if err := os.Chtimes(filepath.Join(secrets, "password"), time.Unix(1, 0), time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	k.now += 5
	if r := mustTick(t, a); status(r) != "ok" || !same(k.keys, []string{piaServerKey}) {
		t.Fatalf("%s %s", status(r), message(r))
	}
}

func TestPIAARefusalWithAReusedTokenIsAskedAgainWithAFreshOne(t *testing.T) {
	a, k, api, _, _ := piaSetup(t, false)
	piaDesire(t, a)
	if r := mustTick(t, a); status(r) != "ok" {
		t.Fatalf("%s", status(r))
	}
	refusals := 1
	real := k.handler
	k.handler = func(req netx.Request) (netx.Response, error) {
		if strings.Contains(req.URL, "/addKey?") && refusals > 0 {
			refusals--
			return jsonBody(map[string]any{"status": "ERROR"}), nil
		}
		return real(req)
	}
	_ = api
	desire(t, a, piaRequest(map[string]any{"request_id": strings.Repeat("3", 32)}))
	tokens := k.tokenRequests()
	if r := mustTick(t, a); status(r) != "ok" || k.tokenRequests() != tokens+1 {
		t.Fatalf("%s %s tokens %d -> %d", status(r), message(r), tokens, k.tokenRequests())
	}
}

func TestPIAContainerHealthcheckNeedsARegisteredTunnel(t *testing.T) {
	a, _, _, _, _ := piaSetup(t, false)
	ctx := context.Background()
	if p, f := a.routingStatus(ctx, true); p || f {
		t.Fatalf("fresh tunnel: %v %v", p, f)
	}
	if p, _ := a.routingStatus(ctx, false); !p {
		t.Fatal("a fresh tunnel with its guards intact is protected without an address")
	}
	a.switchTo(t, piaRequest(nil))
	if p, _ := a.routingStatus(ctx, true); !p {
		t.Fatal("registered tunnel not protected")
	}
}

// -- configuration ---------------------------------------------------------------------------

func TestPIAPortForwardConfigurationRefused(t *testing.T) {
	exit := Exit{Overlay: testOverlay4}
	for name, env := range map[string]map[string]string{
		"forward without a target":     {"PIA_PORT_FORWARD": "on"},
		"target outside the overlay":   {"PIA_PORT_FORWARD": "on", "PIA_PORT_FORWARD_TARGET": "203.0.113.1"},
		"not a flag":                   {"PIA_PORT_FORWARD": "maybe"},
		"target without forwarding":    {"PIA_PORT_FORWARD_TARGET": "192.0.2.10"},
		"target is not canonical IPv4": {"PIA_PORT_FORWARD": "on", "PIA_PORT_FORWARD_TARGET": "192.0.2.010"},
	} {
		if _, err := NewPIAFromEnv(exit, func(k string) string { return env[k] }); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestPIAPortForwardConfigurationAccepted(t *testing.T) {
	exit := Exit{Overlay: testOverlay4}
	env := map[string]string{"PIA_PORT_FORWARD": " On ", "PIA_PORT_FORWARD_TARGET": "192.0.2.10"}
	provider, err := NewPIAFromEnv(exit, func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	p := provider.(*piaProvider)
	if !p.cfg.PortForward || p.cfg.ForwardTarget != "192.0.2.10" || p.cfg.SecretsDir != "/run/secrets/pia" {
		t.Errorf("%+v", p.cfg)
	}
	off, err := NewPIAFromEnv(exit, func(string) string { return "" })
	if err != nil || off.(*piaProvider).cfg.PortForward {
		t.Errorf("forwarding on by default: %v", err)
	}
}

// -- port forwarding ---------------------------------------------------------------------------

func (k *kernel) lastNFT() string {
	if len(k.nftOps) == 0 {
		return ""
	}
	return k.nftOps[len(k.nftOps)-1]
}

func TestPIAPortForwardBindsAndPointsAtTheTarget(t *testing.T) {
	a, k, _, _, _ := piaSetup(t, true)
	piaDesire(t, a)
	mustTick(t, a)
	f := piaOf(a).forward
	if f == nil || f.port != 43210 || !f.bound || k.lastNFT() != "forward 43210 192.0.2.10" {
		t.Fatalf("%+v %v", f, k.nftOps)
	}
	if r := a.inspect(t); r.Decoded()["forwarded_port"] != int64(43210) {
		t.Fatalf("forwarded_port %v", r.Decoded()["forwarded_port"])
	}
}

func TestPIAPortForwardRebindsOnScheduleWithoutNewSignature(t *testing.T) {
	a, k, _, _, _ := piaSetup(t, true)
	piaDesire(t, a)
	mustTick(t, a)
	loads := len(k.nftOps)
	k.now += BindIntervalSec
	a.nextHealth = 0
	mustTick(t, a)
	if n := len(k.requestsTo("/getSignature")); n != 1 {
		t.Errorf("%d signatures", n)
	}
	if n := len(k.requestsTo("/bindPort")); n != 2 {
		t.Errorf("%d binds", n)
	}
	if len(k.nftOps) != loads {
		t.Errorf("rules loaded again: %v", k.nftOps[loads:])
	}
}

func TestPIAPortForwardFailureClearsThePortAndRules(t *testing.T) {
	a, k, api, _, _ := piaSetup(t, true)
	piaDesire(t, a)
	mustTick(t, a)
	api.bindFail = true
	k.now += BindIntervalSec
	a.nextHealth = 0
	mustTick(t, a)
	if piaOf(a).forward != nil || piaOf(a).forwardError == "" || k.lastNFT() != "remove-forward" {
		t.Fatalf("%+v %q %v", piaOf(a).forward, piaOf(a).forwardError, k.nftOps)
	}
	r := a.inspect(t)
	if r.Decoded()["forwarded_port"] != nil || r.Decoded()["port_forward_error"] == nil {
		t.Fatalf("%v %v", r.Decoded()["forwarded_port"], r.Decoded()["port_forward_error"])
	}
}

func TestPIASwitchDropsTheOldPort(t *testing.T) {
	a, k, api, _, _ := piaSetup(t, true)
	piaDesire(t, a)
	mustTick(t, a)
	api.addkey["server_key"] = piaOtherKey
	api.port = 45678
	desire(t, a, piaRequest(map[string]any{"request_id": strings.Repeat("2", 32)}))
	k.now++
	mustTick(t, a)
	f := piaOf(a).forward
	if f == nil || f.port != 45678 || f.serverKey != piaOtherKey || k.lastNFT() != "forward 45678 192.0.2.10" {
		t.Fatalf("%+v %v", f, k.nftOps)
	}
}

func TestPIAIngressGuardAndLeftoverCleanupRunOnceEvenWithForwardingOff(t *testing.T) {
	a, k, _, _, _ := piaSetup(t, false)
	mustTick(t, a)
	if len(k.nftOps) < 2 || k.nftOps[0] != "guard" || k.nftOps[1] != "remove-forward" {
		t.Fatalf("%v", k.nftOps)
	}
	loads := len(k.nftOps)
	mustTick(t, a)
	if len(k.nftOps) != loads {
		t.Errorf("again: %v", k.nftOps[loads:])
	}
}

func TestPIAFailedGuardOrCleanupIsRetried(t *testing.T) {
	a, k, _, _, _ := piaSetup(t, false)
	k.nftFailures = 2
	mustTick(t, a)
	if piaOf(a).guardInstalled || piaOf(a).forwardReconciled {
		t.Fatal("marked done after failures")
	}
	mustTick(t, a)
	if !piaOf(a).guardInstalled || !piaOf(a).forwardReconciled || k.nftOps[0] != "guard" || k.nftOps[1] != "remove-forward" {
		t.Fatalf("%v", k.nftOps)
	}
}

func TestPIANoForwardingUntilGuardAndCleanupSucceed(t *testing.T) {
	a, k, _, _, _ := piaSetup(t, true)
	k.nftAlwaysFail = true
	piaDesire(t, a)
	mustTick(t, a)
	if piaOf(a).forward != nil || !strings.Contains(piaOf(a).forwardError, "guard") {
		t.Fatalf("%+v %q", piaOf(a).forward, piaOf(a).forwardError)
	}
	if len(k.requestsTo("/getSignature")) != 0 || len(k.requestsTo("/bindPort")) != 0 {
		t.Fatal("forwarded before the guard")
	}
	k.nftAlwaysFail = false
	k.now++
	mustTick(t, a)
	if f := piaOf(a).forward; f == nil || !f.bound || !strings.HasPrefix(k.lastNFT(), "forward ") {
		t.Fatalf("%+v %v", f, k.nftOps)
	}
	// The cleanup already ran, so the next tick keeps the new rules.
	loads := len(k.nftOps)
	k.now++
	mustTick(t, a)
	if len(k.nftOps) != loads {
		t.Errorf("rules touched again: %v", k.nftOps[loads:])
	}
}

func TestPIAInterruptedSwitchIsRepairedBeforeTheNextOne(t *testing.T) {
	a, k, _, _, _ := piaSetup(t, false)
	a.switchTo(t, piaRequest(nil))
	// A switch died after adding the next address and its rule.
	k.addrs = append(k.addrs, mustAddr("10.0.0.9"))
	k.rules[4] = append(k.rules[4], Rule{Priority: 94, Src: "10.0.0.9", SrcLen: -1, IPProto: 1, Table: 51821},
		Rule{Priority: 98, Src: "10.0.0.9", SrcLen: -1, IPProto: 1, Action: "unreachable"})
	if p, _ := a.routingStatus(context.Background(), false); p {
		t.Fatal("protected with two addresses")
	}
	r := a.switchTo(t, piaRequest(map[string]any{"request_id": strings.Repeat("2", 32)}))
	if status(r) != "ok" || !same(addrStrings(k), []string{"10.0.0.2"}) || !same(k.sources94(), []string{"10.0.0.2"}) ||
		!same(k.sources98(), []string{"10.0.0.2"}) || k.returnGaps != 0 {
		t.Fatalf("%s %s %v %v %v gaps %d", status(r), message(r), addrStrings(k), k.sources94(), k.sources98(), k.returnGaps)
	}
}

func TestPIANonForwardingRegionIsNotSelectable(t *testing.T) {
	a, _, _, _, _ := piaSetup(t, true)
	ok, err := a.catalog.Refresh(context.Background(), func() ([]byte, error) {
		return piaServerlist(piaRegionJSON(nil), piaRegionJSON(map[string]any{"id": "ex_nopf", "port_forward": false})), nil
	})
	if err != nil || !ok || a.catalog.Relays().Len() != 1 || !a.catalog.Relays().Has(piaRegion) {
		t.Fatalf("%v %v %v", ok, err, a.catalog.Relays().Names())
	}
}

// -- egress check retry --------------------------------------------------------------------------

func piaStatusCall(r netx.Request) bool { return r.URL == PIAStatusURL }

func TestPIAUnansweredStatusCallIsAskedOnceMore(t *testing.T) {
	a, k, _, _, _ := piaSetup(t, false)
	if status(a.switchTo(t, piaRequest(nil))) != "ok" {
		t.Fatal("switch")
	}
	calls := k.unanswered(piaStatusCall, 1, 10)
	start := k.now
	r := a.inspect(t)
	if status(r) != "ok" || checkState(r, "egress") != "pass" || len(*calls) != 2 || k.now-start != 10+EgressRetrySec {
		t.Fatalf("%s calls %d elapsed %v", status(r), len(*calls), k.now-start)
	}
}

func TestPIAStatusCallUnansweredTwiceFails(t *testing.T) {
	a, k, _, _, _ := piaSetup(t, false)
	a.switchTo(t, piaRequest(nil))
	calls := k.unanswered(piaStatusCall, 2, 10)
	r := a.inspect(t)
	if status(r) != "failed" || message(r) != EgressFailedMessage || len(*calls) != 2 {
		t.Fatalf("%s %s %d", status(r), message(r), len(*calls))
	}
}

func TestPIASayingNotConnectedIsNeverAskedAgain(t *testing.T) {
	a, k, api, _, _ := piaSetup(t, false)
	a.switchTo(t, piaRequest(nil))
	api.connected = false
	calls := k.delayed(piaStatusCall)
	start := k.now
	if r := a.inspect(t); message(r) != "Tunnel egress is not confirmed as PIA." || len(*calls) != 1 || k.now != start {
		t.Fatalf("%s %d", message(r), len(*calls))
	}
}

func TestPIAFailedReregistrationClearsOnceTheTunnelRecoversByItself(t *testing.T) {
	// The tunnel stalls, the automatic re-registration is refused, then the old
	// registration's tunnel comes back: the exit reports healthy again without
	// anyone choosing the region again.
	a, k, api, _, _ := piaSetup(t, false)
	piaDesire(t, a)
	if r := mustTick(t, a); status(r) != "ok" {
		t.Fatalf("%s", status(r))
	}
	k.age, api.addkeyBad = 10_000, true
	k.now += 60
	a.nextHealth = 0
	mustTick(t, a)
	k.now += 60
	r := mustTick(t, a)
	if status(r) != "failed" || !strings.HasPrefix(message(r), "Peer update failed") {
		t.Fatalf("%s %s", status(r), message(r))
	}
	registrations := k.addKeys()
	k.age = 1
	k.now += 60
	a.nextHealth = 0
	r = mustTick(t, a)
	if status(r) != "ok" || r.Get("server") != piaRegion || a.attempt.State != "idle" || k.addKeys() != registrations {
		t.Fatalf("%s %s %s %d/%d", status(r), message(r), a.attempt.State, k.addKeys(), registrations)
	}
}

// -- rules 94 and 98: the applier owns both for PIA's per-server address ----------------------------

func TestPIASwitchInstallsAndConfirmsBothRulesBeforeTheAddress(t *testing.T) {
	a, k, api, _, _ := piaSetup(t, false)
	a.switchTo(t, piaRequest(nil))
	k.calls = nil
	api.addkey["server_key"], api.addkey["peer_ip"] = piaOtherKey, "10.0.0.3"
	k.expectedSource = "10.0.0.3"
	if r := a.switchTo(t, piaRequest(map[string]any{"request_id": strings.Repeat("2", 32)})); status(r) != "ok" {
		t.Fatalf("%s %s", status(r), message(r))
	}
	add94 := k.index("rule add from 10.0.0.3 ipproto icmp lookup", 0)
	add98 := k.index("rule add from 10.0.0.3 ipproto icmp unreachable", add94+1)
	address := k.index("address replace 10.0.0.3/32", 0)
	old := k.index("address del 10.0.0.2/32", 0)
	del94 := k.index("rule del priority 94 from 10.0.0.2", 0)
	del98 := k.index("rule del priority 98 from 10.0.0.2", 0)
	if !(0 <= add94 && add94 < add98 && add98 < address && address < old && old < del94 && del94 < del98) {
		t.Fatalf("order %d %d %d %d %d %d", add94, add98, address, old, del94, del98)
	}
	if !same(k.sources94(), []string{"10.0.0.3"}) || !same(k.sources98(), []string{"10.0.0.3"}) || k.returnGaps != 0 || k.bothMissing != 0 {
		t.Fatalf("%v %v gaps %d %d", k.sources94(), k.sources98(), k.returnGaps, k.bothMissing)
	}
}

func TestPIAAnInterruptedSwitchNeverLeavesAnAddressUnprotected(t *testing.T) {
	for _, step := range []string{"rule add from 10.0.0.3 ipproto icmp lookup", "rule add from 10.0.0.3 ipproto icmp unreachable",
		"address replace 10.0.0.3/32", "address del 10.0.0.2/32", "route replace default",
		"rule del priority 94 from 10.0.0.2", "rule del priority 98 from 10.0.0.2"} {
		a, k, api, _, _ := piaSetup(t, false)
		a.switchTo(t, piaRequest(nil))
		api.addkey["server_key"], api.addkey["peer_ip"] = piaOtherKey, "10.0.0.3"
		k.expectedSource = "10.0.0.3"
		k.failWhen = func(s string) bool { return strings.HasPrefix(s, step) }
		a.switchTo(t, piaRequest(map[string]any{"request_id": strings.Repeat("2", 32)}))
		if k.failWhen != nil {
			t.Errorf("%s: the step was never reached", step)
			continue
		}
		if k.returnGaps != 0 || k.bothMissing != 0 {
			t.Errorf("%s: gaps %d %d", step, k.returnGaps, k.bothMissing)
		}
		// The next pass (every tick) repairs whatever the interruption left.
		if len(k.addrs) == 1 {
			k.expectedSource = k.addrs[0].String()
		} else {
			k.expectedSource = "10.0.0.2"
		}
		if err := piaOf(a).reconcileTunnel(context.Background(), a); err != nil {
			t.Errorf("%s: reconcile: %v", step, err)
		}
		if len(k.addrs) != 1 || !same(k.sources94(), addrStrings(k)) || !same(k.sources98(), addrStrings(k)) {
			t.Errorf("%s: addresses %v rules %v %v", step, addrStrings(k), k.sources94(), k.sources98())
		}
		if k.returnGaps != 0 || k.bothMissing != 0 {
			t.Errorf("%s after repair: gaps %d %d", step, k.returnGaps, k.bothMissing)
		}
	}
}

func TestPIAEveryTickRestoresADeletedBackstop(t *testing.T) {
	a, k, _, _, _ := piaSetup(t, false)
	a.switchTo(t, piaRequest(nil))
	var kept []Rule
	for _, r := range k.rules[4] {
		if r.Priority != 98 {
			kept = append(kept, r)
		}
	}
	k.rules[4] = kept
	if p, _ := a.routingStatus(context.Background(), true); p {
		t.Fatal("protected without the backstop")
	}
	mustTick(t, a)
	if !same(k.sources98(), []string{"10.0.0.2"}) {
		t.Fatalf("%v", k.sources98())
	}
	if p, _ := a.routingStatus(context.Background(), true); !p {
		t.Fatal("not restored")
	}
}

func TestPIAAnOrphanedBackstopIsRemoved(t *testing.T) {
	a, k, _, _, _ := piaSetup(t, false)
	a.switchTo(t, piaRequest(nil))
	// An earlier switch died between removing the old 94 and the old 98.
	k.rules[4] = append(k.rules[4], Rule{Priority: 98, Src: "10.0.0.9", SrcLen: -1, IPProto: 1, Action: "unreachable"})
	if err := piaOf(a).reconcileTunnel(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	if !same(k.sources94(), []string{"10.0.0.2"}) || !same(k.sources98(), []string{"10.0.0.2"}) {
		t.Fatalf("%v %v", k.sources94(), k.sources98())
	}
}

func TestPIAARuleNotInItsExactFormIsReplacedAndItsPartnerHolds(t *testing.T) {
	for name, c := range map[string]struct {
		priority int
		bad      Rule
	}{
		"94 in table main":      {94, Rule{Priority: 94, Src: "10.0.0.2", SrcLen: -1, IPProto: 1, Table: 254}},
		"94 for every protocol": {94, Rule{Priority: 94, Src: "10.0.0.2", SrcLen: -1, Table: 51821}},
		"98 with a table":       {98, Rule{Priority: 98, Src: "10.0.0.2", SrcLen: -1, IPProto: 1, Table: 51821}},
		"98 on the overlay":     {98, Rule{Priority: 98, Src: "10.0.0.2", SrcLen: -1, IPProto: 1, Action: "unreachable", Other: true}},
	} {
		a, k, _, _, _ := piaSetup(t, false)
		a.switchTo(t, piaRequest(nil))
		var kept []Rule
		for _, r := range k.rules[4] {
			if r.Priority != c.priority {
				kept = append(kept, r)
			}
		}
		k.rules[4] = append(kept, c.bad)
		if err := piaOf(a).reconcileTunnel(context.Background(), a); err != nil {
			t.Fatal(err)
		}
		var exact []Rule
		for _, r := range k.rules[4] {
			if r.Priority == c.priority {
				exact = append(exact, r)
			}
		}
		table, _ := parseTable(a.exit.Table)
		if len(exact) != 1 || !returnPathExact(exact[0], c.priority, "10.0.0.2", table) || k.bothMissing != 0 {
			t.Errorf("%s: %+v both missing %d", name, exact, k.bothMissing)
		}
	}
}

func parseTable(s string) (int, error) {
	var n int
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err
}
