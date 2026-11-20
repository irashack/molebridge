//go:build drill && systemrig && linux

package exit

import (
	"encoding/base64"
	"encoding/json"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/irashack/molebridge/internal/applier"
	"github.com/irashack/molebridge/internal/nstest"
	"github.com/irashack/molebridge/internal/providers"
)

// The fake PIA network of the multi-provider drills, shaped like PIA's as
// the applier uses it (internal/applier/pia.go, and the unit tests' fake in
// internal/applier/pia_test.go):
//
//   - the region list at serverlist.piaservers.net, JSON on its first line
//     and a signature after it, with one region that forwards ports and one
//     WireGuard server;
//   - the login (POST /api/client/v2/token) and the status check
//     (/api/client/status), which says connected only for the server's own
//     egress address, at www.privateinternetaccess.com;
//   - the server: a WireGuard interface on port 1337 that takes the exit's
//     pia.conf key once it is registered, with the registration API (addKey)
//     on TCP 1337 at its public address and the port-forwarding API
//     (getSignature, bindPort) on port 19999 at its tunnel address, both by
//     TLS name, as PIA's are.
//
// The servers present the rig's certificate: the drill build's
// MOLEBRIDGE_DRILL_PIA_CA (pia_hook_drill.go) makes the exit trust the
// rig's authority instead of PIA's. Each registration hands out the same
// tunnel address, IPv4 only, as PIA's servers do for a key they know.

const (
	rigPIARegion   = "zz-example"
	rigPIACN       = "zzexample401"
	rigPIAEndpoint = "198.51.100.21"
	rigPIAGateway  = "198.51.100.22"
	rigPIAEgress   = "203.0.113.40"
	rigPIALink     = "pia0"
	rigPIAPeer     = "10.10.0.2" // the exit's tunnel address, from addKey
	rigPIAVIP      = "10.10.0.1" // the server's, where port forwarding answers
	rigPIAPort     = 1337
	rigPIAForward  = 47047 // the port getSignature hands out
	rigPIAToken    = "drill-token-0000"
	rigPIAUser     = "drill-user"
	rigPIAPass     = "drill-password"
)

// rigPIA is the fake PIA server and its API's counts.
type rigPIA struct {
	ns   *nstest.NS
	key  wgtypes.Key // the server's
	exit wgtypes.Key // the exit's pia.conf key

	mu                           sync.Mutex
	logins, addKeys, sigs, binds int
}

// counts are the logins, registrations, signatures and binds served so far.
func (p *rigPIA) counts() (int, int, int, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.logins, p.addKeys, p.sigs, p.binds
}

// urlPath is the path of one of the code's provider URLs.
func urlPath(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u.Path
}

// addPIA builds the fake PIA server, its API and region list, the exit's
// pia.conf and PIA's credential files, and adds PIA's settings to the
// exit's environment. It must run before the exit starts.
func (r *systemRig) addPIA() *rigPIA {
	t := r.t
	p := &rigPIA{ns: nstest.New(t, "pia"), key: rigKey(t), exit: rigKey(t)}
	ns, in := p.ns, r.internet
	rigSysctls(ns)
	ns.Sysctl("net.ipv4.ip_forward=1")
	ns.Veth("eth0", in, rigPIALink)
	addrUp(ns, "eth0", rigPIAEndpoint+"/30")
	addrUp(in, rigPIALink, rigPIAGateway+"/30")
	ns.IP("route", "add", "default", "via", rigPIAGateway)
	in.IP("route", "add", rigPIAEgress+"/32", "via", rigPIAEndpoint)
	ns.IP("link", "add", "wg0", "type", "wireguard")
	port := rigPIAPort
	wgSet(t, ns, "wg0", wgtypes.Config{PrivateKey: &p.key, ListenPort: &port, ReplacePeers: true, Peers: []wgtypes.PeerConfig{{
		PublicKey: p.exit.PublicKey(), ReplaceAllowedIPs: true,
		// The tunnel address addKey hands out, and the overlay's (the fake
		// NetBird does not masquerade the client). No IPv6: PIA carries none.
		AllowedIPs: rigPrefixes(t, rigPIAPeer+"/32", "192.0.2.0/24"),
	}}})
	addrUp(ns, "wg0", rigPIAVIP+"/32")
	for _, c := range []string{rigPIAPeer + "/32", "192.0.2.0/24"} {
		ns.IP("route", "add", c, "dev", "wg0")
	}
	nat := `table inet relay {
  chain post {
    type nat hook postrouting priority srcnat; policy accept;
    iifname "wg0" oifname "eth0" meta nfproto ipv4 snat ip to ` + rigPIAEgress + `
  }
}
`
	if out, err := ns.ExecInput(nat, "nft", "-f", "-"); err != nil {
		t.Fatalf("nft in pia: %v\n%s", err, out)
	}

	// The exit's PIA config, as prepare-config --pia writes it: the key,
	// no address and no peer (the applier sets both when it registers).
	conf := "[Interface]\nPrivateKey = " + p.exit.String() + "\nMTU = 1420\nTable = off\n" +
		"PostUp = ip route replace default dev %i table 51821\nPreDown = ip route del default dev %i table 51821\n"
	if err := os.WriteFile(filepath.Join(r.confDir, "pia.conf"), []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	secrets := r.path("pia-secrets")
	if err := os.MkdirAll(secrets, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{"username": rigPIAUser, "password": rigPIAPass} {
		if err := os.WriteFile(filepath.Join(secrets, name), []byte(value+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r.exitExtra = append(r.exitExtra, "PIA_SECRETS_DIR="+secrets, "MOLEBRIDGE_DRILL_PIA_CA="+r.caPath)

	// The region list, checked as the exit will read it.
	region := map[string]any{"id": rigPIARegion, "name": "ZZ " + rigCity, "country": "ZZ", "offline": false,
		"port_forward": true, "geo": false, "auto_region": true, "dns": "example.test",
		"servers": map[string]any{"wg": []any{map[string]any{"ip": rigPIAEndpoint, "cn": rigPIACN}},
			"meta": []any{map[string]any{"ip": rigPIAEndpoint, "cn": rigPIACN}}}}
	list, err := json.Marshal(map[string]any{"groups": map[string]any{}, "regions": []any{region}})
	if err != nil {
		t.Fatal(err)
	}
	served := append(list, []byte("\n\nU0lHTkFUVVJFLU5PVC1KU09O")...)
	entries, err := providers.ParsePIACatalog(served, true)
	if err != nil {
		t.Fatalf("the fake PIA region list: %v", err)
	}
	if got, ok := entries.Get(rigPIARegion); !ok || entries.Len() != 1 || len(got.Servers) != 1 || got.Servers[0].IP != rigPIAEndpoint {
		t.Fatalf("the fake PIA region list reads as %d regions, %+v", entries.Len(), got)
	}

	// PIA's web API, on the rig's check server.
	serverlistPath, tokenPath, statusPath := urlPath(providers.PIAServerlistURL), urlPath(applier.PIATokenURL), urlPath(applier.PIAStatusURL)
	api := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		host, _, _ := net.SplitHostPort(req.RemoteAddr)
		src, err := netip.ParseAddr(host)
		if err != nil {
			http.Error(w, "bad source", http.StatusInternalServerError)
			return
		}
		src = src.Unmap()
		r.logServed("pia %s %s%s from %s", req.Method, req.Host, req.URL.Path, src)
		switch req.URL.Path {
		case serverlistPath:
			_, _ = w.Write(served)
			return
		case tokenPath:
			mediaType, params, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
			if err != nil || req.Method != http.MethodPost || mediaType != "multipart/form-data" {
				http.Error(w, "bad login request", http.StatusBadRequest)
				return
			}
			form, err := multipart.NewReader(req.Body, params["boundary"]).ReadForm(1 << 16)
			if err != nil || len(form.Value["username"]) != 1 || len(form.Value["password"]) != 1 ||
				form.Value["username"][0] != rigPIAUser || form.Value["password"][0] != rigPIAPass {
				http.Error(w, `{"message": "unauthorized"}`, http.StatusUnauthorized)
				return
			}
			p.mu.Lock()
			p.logins++
			p.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"token": rigPIAToken})
		case statusPath:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"ip": src.String(), "connected": src.String() == rigPIAEgress})
		default:
			http.NotFound(w, req)
		}
	})
	r.mu.Lock()
	if r.apis == nil {
		r.apis = map[string]http.Handler{}
	}
	for _, u := range []string{providers.PIAServerlistURL, applier.PIATokenURL} {
		parsed, _ := url.Parse(u)
		r.apis[parsed.Hostname()] = api
	}
	r.mu.Unlock()

	// The server's own APIs, by TLS name: registration at its public
	// address, port forwarding at its tunnel address (reached only through
	// the tunnel).
	write := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	server := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.logServed("pia server %s%s from %s", req.Host, req.URL.Path, req.RemoteAddr)
		q := req.URL.Query()
		switch req.URL.Path {
		case "/addKey":
			if q.Get("pt") != rigPIAToken || q.Get("pubkey") != p.exit.PublicKey().String() {
				write(w, map[string]any{"status": "ERROR", "message": "the drill's PIA server knows another key"})
				return
			}
			p.mu.Lock()
			p.addKeys++
			p.mu.Unlock()
			write(w, map[string]any{"status": "OK", "server_key": p.key.PublicKey().String(), "server_port": rigPIAPort,
				"server_ip": rigPIAEndpoint, "server_vip": rigPIAVIP, "peer_ip": rigPIAPeer, "peer_pubkey": q.Get("pubkey")})
		case "/getSignature":
			if q.Get("token") != rigPIAToken {
				write(w, map[string]any{"status": "ERROR"})
				return
			}
			p.mu.Lock()
			p.sigs++
			p.mu.Unlock()
			payload, _ := json.Marshal(map[string]any{"token": "x", "port": rigPIAForward, "expires_at": "2099-01-01T00:00:00Z"})
			write(w, map[string]any{"status": "OK", "payload": base64.StdEncoding.EncodeToString(payload),
				"signature": base64.StdEncoding.EncodeToString([]byte("drill-signature"))})
		case "/bindPort":
			if q.Get("payload") == "" || q.Get("signature") == "" {
				write(w, map[string]any{"status": "ERROR"})
				return
			}
			p.mu.Lock()
			p.binds++
			p.mu.Unlock()
			write(w, map[string]any{"status": "OK", "message": "port scheduled for add"})
		default:
			http.NotFound(w, req)
		}
	})
	r.serveIn(ns, net.JoinHostPort(rigPIAEndpoint, strconv.Itoa(rigPIAPort)), server)
	r.serveIn(ns, net.JoinHostPort(rigPIAVIP, "19999"), server)
	return p
}

// forwardTable is the exit's port-forwarding table as nft lists it, "" when
// there is none.
func (r *systemRig) forwardTable() string {
	out, err := r.exit.Exec("nft", "list", "table", "ip", "molebridge_forward")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}
