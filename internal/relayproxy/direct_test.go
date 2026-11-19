package relayproxy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// nordRig is a NordVPN Relays over fakes: a catalogue of two servers and the
// exit's result.json naming the current one.
type nordRig struct {
	relays   *Relays
	dialer   *fakeDialer
	resolver *fakeResolver
	result   string
}

func nordEntry(name, cc, code string) string {
	return `"` + name + `": {"hostname": "` + name + `", "public_key": "` + zeroKey + `", "ipv4_addr_in": "198.51.100.20",
		"city": "Example City", "country": "Example", "country_code": "` + strings.ToUpper(cc) + `", "location_code": "` + code + `", "virtual": false}`
}

func newNordRig(t *testing.T) *nordRig {
	t.Helper()
	dir := t.TempDir()
	catalog := filepath.Join(dir, "relays.json")
	body := `{"fetched_at": "2026-11-19T18:00:00Z", "provider": "nordvpn", "relays": {` +
		nordEntry("se123.nordvpn.com", "se", "se-gothenburg") + `, ` + nordEntry("de45.nordvpn.com", "de", "de-frankfurt") + `}}`
	if err := os.WriteFile(catalog, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	g := &nordRig{dialer: &fakeDialer{}, resolver: &fakeResolver{answers: map[string][]netip.Addr{}}, result: filepath.Join(dir, "result.json")}
	var err error
	g.relays, err = New(Config{Provider: "nordvpn", CatalogPath: catalog, ResultPath: g.result, Dialer: g.dialer, Resolver: g.resolver,
		Now: newClock().Now})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func (g *nordRig) setResult(t *testing.T, body string) {
	t.Helper()
	if err := os.WriteFile(g.result, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func echo(c net.Conn) { buf := make([]byte, 1); _, _ = c.Read(buf) }

func TestDirectDialUsesTheExitsCurrentServer(t *testing.T) {
	g := newNordRig(t)
	g.setResult(t, `{"schema": 2, "server": "se123.nordvpn.com"}`)
	g.resolver.answers["example.net"] = addrs("2001:db8::1", "192.0.2.10", "192.0.2.11")
	g.dialer.handle("192.0.2.11:443", echo)
	g.dialer.handle("192.0.2.5:22", echo)
	ctx := context.Background()
	for _, location := range []string{"any", "se", "se-gothenburg", "se123.nordvpn.com", "SE"} {
		conn, server, err := g.relays.Dial(ctx, location, "de45.nordvpn.com", "example.net:443")
		if err != nil || server != "se123.nordvpn.com" {
			t.Fatalf("%s: %s %v", location, server, err)
		}
		conn.Close()
	}
	// NordVPN's tunnel carries no IPv6: only A records are asked for, and an
	// IPv6 answer would be skipped; the first address refused, the next used.
	if g.resolver.calls[0] != "ip4 example.net" {
		t.Fatal(g.resolver.calls)
	}
	if calls := g.dialer.calls(); !reflect.DeepEqual(calls[:2], []string{"tcp 192.0.2.10:443", "tcp 192.0.2.11:443"}) {
		t.Fatal(calls)
	}
	// An address target is dialled as it is, with no lookup.
	before := len(g.resolver.calls)
	conn, _, err := g.relays.Dial(ctx, "any", "", "192.0.2.5:22")
	if err != nil || len(g.resolver.calls) != before {
		t.Fatal(err)
	}
	conn.Close()
	if _, _, err := g.relays.Dial(ctx, "any", "", "[2001:db8::5]:22"); !errors.Is(err, ErrUnreachable) {
		t.Fatal(err)
	}
	// Nothing is benched, and the current server is the only one listed.
	st := g.relays.Servers()
	if len(st) != 1 || st[0].Server != "se123.nordvpn.com" || st[0].Benched || st[0].LastOK.IsZero() {
		t.Fatalf("%+v", st)
	}
}

func TestDirectDialRefusals(t *testing.T) {
	g := newNordRig(t)
	ctx := context.Background()
	for _, body := range []string{"", `{"server": null}`, `{"server": "se-got-wg-001"}`, `{"server": 5}`,
		`{"server": "se123.nordvpn.com", "server": "de45.nordvpn.com"}`, `not json`} {
		g.setResult(t, body)
		if _, _, err := g.relays.Dial(ctx, "any", "", "192.0.2.5:22"); !errors.Is(err, ErrNoCurrent) {
			t.Errorf("%q: %v", body, err)
		}
		if g.relays.Servers() != nil {
			t.Errorf("%q: servers listed", body)
		}
	}
	g.setResult(t, `{"server": "se123.nordvpn.com"}`)
	for _, location := range []string{"de", "de-frankfurt", "de45.nordvpn.com", "se-stockholm"} {
		if _, _, err := g.relays.Dial(ctx, location, "", "192.0.2.5:22"); !errors.Is(err, ErrNoServer) {
			t.Errorf("%s: %v", location, err)
		}
	}
	// A current server the catalogue doesn't list serves only "any".
	g.setResult(t, `{"server": "nl9.nordvpn.com"}`)
	g.dialer.handle("192.0.2.5:22", echo)
	if _, _, err := g.relays.Dial(ctx, "nl", "", "192.0.2.5:22"); !errors.Is(err, ErrNoServer) {
		t.Error(err)
	}
	if conn, server, err := g.relays.Dial(ctx, "any", "", "192.0.2.5:22"); err != nil || server != "nl9.nordvpn.com" {
		t.Errorf("%s %v", server, err)
	} else {
		conn.Close()
	}
	if _, _, err := g.relays.Dial(ctx, "any", "", "missing.example.net:443"); !errors.Is(err, errNotFound) {
		t.Error(err)
	}
	if len(g.dialer.calls()) != 1 {
		t.Fatal(g.dialer.calls())
	}
}
