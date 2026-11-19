package relayproxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"
)

func TestMullvadSocksName(t *testing.T) {
	good := map[string]string{
		"se-got-wg-001": "se-got-wg-socks5-001.relays.mullvad.net",
		"us-nyc-wg-301": "us-nyc-wg-socks5-301.relays.mullvad.net",
	}
	for in, want := range good {
		if got, ok := MullvadSocksName(in); !ok || got != want {
			t.Errorf("%s: %q %v", in, got, ok)
		}
	}
	for _, in := range []string{"", "se-got-wg-01", "se-got-wg-0001", "se-got-ovpn-001", "se-wg-001",
		"gb-lon-ab-wg-001", "SE-GOT-wg-001", "se-got-wg-001.example.test", "se-got-wg-socks5-001"} {
		if got, ok := MullvadSocksName(in); ok {
			t.Errorf("%s: %q", in, got)
		}
	}
}

func TestNewRefusals(t *testing.T) {
	d, r := &fakeDialer{}, &fakeResolver{}
	cases := []struct {
		cfg  Config
		want error
	}{
		{Config{Provider: "gluetun-mullvad", CatalogPath: "x", ResultPath: "y", Dialer: d, Resolver: r}, ErrProvider},
		{Config{Provider: "", CatalogPath: "x", Dialer: d, Resolver: r}, ErrProvider},
		{Config{Provider: "mullvad", CatalogPath: "x", Resolver: r}, ErrConfig},
		{Config{Provider: "mullvad", CatalogPath: "x", Dialer: d}, ErrConfig},
		{Config{Provider: "mullvad", Dialer: d, Resolver: r}, ErrConfig},
		{Config{Provider: "pia", CatalogPath: "x", Dialer: d, Resolver: r}, ErrConfig},
	}
	for _, c := range cases {
		if _, err := New(c.cfg); !errors.Is(err, c.want) {
			t.Errorf("%+v: %v", c.cfg, err)
		}
	}
}

func TestCatalogDropsBadEntries(t *testing.T) {
	dir := t.TempDir()
	path := writeSnapshot(t, dir,
		mullvadEntry("se-got-wg-001", "se-got"),
		mullvadEntry("se-sto-wg-002", "se-sto"),
		// The catalogue's own validation drops these.
		`"se-mma-wg-001": {"hostname": "se-mma-wg-001", "public_key": "bad", "ipv4_addr_in": "198.51.100.10", "city": "C", "country": "E", "location_code": "se-mma"}`,
		`"se-mma-wg-002": {"hostname": "se-mma-wg-002", "public_key": "`+zeroKey+`", "ipv4_addr_in": "10.0.0.1", "city": "C", "country": "E", "location_code": "se-mma"}`,
		`"se-mma-wg-003": {"hostname": "se-mma-wg-004", "public_key": "`+zeroKey+`", "ipv4_addr_in": "198.51.100.10", "city": "C", "country": "E", "location_code": "se-mma"}`,
		// These pass it, but have no proxy name or a location code that
		// is not theirs.
		mullvadEntry("gb-lon-ab-wg-001", "gb-lon"),
		mullvadEntry("de-fra-wg-001", "se-got"),
		mullvadEntry("de-ber-wg-001", "Not a code"),
	)
	r, err := New(Config{Provider: "mullvad", CatalogPath: path, Dialer: &fakeDialer{}, Resolver: &fakeResolver{}})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, s := range r.Servers() {
		names = append(names, s.Server)
	}
	if !reflect.DeepEqual(names, []string{"se-got-wg-001", "se-sto-wg-002"}) || r.Known() != 2 {
		t.Fatal(names)
	}
	// Another provider's snapshot, and no snapshot, are empty catalogues.
	if len(loadCatalog(path, "pia").servers) != 0 || len(loadCatalog(filepath.Join(dir, "none.json"), "mullvad").servers) != 0 {
		t.Fatal("a foreign or missing snapshot gave servers")
	}
}

func TestCatalogRereadWhenTheFileChanges(t *testing.T) {
	g := newRig(t, "se-got-wg-001")
	if g.relays.Known() != 1 {
		t.Fatal(g.relays.Known())
	}
	path := writeSnapshot(t, g.dir, mullvadEntry("se-got-wg-001", "se-got"), mullvadEntry("de-fra-wg-002", "de-fra"))
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
	if g.relays.Known() != 2 {
		t.Fatal("the new snapshot was not read")
	}
}

func TestParseLocationAndMatching(t *testing.T) {
	got := server{name: "se-got-wg-001", city: "se-got", country: "se"}
	sto := server{name: "se-sto-wg-002", city: "se-sto", country: "se"}
	fra := server{name: "de-fra-wg-001", city: "de-fra", country: "de"}
	cases := map[string][]server{
		"any":           {got, sto, fra},
		"ANY":           {got, sto, fra},
		"se":            {got, sto},
		"SE":            {got, sto},
		"se-got":        {got},
		"se-got-wg-001": {got},
		"Se-Got-Wg-001": {got},
		"de":            {fra},
		"us":            nil,
		"se-got-wg-002": nil,
	}
	for text, want := range cases {
		loc, err := parseLocation(text)
		if err != nil {
			t.Fatalf("%q: %v", text, err)
		}
		var matched []server
		for _, s := range []server{got, sto, fra} {
			if loc.matches(s) {
				matched = append(matched, s)
			}
		}
		if !reflect.DeepEqual(matched, want) {
			t.Errorf("%q: %v", text, matched)
		}
	}
	// A PIA region id may hold '_'.
	if loc, err := parseLocation("DE_Berlin"); err != nil || !loc.matches(server{name: "de_berlin", city: "de-de_berlin", country: "de"}) {
		t.Fatalf("%+v %v", loc, err)
	}
	for _, text := range []string{"", "-se", "se.got", "se123.nordvpn.com", "se got", "se/got", "se\x00", "Kse", "sé", string(make([]byte, 65))} {
		if _, err := parseLocation(text); !errors.Is(err, ErrLocation) {
			t.Errorf("%q accepted", text)
		}
	}
}

func TestParseTarget(t *testing.T) {
	good := map[string]struct {
		host string
		port uint16
	}{
		"example.net:443":            {"example.net", 443},
		"Example.NET.:80":            {"Example.NET", 80},
		"192.0.2.1:22":               {"192.0.2.1", 22},
		"[2001:db8::1]:8443":         {"2001:db8::1", 8443},
		"[::ffff:192.0.2.1]:1":       {"192.0.2.1", 1},
		"_svc.example.test:65535":    {"_svc.example.test", 65535},
		"a.b.c.d.e.example.test:123": {"a.b.c.d.e.example.test", 123},
	}
	for in, want := range good {
		host, port, err := ParseTarget(in)
		if err != nil || host != want.host || port != want.port {
			t.Errorf("%s: %s %d %v", in, host, port, err)
		}
	}
	for _, in := range []string{"", "example.net", "example.net:0", "example.net:65536", "example.net:https",
		":443", "exa mple.net:443", "a..b:443", "[fe80::1%eth0]:443", "ex\x00.net:443", "exämple.net:443",
		string(bytes.Repeat([]byte("a."), 130)) + "a:443"} {
		if _, _, err := ParseTarget(in); !errors.Is(err, ErrTarget) {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestDialThroughARelayProxy(t *testing.T) {
	g := newRig(t, "se-got-wg-001")
	s := &socksServer{}
	g.serve(0, s)
	conn, server, err := g.relays.Dial(context.Background(), "se-got", "", "example.net:443")
	if err != nil || server != "se-got-wg-001" {
		t.Fatalf("%s %v", server, err)
	}
	defer conn.Close()
	// The connection is the relay proxy's, past the handshake, with no
	// deadline left on it.
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("%q %v", buf, err)
	}
	if !reflect.DeepEqual(g.resolver.calls, []string{"ip4 se-got-wg-socks5-001.relays.mullvad.net"}) {
		t.Fatal(g.resolver.calls)
	}
	if !reflect.DeepEqual(g.dialer.calls(), []string{"tcp 10.124.0.1:1080"}) {
		t.Fatal(g.dialer.calls())
	}
	// The name went to the relay proxy, not to the resolver.
	if req := s.requests(); len(req) != 1 || !bytes.Equal(req[0], domainRequest("example.net", 443)) {
		t.Fatalf("% x", req)
	}
	if st := g.state("se-got-wg-001"); st.Benched || !st.LastOK.Equal(g.clock.Now()) {
		t.Fatalf("%+v", st)
	}
}

func TestIPTargetsAreSentAsAddresses(t *testing.T) {
	g := newRig(t, "se-got-wg-001")
	s := &socksServer{}
	g.serve(0, s)
	for _, target := range []string{"192.0.2.9:80", "[2001:db8::9]:80"} {
		conn, _, err := g.relays.Dial(context.Background(), "any", "", target)
		if err != nil {
			t.Fatal(err)
		}
		conn.Close()
	}
	req := s.requests()
	want4 := []byte{5, 1, 0, 1, 192, 0, 2, 9, 0, 80}
	want6 := append(append([]byte{5, 1, 0, 4}, netip.MustParseAddr("2001:db8::9").AsSlice()...), 0, 80)
	if len(req) != 2 || !bytes.Equal(req[0], want4) || !bytes.Equal(req[1], want6) {
		t.Fatalf("% x", req)
	}
}

func TestAnswersOutsideTheRelayRangeAreRefused(t *testing.T) {
	for _, answer := range [][]netip.Addr{
		addrs("192.0.2.1"),
		addrs("10.124.0.1", "198.51.100.1"),
		addrs("10.125.0.1"),
		addrs("10.64.0.1"),
		addrs("::ffff:192.0.2.1"),
		nil,
	} {
		g := newRig(t, "se-got-wg-001")
		g.serve(0, &socksServer{})
		g.resolver.answers["se-got-wg-socks5-001.relays.mullvad.net"] = answer
		if _, _, err := g.relays.Dial(context.Background(), "any", "", "example.net:443"); !errors.Is(err, ErrOutOfRange) {
			t.Fatalf("%v: %v", answer, err)
		}
		if len(g.dialer.calls()) != 0 {
			t.Fatalf("%v: dialled %v", answer, g.dialer.calls())
		}
		if st := g.state("se-got-wg-001"); !st.Benched {
			t.Fatalf("%v: not benched", answer)
		}
	}
	// A v4-mapped answer inside the range is the address itself.
	if a, err := relayAddress(addrs("::ffff:10.124.0.7")); err != nil || a != netip.MustParseAddr("10.124.0.7") {
		t.Fatal(a, err)
	}
}

func TestBenchingDoublesToAnHourAndSuccessClearsIt(t *testing.T) {
	g := newRig(t, "se-got-wg-001")
	ctx := context.Background()
	want := []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 16 * time.Minute,
		32 * time.Minute, time.Hour, time.Hour}
	for i, d := range want {
		_, _, err := g.relays.Dial(ctx, "se-got-wg-001", "", "example.net:443")
		if !errors.Is(err, errRefused) {
			t.Fatalf("failure %d: %v", i, err)
		}
		st := g.state("se-got-wg-001")
		if !st.Benched || !st.BenchedUntil.Equal(g.clock.Now().Add(d)) || st.Reason != "connection failed" {
			t.Fatalf("failure %d: %+v, want %v", i, st, d)
		}
		// Benched: not tried again until the time is up.
		g.clock.Add(d - time.Second)
		if _, _, err := g.relays.Dial(ctx, "se-got-wg-001", "", "example.net:443"); !errors.Is(err, ErrAllBenched) {
			t.Fatalf("failure %d: tried while benched: %v", i, err)
		}
		g.clock.Add(time.Second)
		if st := g.state("se-got-wg-001"); st.Benched {
			t.Fatalf("failure %d: still benched at its end", i)
		}
	}
	g.serve(0, &socksServer{})
	conn, _, err := g.relays.Dial(ctx, "se-got-wg-001", "", "example.net:443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if st := g.state("se-got-wg-001"); st.Benched || st.Reason != "" || !st.LastOK.Equal(g.clock.Now()) {
		t.Fatalf("%+v", st)
	}
	// Cleared: the next failure starts at a minute again.
	g.dialer.handle("10.124.0.1:1080", nil)
	_, _, _ = g.relays.Dial(ctx, "any", "", "example.net:443")
	if st := g.state("se-got-wg-001"); !st.BenchedUntil.Equal(g.clock.Now().Add(time.Minute)) {
		t.Fatalf("%+v", st)
	}
}

func TestReplyCodes(t *testing.T) {
	for code := byte(1); code <= 9; code++ {
		g := newRig(t, "se-got-wg-001")
		g.serve(0, &socksServer{code: code})
		_, server, err := g.relays.Dial(context.Background(), "any", "", "example.net:443")
		var reply *ReplyError
		if !errors.As(err, &reply) || reply.Code != code {
			t.Fatalf("code %d: %v", code, err)
		}
		// The proxy maps the far end's answer through the errno it wraps.
		errnos := map[byte]error{ReplyConnectionRefused: syscall.ECONNREFUSED, ReplyHostUnreachable: syscall.EHOSTUNREACH,
			ReplyNetworkUnreachable: syscall.ENETUNREACH}
		for c, errno := range errnos {
			if errors.Is(err, errno) != (c == code) {
				t.Fatalf("code %d: errors.Is %v = %v", code, errno, !(c == code))
			}
		}
		st := g.state("se-got-wg-001")
		if code == ReplyHostUnreachable || code == ReplyConnectionRefused {
			// About the target: the relay proxy worked, and is reported.
			if !reply.Target() || st.Benched || server != "se-got-wg-001" || st.LastOK.IsZero() {
				t.Fatalf("code %d: %+v %q", code, st, server)
			}
			continue
		}
		if reply.Target() || !st.Benched || st.Reason == "" {
			t.Fatalf("code %d: %+v", code, st)
		}
	}
	g := newRig(t, "se-got-wg-001")
	g.serve(0, &socksServer{code: ReplyGeneralFailure})
	_, _, _ = g.relays.Dial(context.Background(), "any", "", "example.net:443")
	if st := g.state("se-got-wg-001"); st.Reason != "relay proxy replied general failure" {
		t.Fatal(st.Reason)
	}
}

func TestChoosingIsUniformAmongTheUnbenched(t *testing.T) {
	g := newRig(t, "se-got-wg-001", "se-got-wg-002", "se-got-wg-003", "de-fra-wg-001")
	for i := 0; i < 4; i++ {
		g.serve(i, &socksServer{})
	}
	ctx := context.Background()
	// Bench se-got-wg-001 (the first choice with Intn returning 0).
	g.dialer.handle("10.124.0.1:1080", nil)
	g.picks = nil
	conn, server, err := g.relays.Dial(ctx, "se", "", "example.net:443")
	if err != nil || server != "se-got-wg-002" {
		t.Fatalf("%s %v", server, err)
	}
	conn.Close()
	// Three in the country, then two once the first failed.
	if !reflect.DeepEqual(g.picks, []int{3, 2}) {
		t.Fatal(g.picks)
	}
	g.picks = nil
	conn, _, err = g.relays.Dial(ctx, "se", "", "example.net:443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if !reflect.DeepEqual(g.picks, []int{2}) {
		t.Fatal(g.picks)
	}
	// The real choice spreads over every candidate.
	r, _ := New(Config{Provider: "mullvad", CatalogPath: g.relays.cfg.CatalogPath, Dialer: g.dialer, Resolver: g.resolver})
	seen := map[string]bool{}
	for i := 0; i < 200 && len(seen) < 4; i++ {
		conn, server, err := r.Dial(ctx, "any", "", "example.net:443")
		if err != nil {
			continue // se-got-wg-001 still refuses
		}
		conn.Close()
		seen[server] = true
	}
	if len(seen) != 3 {
		t.Fatal(seen)
	}
}

func TestPinnedIsPreferredWhileItWorks(t *testing.T) {
	g := newRig(t, "se-got-wg-001", "se-got-wg-002", "de-fra-wg-001")
	for i := 0; i < 3; i++ {
		g.serve(i, &socksServer{})
	}
	ctx := context.Background()
	dial := func(location, pinned string) (string, error) {
		conn, server, err := g.relays.Dial(ctx, location, pinned, "example.net:443")
		if err == nil {
			conn.Close()
		}
		return server, err
	}
	g.picks = nil
	if server, err := dial("se", "se-got-wg-002"); err != nil || server != "se-got-wg-002" || len(g.picks) != 0 {
		t.Fatalf("%s %v %v", server, err, g.picks)
	}
	// A pinned server outside the location is not used.
	if server, err := dial("se", "de-fra-wg-001"); err != nil || server == "de-fra-wg-001" {
		t.Fatalf("%s %v", server, err)
	}
	// A failing pinned server is benched and another is used at once.
	g.dialer.handle("10.124.0.2:1080", nil)
	if server, err := dial("se", "se-got-wg-002"); err != nil || server != "se-got-wg-001" {
		t.Fatalf("%s %v", server, err)
	}
	if !g.state("se-got-wg-002").Benched {
		t.Fatal("the pinned server was not benched")
	}
	// Benched, it is passed over without being tried.
	before := len(g.dialer.calls())
	if server, err := dial("se", "se-got-wg-002"); err != nil || server != "se-got-wg-001" || len(g.dialer.calls()) != before+1 {
		t.Fatalf("%s %v", server, err)
	}
}

func TestADialTriesAtMostThreeServers(t *testing.T) {
	g := newRig(t, "se-got-wg-001", "se-got-wg-002", "se-got-wg-003", "se-got-wg-004")
	_, _, err := g.relays.Dial(context.Background(), "any", "", "example.net:443")
	if !errors.Is(err, errRefused) || len(g.dialer.calls()) != 3 {
		t.Fatalf("%v %v", err, g.dialer.calls())
	}
	benched := 0
	for _, s := range g.relays.Servers() {
		if s.Benched {
			benched++
		}
	}
	if benched != 3 {
		t.Fatal(benched)
	}
}

func TestNameLookupFailureBenches(t *testing.T) {
	g := newRig(t, "se-got-wg-001")
	delete(g.resolver.answers, "se-got-wg-socks5-001.relays.mullvad.net")
	if _, _, err := g.relays.Dial(context.Background(), "any", "", "example.net:443"); !errors.Is(err, errNotFound) {
		t.Fatal(err)
	}
	if st := g.state("se-got-wg-001"); !st.Benched || st.Reason != "name lookup failed" {
		t.Fatalf("%+v", st)
	}
}

func TestHandshakeTimeoutBenches(t *testing.T) {
	g := newRig(t, "se-got-wg-001")
	g.relays.cfg.HandshakeTimeout = 50 * time.Millisecond
	g.dialer.handle("10.124.0.1:1080", func(c net.Conn) { _, _ = io.Copy(io.Discard, c) })
	start := time.Now()
	if _, _, err := g.relays.Dial(context.Background(), "any", "", "example.net:443"); err == nil {
		t.Fatal("no error")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("the handshake timeout did not end the wait")
	}
	if st := g.state("se-got-wg-001"); !st.Benched || st.Reason != "handshake timed out" {
		t.Fatalf("%+v", st)
	}
}

func TestCallerCancellationDoesNotBench(t *testing.T) {
	g := newRig(t, "se-got-wg-001")
	g.dialer.handle("10.124.0.1:1080", func(c net.Conn) { _, _ = io.Copy(io.Discard, c) })
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(20*time.Millisecond, cancel)
	if _, _, err := g.relays.Dial(ctx, "any", "", "example.net:443"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if st := g.state("se-got-wg-001"); st.Benched {
		t.Fatalf("%+v", st)
	}
}

func TestDialRefusals(t *testing.T) {
	g := newRig(t, "se-got-wg-001")
	ctx := context.Background()
	if _, _, err := g.relays.Dial(ctx, "se", "", "example.net"); !errors.Is(err, ErrTarget) {
		t.Error(err)
	}
	if _, _, err := g.relays.Dial(ctx, "se got", "", "example.net:443"); !errors.Is(err, ErrLocation) {
		t.Error(err)
	}
	if _, _, err := g.relays.Dial(ctx, "us", "", "example.net:443"); !errors.Is(err, ErrNoServer) {
		t.Error(err)
	}
	if len(g.dialer.calls()) != 0 || len(g.resolver.calls) != 0 {
		t.Fatal("a refused dial reached the network")
	}
}
