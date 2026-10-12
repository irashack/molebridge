package panel

// Ported from panel/test_app.py: LatencyTests, LatencyBoundsTests and
// LatencyEndpointTests.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/providers"
)

func mullvadRelays(rows ...[3]string) *providers.Entries {
	entries := providers.NewEntries()
	for _, r := range rows {
		entries.Set(r[0], &providers.Relay{Shape: providers.ShapeMullvad, Hostname: r[0], Country: r[1], City: "", IPv4AddrIn: r[2]})
	}
	return entries
}

func sampleRelays() *providers.Entries {
	entries := providers.NewEntries()
	for _, r := range []struct{ host, country, city, ip string }{
		{"se-sto-wg-001", "Sweden", "Stockholm", "198.51.100.10"},
		{"se-sto-wg-002", "Sweden", "Stockholm", "198.51.100.11"},
		{"us-nyc-wg-301", "USA", "New York", "198.51.100.12"},
	} {
		entries.Set(r.host, &providers.Relay{Shape: providers.ShapeMullvad, Hostname: r.host, Country: r.country, City: r.city,
			LocationCode: "xx-xxx", IPv4AddrIn: r.ip})
	}
	return entries
}

type probeLog struct {
	mu     sync.Mutex
	probed []string
}

func (p *probeLog) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.probed)
}

// fakeProbe answers 20.0 ms, nil for addresses ending .12.
func stubProbe(h *harness) *probeLog {
	log := &probeLog{}
	h.srv.probe = func(ip string) *float64 {
		log.mu.Lock()
		log.probed = append(log.probed, ip)
		log.mu.Unlock()
		if strings.HasSuffix(ip, ".12") {
			return nil
		}
		ms := 20.0
		return &ms
	}
	return log
}

func latencyMap(values []Latency) map[string]*float64 {
	out := map[string]*float64{}
	for _, v := range values {
		out[v.Hostname] = v.MS
	}
	return out
}

func TestCitySweepProbesOneRelayPerCity(t *testing.T) {
	targets := latencyTargets(map[string][]string{"scope": {"cities"}}, sampleRelays())
	sort.Strings(targets)
	if !reflect.DeepEqual(targets, []string{"se-sto-wg-001", "us-nyc-wg-301"}) {
		t.Fatalf("targets = %v", targets)
	}
}

func TestCountryAndHostTargetsIgnoreUnlistedNames(t *testing.T) {
	h := newSingleHarness(t, nil)
	stubProbe(h)
	relays := sampleRelays()
	targets := latencyTargets(map[string][]string{"country": {"Sweden"}, "hosts": {"evil-wg-001,us-nyc-wg-301"}}, relays)
	got := h.srv.measureLatency(relays, targets, false, "")
	twenty := 20.0
	want := map[string]*float64{"se-sto-wg-001": &twenty, "se-sto-wg-002": &twenty, "us-nyc-wg-301": nil}
	if !reflect.DeepEqual(latencyMap(got), want) || len(got) != 3 {
		t.Fatalf("got %v", got)
	}
}

func TestCachedResultsAreNotReprobedUnlessFresh(t *testing.T) {
	h := newSingleHarness(t, nil)
	log := stubProbe(h)
	relays := sampleRelays()
	h.srv.measureLatency(relays, []string{"se-sto-wg-001"}, false, "")
	h.srv.measureLatency(relays, []string{"se-sto-wg-001"}, false, "")
	if log.count() != 1 {
		t.Fatalf("%d probes", log.count())
	}
	h.srv.measureLatency(relays, []string{"se-sto-wg-001"}, true, "")
	if log.count() != 2 {
		t.Fatalf("%d probes", log.count())
	}
}

func TestCachedResultsExpire(t *testing.T) {
	now := time.Now()
	h := newHarness(t, nil, func(o *Options) { o.Mono = func() time.Time { return now } })
	log := stubProbe(h)
	relays := sampleRelays()
	h.srv.measureLatency(relays, []string{"se-sto-wg-001"}, false, "")
	now = now.Add(latencyTTL - time.Second)
	h.srv.measureLatency(relays, []string{"se-sto-wg-001"}, false, "")
	if log.count() != 1 {
		t.Fatalf("%d probes before the TTL", log.count())
	}
	now = now.Add(2 * time.Second)
	h.srv.measureLatency(relays, []string{"se-sto-wg-001"}, false, "")
	if log.count() != 2 {
		t.Fatalf("%d probes after the TTL", log.count())
	}
}

func TestHostListIsCapped(t *testing.T) {
	var many []string
	for i := 0; i < 200; i++ {
		many = append(many, fmt.Sprintf("x%d-wg-001", i))
	}
	got := latencyTargets(map[string][]string{"hosts": {strings.Join(many, ",")}}, sampleRelays())
	if len(got) != maxProbeHosts {
		t.Fatalf("%d targets", len(got))
	}
}

type refusedDial struct{ err error }

func (r refusedDial) dial(context.Context, string, string) (net.Conn, error) { return nil, r.err }

func TestProbeCountsRefusedConnectionAsRoundTrip(t *testing.T) {
	refused := &net.OpError{Op: "dial", Err: &errnoWrap{syscall.ECONNREFUSED}}
	mono := time.Now
	if got := probeTCPRTT(refusedDial{refused}.dial, "198.51.100.10", 443, time.Second, 1, mono); got == nil {
		t.Error("a refused connection was not counted")
	}
	timeout := &net.OpError{Op: "dial", Err: errors.New("i/o timeout")}
	if got := probeTCPRTT(refusedDial{timeout}.dial, "198.51.100.10", 443, time.Second, 1, mono); got != nil {
		t.Error("a timeout was counted")
	}
}

type errnoWrap struct{ errno syscall.Errno }

func (e *errnoWrap) Error() string { return e.errno.Error() }
func (e *errnoWrap) Unwrap() error { return e.errno }

func TestProbeTimesARealHandshakeToLoopback(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	if got := probeTCPRTT((&net.Dialer{}).DialContext, "127.0.0.1", port, time.Second, 2, time.Now); got == nil || *got < 0 {
		t.Fatalf("rtt = %v", got)
	}
}

// -- LatencyBoundsTests ----------------------------------------------------------------

// bigland is n servers spread over `cities` cities, with loads that repeat.
func bigland(n, cities int) *providers.Entries {
	entries := providers.NewEntries()
	for i := 0; i < n; i++ {
		host := fmt.Sprintf("bg%04d.nordvpn.com", i)
		relay := &providers.Relay{Shape: providers.ShapeNordVPN, Hostname: host, Country: "Bigland",
			City: fmt.Sprintf("City %d", i%cities), IPv4AddrIn: fmt.Sprintf("198.51.100.%d", i%250)}
		if i%5 != 0 {
			load := int64((i * 7) % 100)
			relay.Load = &load
		}
		entries.Set(host, relay)
	}
	return entries
}

func TestNormalSizeCountryIsTimedWholeAsBefore(t *testing.T) {
	relays := bigland(maxCountryProbes, 3)
	probed, total := countrySample(relays, "Bigland")
	names := relays.Names()
	sort.Strings(names)
	if !reflect.DeepEqual(probed, names) || total != maxCountryProbes {
		t.Fatalf("probed %d of %d", len(probed), total)
	}
	if probed, total := countrySample(relays, "Elsewhere"); len(probed) != 0 || total != 0 {
		t.Fatalf("Elsewhere: %v %d", probed, total)
	}
}

func TestLargeCountryIsSampledTheSameWayEveryTime(t *testing.T) {
	relays := bigland(1900, 3)
	probed, total := countrySample(relays, "Bigland")
	if len(probed) != maxCountryProbes || total != 1900 {
		t.Fatalf("probed %d of %d", len(probed), total)
	}
	seen := map[string]bool{}
	for _, h := range probed {
		seen[h] = true
	}
	if len(seen) != len(probed) {
		t.Fatal("duplicates in the sample")
	}
	// The same whichever order the catalogue was built in.
	reversed := providers.NewEntries()
	names := relays.Names()
	for i := len(names) - 1; i >= 0; i-- {
		r, _ := relays.Get(names[i])
		reversed.Set(names[i], r)
	}
	again, _ := countrySample(reversed, "Bigland")
	if !reflect.DeepEqual(probed, again) {
		t.Fatal("the sample depends on catalogue order")
	}
	// Each city in turn, lowest load first; servers with no load last.
	cityOf := func(h string) string { r, _ := relays.Get(h); return r.City }
	if got := []string{cityOf(probed[0]), cityOf(probed[1]), cityOf(probed[2])}; !reflect.DeepEqual(got, []string{"City 0", "City 1", "City 2"}) {
		t.Fatalf("first three: %v", got)
	}
	for _, city := range []string{"City 0", "City 1", "City 2"} {
		var loads []*int64
		for _, h := range probed {
			if r, _ := relays.Get(h); r.City == city {
				loads = append(loads, r.Load)
			}
		}
		sawNone := false
		var last int64 = -1
		for _, l := range loads {
			if l == nil {
				sawNone = true
				continue
			}
			if sawNone || *l < last {
				t.Fatalf("%s: loads out of order", city)
			}
			last = *l
		}
	}
}

func TestTargetsAreCappedDeduplicatedAndKeepNamedHosts(t *testing.T) {
	relays := bigland(1900, 400)
	named := []string{"bg1899.nordvpn.com", "bg1898.nordvpn.com"}
	targets := latencyTargets(map[string][]string{"hosts": {strings.Join(append(append([]string{}, named...), named...), ",")},
		"scope": {"cities"}, "country": {"Bigland"}}, relays)
	if len(targets) != maxProbeTargets {
		t.Fatalf("%d targets", len(targets))
	}
	seen := map[string]bool{}
	for _, h := range targets {
		if seen[h] {
			t.Fatalf("%s twice", h)
		}
		seen[h] = true
	}
	if !reflect.DeepEqual(targets[:2], named) {
		t.Fatalf("first targets %v", targets[:2])
	}
}

func oneRelay(ip string) *providers.Entries {
	return mullvadRelays([3]string{"a", "X", ip})
}

func TestOneExitsSlowProbesDoNotBlockAnotherExit(t *testing.T) {
	h := newSingleHarness(t, nil)
	started, release := make(chan struct{}), make(chan struct{})
	h.srv.probe = func(ip string) *float64 {
		if ip == "198.51.100.1" {
			close(started)
			<-release
		}
		ms := 10.0
		return &ms
	}
	slow := make(chan struct{})
	go func() {
		h.srv.measureLatency(oneRelay("198.51.100.1"), []string{"a"}, false, "home")
		close(slow)
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the slow probe never started")
	}
	began := time.Now()
	got := h.srv.measureLatency(oneRelay("198.51.100.2"), []string{"a"}, false, "away")
	if len(got) != 1 || got[0].MS == nil || *got[0].MS != 10.0 {
		t.Fatalf("got %v", got)
	}
	if time.Since(began) > 2*time.Second {
		t.Fatal("the second exit waited for the first")
	}
	close(release)
	<-slow
}

func TestAHostAlreadyBeingProbedIsWaitedForNotProbedAgain(t *testing.T) {
	h := newSingleHarness(t, nil)
	started, release := make(chan struct{}, 4), make(chan struct{})
	var mu sync.Mutex
	var calls []string
	h.srv.probe = func(ip string) *float64 {
		mu.Lock()
		calls = append(calls, ip)
		mu.Unlock()
		started <- struct{}{}
		<-release
		ms := 12.0
		return &ms
	}
	relays := oneRelay("198.51.100.1")
	var wg sync.WaitGroup
	results := make([][]Latency, 2)
	wg.Add(1)
	go func() { defer wg.Done(); results[0] = h.srv.measureLatency(relays, []string{"a"}, false, "home") }()
	<-started
	wg.Add(1)
	go func() { defer wg.Done(); results[1] = h.srv.measureLatency(relays, []string{"a"}, true, "home") }()
	time.Sleep(100 * time.Millisecond)
	close(release)
	wg.Wait()
	if !reflect.DeepEqual(calls, []string{"198.51.100.1"}) {
		t.Fatalf("calls = %v", calls)
	}
	if len(results[1]) != 1 || results[1][0].MS == nil || *results[1][0].MS != 12.0 {
		t.Fatalf("second result %v", results[1])
	}
	if n := len(h.srv.latency.inflight); n != 0 {
		t.Fatalf("%d probes still in flight", n)
	}
}

func TestAdmissionIsOnePerExitAndBoundedPanelWide(t *testing.T) {
	l := newLatencyState()
	if !l.admit("home") || l.admit("home") {
		t.Fatal("one request per exit")
	}
	var others []string
	for i := 0; i < latencySlots-1; i++ {
		id := fmt.Sprintf("x%d", i)
		others = append(others, id)
		if !l.admit(id) {
			t.Fatalf("%s refused", id)
		}
	}
	if l.admit("away") {
		t.Fatal("more than latencySlots admitted")
	}
	l.release("home")
	if !l.admit("away") {
		t.Fatal("a freed slot was not reusable")
	}
	for _, id := range append(others, "away") {
		l.release(id)
	}
	if !l.admit("home") {
		t.Fatal("slots leaked")
	}
	l.release("home")
}

// -- LatencyEndpointTests ----------------------------------------------------------------------

func TestBusyExitGets429(t *testing.T) {
	h := newSingleHarness(t, nil)
	if !h.srv.latency.admit("") {
		t.Fatal("admit")
	}
	defer h.srv.latency.release("")
	a := h.get("/api/latency?scope=cities", "", nil)
	if a.Status != 429 || a.Header.Get("Retry-After") != "3" || a.Body != `{"error": "latency busy"}` {
		t.Fatalf("%d %v %q", a.Status, a.Header, a.Body)
	}
}

func TestCountryAnswerSaysHowManyWereTimed(t *testing.T) {
	h := newHarness(t, map[string]string{"PROVIDER": "nordvpn"}, nil)
	relays := map[string]any{}
	for i := 0; i < 300; i++ {
		host := fmt.Sprintf("bg%04d.nordvpn.com", i)
		relays[host] = nordEntry(host, fmt.Sprintf("City %d", i%3), "Bigland", "US", "us-bigland", i%100, false, fmt.Sprintf("198.51.100.%d", i%250))
	}
	mustWrite(t, h.srv.Single.RelaysPath, map[string]any{"fetched_at": nowISO(), "provider": "nordvpn", "relays": relays})
	h.srv.probe = func(string) *float64 { ms := 5.0; return &ms }
	a := h.get("/api/latency?country=Bigland", "", nil)
	body := jsonBody(t, a)
	country, _ := body["country"].(map[string]any)
	if a.Status != 200 || country["probed"] != float64(maxCountryProbes) || country["total"] != float64(300) ||
		len(body["latency"].(map[string]any)) != maxCountryProbes {
		t.Fatalf("%d %v", a.Status, body["country"])
	}
	// The slot was given back.
	if !h.srv.latency.admit("") {
		t.Fatal("the slot leaked")
	}
	h.srv.latency.release("")
}

func TestLatencyAnswerIsInRequestOrder(t *testing.T) {
	h := newSingleHarness(t, nil)
	mustWrite(t, h.srv.Single.RelaysPath, catalogue(
		relayEntry("se-sto-wg-001", map[string]any{"ipv4_addr_in": "198.51.100.10"}),
		relayEntry("se-sto-wg-002", map[string]any{"ipv4_addr_in": "198.51.100.12"})))
	stubProbe(h)
	a := h.get("/api/latency?hosts=se-sto-wg-002,se-sto-wg-001,nope-wg-009", "", nil)
	if a.Body != `{"latency": {"se-sto-wg-002": null, "se-sto-wg-001": 20.0}}` {
		t.Fatalf("body = %s", a.Body)
	}
}
