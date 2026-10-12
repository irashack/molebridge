package panel

import (
	"context"
	"errors"
	"math"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/irashack/molebridge/internal/providers"
)

// Lazy latency probing, ported from app.py: a TCP handshake round trip to
// the relay's port 443, which Mullvad relays and PIA's region servers
// accept; NordVPN's are expected to (untested). A refused connection still
// times the round trip. No ICMP, so no capabilities are needed.
const (
	probePort     = 443
	probeTimeout  = 1500 * time.Millisecond
	probeAttempts = 2
	probeWorkers  = 24
	latencyTTL    = 15 * time.Minute
	maxProbeHosts = 64
	// A country larger than this is timed on a sample: the lowest-load
	// servers, taken in turn from each city, so a large provider cannot turn
	// one click into thousands of connections. A smaller country is timed
	// whole, as before.
	maxCountryProbes = 128
	// Every target of one latency request, after duplicates are dropped.
	maxProbeTargets = 256
	// Latency requests running at once, panel-wide, and per exit. A request
	// that finds no free slot is answered 429 at once, before it loads
	// anything.
	latencySlots = 4
	// How long a request waits for probes another request already started.
	probeWait = 60 * time.Second
)

// DialFunc opens a connection, as net.Dialer.DialContext.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// probeTCPRTT is the best TCP handshake time in ms over the attempts, or nil
// if every attempt failed. A refused connection still completes a round
// trip, so it counts.
func probeTCPRTT(dial DialFunc, ip string, port int, timeout time.Duration, attempts int, mono func() time.Time) *float64 {
	var best *float64
	address := net.JoinHostPort(ip, strconv.Itoa(port))
	for i := 0; i < attempts; i++ {
		start := mono()
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		conn, err := dial(ctx, "tcp", address)
		cancel()
		switch {
		case err == nil:
			conn.Close()
		case errors.Is(err, syscall.ECONNREFUSED):
		default:
			continue
		}
		ms := float64(mono().Sub(start)) / float64(time.Millisecond)
		if best == nil || ms < *best {
			best = &ms
		}
	}
	if best == nil {
		return nil
	}
	rounded := math.Round(*best*10) / 10
	return &rounded
}

type probeKey struct{ scope, hostname string }

type probeResult struct {
	ms *float64
	at time.Time
}

// latencyState is the process-lifetime probe state: the cache, the probes in
// flight and the admission table.
type latencyState struct {
	// mu guards the cache and the in-flight table only; it is never held
	// while probing.
	mu       sync.Mutex
	cache    map[probeKey]probeResult
	inflight map[probeKey]chan struct{}

	admission sync.Mutex
	exits     map[string]bool
}

func newLatencyState() *latencyState {
	return &latencyState{cache: map[probeKey]probeResult{}, inflight: map[probeKey]chan struct{}{}, exits: map[string]bool{}}
}

// admit takes a latency slot for this exit: one request per exit,
// latencySlots panel-wide. False means busy; the caller answers 429.
func (l *latencyState) admit(exitID string) bool {
	l.admission.Lock()
	defer l.admission.Unlock()
	if l.exits[exitID] || len(l.exits) >= latencySlots {
		return false
	}
	l.exits[exitID] = true
	return true
}

func (l *latencyState) release(exitID string) {
	l.admission.Lock()
	delete(l.exits, exitID)
	l.admission.Unlock()
}

// Latency is one hostname's measured round trip, nil when unreachable.
type Latency struct {
	Hostname string
	MS       *float64
}

// measureLatency returns the latency for each listed hostname present in the
// catalogue, probing only entries missing from or stale in the cache (or all,
// when fresh). scope is the exit id: each exit's names are cached apart. A
// host another request is probing right now is waited for, not probed
// again; no lock is held while probing, so one exit's probes never hold up
// another's.
func (s *Server) measureLatency(relays *providers.Entries, hostnames []string, fresh bool, scope string) []Latency {
	seen := map[string]bool{}
	var wanted []string
	for _, h := range hostnames {
		if !seen[h] && relays.Has(h) {
			seen[h] = true
			wanted = append(wanted, h)
		}
	}
	l := s.latency
	type ownProbe struct {
		hostname string
		done     chan struct{}
	}
	var own []ownProbe
	var others []chan struct{}
	l.mu.Lock()
	now := s.mono()
	for _, hostname := range wanted {
		key := probeKey{scope, hostname}
		if done, running := l.inflight[key]; running {
			others = append(others, done)
			continue
		}
		cached, have := l.cache[key]
		if fresh || !have || now.Sub(cached.at) > latencyTTL {
			done := make(chan struct{})
			l.inflight[key] = done
			own = append(own, ownProbe{hostname, done})
		}
	}
	l.mu.Unlock()

	func() {
		defer func() {
			l.mu.Lock()
			for _, p := range own {
				delete(l.inflight, probeKey{scope, p.hostname})
				close(p.done)
			}
			l.mu.Unlock()
		}()
		if len(own) == 0 {
			return
		}
		results := make([]*float64, len(own))
		workers := probeWorkers
		if len(own) < workers {
			workers = len(own)
		}
		jobs := make(chan int)
		var wg sync.WaitGroup
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range jobs {
					info, _ := relays.Get(own[i].hostname)
					results[i] = s.probe(info.IPv4AddrIn)
				}
			}()
		}
		for i := range own {
			jobs <- i
		}
		close(jobs)
		wg.Wait()
		measured := s.mono()
		l.mu.Lock()
		for i, p := range own {
			l.cache[probeKey{scope, p.hostname}] = probeResult{results[i], measured}
		}
		l.mu.Unlock()
	}()

	if len(others) > 0 {
		deadline := time.After(probeWait)
	wait:
		for _, done := range others {
			select {
			case <-done:
			case <-deadline:
				break wait
			}
		}
	}
	out := make([]Latency, 0, len(wanted))
	l.mu.Lock()
	for _, h := range wanted {
		out = append(out, Latency{h, l.cache[probeKey{scope, h}].ms})
	}
	l.mu.Unlock()
	return out
}

// cityRepresentatives is one relay per city (the lowest-numbered), for a
// whole-list sweep.
func cityRepresentatives(relays *providers.Entries) []string {
	type place struct{ country, city string }
	seen := map[place]bool{}
	var chosen []string
	for _, hostname := range sortedNames(relays) {
		info, _ := relays.Get(hostname)
		key := place{info.Country, info.City}
		if !seen[key] {
			seen[key] = true
			chosen = append(chosen, hostname)
		}
	}
	return chosen
}

// countrySample returns the servers to time and the servers in the country.
// Up to maxCountryProbes, chosen the same way every time: each city's servers
// ordered by load (unknown last), then name, taken one city at a time in turn.
func countrySample(relays *providers.Entries, country string) ([]string, int) {
	cities := map[string][]string{}
	for _, hostname := range sortedNames(relays) {
		info, _ := relays.Get(hostname)
		if info.Country == country {
			cities[info.City] = append(cities[info.City], hostname)
		}
	}
	total := 0
	for _, hosts := range cities {
		total += len(hosts)
	}
	cityNames := make([]string, 0, len(cities))
	for city := range cities {
		cityNames = append(cityNames, city)
	}
	sort.Strings(cityNames)
	if total <= maxCountryProbes {
		var all []string
		for _, city := range cityNames {
			all = append(all, cities[city]...)
		}
		sort.Strings(all)
		return all, total
	}
	load := func(hostname string) int64 {
		info, _ := relays.Get(hostname)
		if info.Load != nil {
			return *info.Load
		}
		return 101
	}
	queues := make([][]string, 0, len(cityNames))
	for _, city := range cityNames {
		queue := append([]string(nil), cities[city]...)
		sort.SliceStable(queue, func(i, j int) bool {
			if li, lj := load(queue[i]), load(queue[j]); li != lj {
				return li < lj
			}
			return queue[i] < queue[j]
		})
		queues = append(queues, queue)
	}
	var chosen []string
	for depth := 0; len(chosen) < maxCountryProbes; depth++ {
		for _, queue := range queues {
			if depth < len(queue) {
				chosen = append(chosen, queue[depth])
			}
		}
	}
	return chosen[:maxCountryProbes], total
}

// latencyTargets is at most maxProbeTargets: the named hosts first, then the
// city sweep, then a country's servers (sampled when it is large).
func latencyTargets(query map[string][]string, relays *providers.Entries) []string {
	var targets []string
	for _, h := range strings.Split(first(query, "hosts"), ",") {
		if h != "" {
			targets = append(targets, h)
		}
	}
	if len(targets) > maxProbeHosts {
		targets = targets[:maxProbeHosts]
	}
	if first(query, "scope") == "cities" {
		targets = append(targets, cityRepresentatives(relays)...)
	}
	if country := first(query, "country"); country != "" {
		sample, _ := countrySample(relays, country)
		targets = append(targets, sample...)
	}
	seen := map[string]bool{}
	var unique []string
	for _, h := range targets {
		if !seen[h] {
			seen[h] = true
			unique = append(unique, h)
		}
	}
	if len(unique) > maxProbeTargets {
		unique = unique[:maxProbeTargets]
	}
	return unique
}
