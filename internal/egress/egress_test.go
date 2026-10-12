// Tests for molebridge/egress.py, ported from the pure-check section of
// tools/test_egress.py (test_echo_services_are_two_independent_https_hosts_per_
// family through test_only_independent_evidence_show_a_host_without_ipv6). The
// rest of that file drives the applier's tunnel_egress against a fake kernel
// and belongs to the applier port; its status-model tests are in
// internal/state and internal/verdict.
package egress

import (
	"fmt"
	"strings"
	"testing"

	"github.com/irashack/molebridge/internal/validate"
)

const (
	tunnelIP  = "203.0.113.10"
	hostIP    = "198.51.100.99"
	tunnelIP6 = "2001:db8:3::10"
	hostIP6   = "2001:db8:4::99"
)

func js(t testing.TB, text string) any {
	t.Helper()
	v, err := validate.DecodeJSONString(text)
	if err != nil {
		t.Fatalf("%v in %s", err, text)
	}
	return v
}

func TestEchoServicesAreTwoIndependentHTTPSHostsPerFamily(t *testing.T) {
	for family, urls := range EchoURLs {
		hosts := map[string]bool{}
		for _, url := range urls {
			if !strings.HasPrefix(url, "https://") {
				t.Errorf("%d: %s", family, url)
			}
			host := strings.Split(url, "/")[2]
			_, domain, _ := strings.Cut(host, ".")
			hosts[domain] = true
		}
		if len(urls) != 2 || len(hosts) != 2 {
			t.Errorf("family %d: %v", family, urls)
		}
	}
	if EchoMaxBytes != 256 || HostLacksFamily != "host-lacks-family" {
		t.Error("constants")
	}
}

func TestEchoAnswersAreParsedToCanonicalAddresses(t *testing.T) {
	for _, tc := range []struct {
		raw      string
		family   int
		expected string
	}{
		{"203.0.113.10\n", 4, "203.0.113.10"}, {"  203.0.113.10\r\n", 4, "203.0.113.10"},
		{"2001:DB8:3:0::10\n", 6, "2001:db8:3::10"}, {"\t2001:db8:3::10 ", 6, "2001:db8:3::10"},
	} {
		if got, err := ParseEcho(tc.raw, tc.family); err != nil || got != tc.expected {
			t.Errorf("ParseEcho(%q, %d) = %q, %v", tc.raw, tc.family, got, err)
		}
	}
}

func TestEchoAnswersThatAreNotOneUsableAddressAreRefused(t *testing.T) {
	for _, tc := range []struct {
		raw    string
		family int
	}{
		{"", 4}, {"\n", 4}, {"not an address", 4}, {"203.0.113.10 203.0.113.11", 4}, {"203.0.113.10", 6},
		{"2001:db8::1", 4}, {"127.0.0.1", 4}, {"0.0.0.0", 4}, {"::1", 6}, {"fe80::1", 6}, {"224.0.0.1", 4},
		{"203.0.113.10" + strings.Repeat(" ", 300), 4}, {`{"ip": "203.0.113.10"}`, 4},
		{"203.0.113.010", 4}, {"203.0.113.10 x", 4}, {"203.0.113.10\x1f1", 4}, {"169.254.1.1", 4}, {"ff02::1", 6},
		{"::", 6}, {"203.0.113.10", 5}, {"203.0.113.10", 0}, {"2001:db8::1%eth0", 6},
		{"::ffff:127.0.0.1", 6}, {"::ffff:169.254.1.1", 6},
	} {
		if got, err := ParseEcho(tc.raw, tc.family); err == nil {
			t.Errorf("ParseEcho(%q, %d) = %q", tc.raw, tc.family, got)
		}
	}
	// 256 characters is the limit, even where the answer would parse.
	if _, err := ParseEcho("203.0.113.10"+strings.Repeat("\n", 244), 4); err != nil {
		t.Errorf("256 characters: %v", err)
	}
	if _, err := ParseEcho("203.0.113.10"+strings.Repeat("\n", 245), 4); err == nil {
		t.Error("257 characters accepted")
	}
	// Errors never carry the answer.
	_, err := ParseEcho("SECRET-text", 4)
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Errorf("error echoes input: %v", err)
	}
}

func TestExitAddressesComeOnlyFromTheEntryAndItsFamily(t *testing.T) {
	relay := js(t, `{"exit_ips": ["203.0.113.10", "2001:db8:3::10", "bogus", 7, "203.0.113.011"]}`)
	if got := ExitAddresses(relay, 4); len(got) != 1 || !got["203.0.113.10"] {
		t.Errorf("v4: %v", got)
	}
	if got := ExitAddresses(relay, 6); len(got) != 1 || !got["2001:db8:3::10"] {
		t.Errorf("v6: %v", got)
	}
	for _, relay := range []string{`null`, `{}`, `{"exit_ips": []}`, `{"exit_ips": "x"}`, `{"exit_ips": ["bogus"]}`, `[]`, `"x"`} {
		if got := ExitAddresses(js(t, relay), 4); got != nil {
			t.Errorf("%s: %v", relay, got)
		}
	}
	if got := ExitAddresses(js(t, `{"exit_ips": ["2001:db8:3::10"]}`), 4); got != nil {
		t.Errorf("wrong family: %v", got)
	}
	// Addresses are kept in canonical form.
	if got := ExitAddresses(js(t, `{"exit_ips": ["2001:DB8:3:0::10"]}`), 6); !got["2001:db8:3::10"] {
		t.Errorf("canonical: %v", got)
	}
}

func TestTunnelVerdictNeedsEveryCondition(t *testing.T) {
	age := func(n int) *int { return &n }
	expectedSet := func(a ...string) map[string]bool {
		m := map[string]bool{}
		for _, s := range a {
			m[s] = true
		}
		return m
	}
	for i, tc := range []struct {
		echoes   []string
		host     string
		expected map[string]bool
		age      *int
		ok       bool
	}{
		{[]string{tunnelIP, tunnelIP}, hostIP, nil, age(5), true},
		{[]string{tunnelIP6, tunnelIP6}, HostLacksFamily, nil, age(5), true},
		// A failed measurement is unverified, never skipped.
		{[]string{tunnelIP, tunnelIP}, "", nil, age(5), false},
		{[]string{tunnelIP6, tunnelIP6}, "", nil, age(5), false},
		{[]string{tunnelIP, tunnelIP}, hostIP, expectedSet(tunnelIP), age(5), true},
		{[]string{tunnelIP, tunnelIP}, hostIP, expectedSet("203.0.113.11"), age(5), false},
		{[]string{tunnelIP, "203.0.113.11"}, hostIP, nil, age(5), false},
		{[]string{tunnelIP}, hostIP, nil, age(5), false},
		{nil, hostIP, nil, age(5), false},
		{[]string{tunnelIP, tunnelIP}, tunnelIP, nil, age(5), false},
		{[]string{tunnelIP, tunnelIP}, hostIP, nil, nil, false},
		{[]string{tunnelIP, tunnelIP}, hostIP, nil, age(180), false},
		{[]string{tunnelIP, tunnelIP}, hostIP, nil, age(179), true},
		{[]string{tunnelIP, tunnelIP}, hostIP, nil, age(-1), false},
		{[]string{tunnelIP, tunnelIP}, hostIP, nil, age(0), true},
		{[]string{"", ""}, hostIP, nil, age(5), false},
		{[]string{tunnelIP, tunnelIP, tunnelIP}, hostIP, nil, age(5), true},
		{[]string{tunnelIP, tunnelIP, "203.0.113.11"}, hostIP, nil, age(5), false},
	} {
		if got := TunnelVerdict(tc.echoes, tc.host, tc.expected, tc.age, 180); got != tc.ok {
			t.Errorf("case %d: %v", i, got)
		}
	}
}

var ignore = map[string]bool{"mullvad": true, "wt0": true}

// What a namespace with no IPv6 of its own still lists, in every table.
func noHostRoutes6() string {
	return `[
 {"dst": "fe80::/64", "dev": "eth0", "protocol": "kernel", "metric": 256},
 {"dst": "2001:db8:1::/64", "dev": "wt0", "protocol": "kernel", "metric": 256},
 {"dst": "default", "dev": "mullvad", "table": "51821"},
 {"type": "unreachable", "dst": "default", "table": "51821", "metric": 4096},
 {"type": "local", "dst": "::1", "table": "local", "dev": "lo"},
 {"type": "local", "dst": "fe80::2", "table": "local", "dev": "eth0"},
 {"type": "local", "dst": "` + tunnelIP6 + `", "table": "local", "dev": "mullvad"},
 {"type": "anycast", "dst": "fe80::", "table": "local", "dev": "eth0"},
 {"type": "multicast", "dst": "ff00::/8", "table": "local", "dev": "eth0"}]`
}

func globalOn(name string) string {
	return fmt.Sprintf(`{"ifname": %q, "addr_info": [{"family": "inet6", "scope": "global", "local": %q, "prefixlen": 128}]}`, name, hostIP6)
}

func TestOnlyIndependentEvidenceShowsAHostWithoutIPv6(t *testing.T) {
	plus := func(extra string) string { return noHostRoutes6()[:len(noHostRoutes6())-1] + "," + extra + "]" }
	for i, tc := range []struct {
		routes, links string
		lacks         bool
	}{
		{`[]`, `[]`, true},
		{noHostRoutes6(), `[]`, true},
		{noHostRoutes6(), `[` + globalOn("mullvad") + `,` + globalOn("wt0") + `, {"ifname": "eth0", "addr_info": []}, {"ifname": "eth1"},
			{"ifname": "lo", "addr_info": [{"family": "inet6", "scope": "host", "local": "::1"}]}]`, true},
		// Any route that could carry the host's own IPv6, in any table.
		{`[{"dst": "default", "gateway": "fe80::1", "dev": "eth0"}]`, `[]`, false},
		{`[{"dst": "default", "gateway": "fe80::1", "dev": "eth0", "table": "200"}]`, `[]`, false},
		{`[{"dst": "2001:db8:4::/48", "dev": "eth0", "table": "200"}]`, `[]`, false},
		{`[{"type": "local", "dst": "` + hostIP6 + `", "table": "local", "dev": "lo"}]`, `[]`, false},
		{`[{"type": "unreachable", "dst": "default", "gateway": "fe80::1"}]`, `[]`, false},
		{`[{"dst": "not a prefix", "dev": "eth0"}]`, `[]`, false},
		{`[{"dev": "eth0"}]`, `[]`, false},
		{`["default"]`, `[]`, false},
		{plus(`{"dst": "default", "gateway": "fe80::1", "dev": "eth0"}`), `[]`, false},
		// More shapes of destination.
		{`[{"dst": "fe80::/10", "dev": "eth0"}]`, `[]`, true},
		{`[{"dst": "fe80::/9", "dev": "eth0"}]`, `[]`, false},
		{`[{"dst": "febf::/16", "dev": "eth0"}]`, `[]`, true},
		{`[{"dst": "fec0::/16", "dev": "eth0"}]`, `[]`, false},
		{`[{"dst": "fe80::1/64", "dev": "eth0"}]`, `[]`, true},
		{`[{"dst": "ff02::1", "dev": "eth0"}]`, `[]`, true},
		{`[{"dst": "::1", "dev": "lo"}]`, `[]`, true},
		{`[{"dst": "::1/128", "dev": "lo"}]`, `[]`, true},
		{`[{"dst": "::/0", "dev": "eth0"}]`, `[]`, false},
		{`[{"dst": "::/128", "dev": "eth0"}]`, `[]`, false},
		{`[{"dst": "fe80::/64/1", "dev": "eth0"}]`, `[]`, false},
		{`[{"dst": "fe80::/129", "dev": "eth0"}]`, `[]`, false},
		{`[{"dst": "fe80::/-1", "dev": "eth0"}]`, `[]`, false},
		{`[{"dst": "fe80::/", "dev": "eth0"}]`, `[]`, false},
		{`[{"dst": "fe80::%eth0/64", "dev": "eth0"}]`, `[]`, false},
		{`[{"dst": 5, "dev": "eth0"}]`, `[]`, false},
		{`[{"type": "blackhole", "dst": "default"}]`, `[]`, true},
		{`[{"type": "prohibit", "dst": "2001:db8::/32", "via": {"gw": "x"}}]`, `[]`, false},
		{`[{"type": "throw", "dst": "default", "nexthops": []}]`, `[]`, false},
		{`[{"dev": 5, "dst": "default"}]`, `[]`, false},
		// A global address anywhere but the tunnel and the overlay, loopback included.
		{`[]`, `[` + globalOn("eth0") + `]`, false},
		{`[]`, `[` + globalOn("lo") + `]`, false},
		{`[]`, `[{"ifname": "lo", "addr_info": [{"family": "inet6", "local": "` + hostIP6 + `"}]}]`, false},
		{`[]`, `[{"ifname": "eth0", "addr_info": "x"}]`, false},
		{`[]`, `[{"ifname": "eth0", "addr_info": null}]`, false},
		{`[]`, `[{"addr_info": []}]`, false},
		{`[]`, `["eth0"]`, false},
		{`[]`, `[{"ifname": "eth0", "addr_info": ["x"]}]`, false},
		{`[]`, `[{"ifname": "eth0", "addr_info": [{"family": "inet", "scope": "global", "local": "198.51.100.5"}]}]`, true},
		{`[]`, `[{"ifname": "eth0", "addr_info": [{"family": "inet6", "scope": "link", "local": "fe80::1"}]}]`, true},
		{`null`, `[]`, false}, {`{}`, `[]`, false}, {`[]`, `null`, false},
	} {
		if got := HostLacksIPv6(js(t, tc.routes), js(t, tc.links), ignore); got != tc.lacks {
			t.Errorf("case %d: %s / %s -> %v", i, tc.routes, tc.links, got)
		}
	}
}

func FuzzParseEcho(f *testing.F) {
	for _, s := range []string{"203.0.113.10\n", "2001:db8::1", "", "::ffff:1.2.3.4", "fe80::1%eth0", " 1.2.3.4 "} {
		f.Add(s, 4)
		f.Add(s, 6)
	}
	f.Fuzz(func(t *testing.T, raw string, family int) {
		address, err := ParseEcho(raw, family)
		if err != nil {
			return
		}
		// What is accepted is canonical and parses again to itself.
		again, err := ParseEcho(address, family)
		if err != nil || again != address {
			t.Fatalf("%q -> %q -> %q (%v)", raw, address, again, err)
		}
	})
}

func FuzzHostLacksIPv6(f *testing.F) {
	f.Add([]byte(`[{"dst": "fe80::/64", "dev": "eth0"}]`), []byte(`[{"ifname": "lo", "addr_info": []}]`))
	f.Fuzz(func(t *testing.T, routes, links []byte) {
		r, err1 := validate.DecodeJSON(routes)
		l, err2 := validate.DecodeJSON(links)
		if err1 != nil || err2 != nil {
			return
		}
		HostLacksIPv6(r, l, ignore) // never panics
	})
}
