package panel

// Ported from panel/test_app.py: CsrfAndOriginUnitTests (origin and host
// allowlists) and test_forwarded_host_header_is_not_trusted; plus parse_qs
// and request-target behaviour the Python server got from urllib.

import (
	"reflect"
	"testing"
)

func settingsWithHosts(raw string) *Settings {
	return &Settings{PublicHosts: parsePublicHosts(raw, nil)}
}

func TestOriginAllowlist(t *testing.T) {
	s := settingsWithHosts("exit.example.test, other.example.test:8443")
	for origin, want := range map[string]bool{
		"":                                true,
		"https://exit.example.test":       true,
		"https://exit.example.test:443":   true,
		"https://exit.example.test:8443":  false,
		"https://other.example.test:8443": true,
		"https://other.example.test":      false,
		"https://evil.example.com":        false,
		"https://exit.example.test/path":  false,
		"ftp://exit.example.test":         false,
		"http://[":                        false,
		"null":                            false,
		"https://user@exit.example.test":  false,
		"https://exit.example.test?x=1":   false,
		"https://exit.example.test:99999": false,
		"http://exit.example.test":        true,
		"http://exit.example.test:80":     true,
		"https://EXIT.example.test":       true,
	} {
		if got := s.OriginAllowed(origin); got != want {
			t.Errorf("OriginAllowed(%q) = %v, want %v", origin, got, want)
		}
	}
	// Loopback is always acceptable, on any port: SSH forwards vary.
	none := settingsWithHosts("")
	for origin, want := range map[string]bool{
		"http://[::1]:8095": true, "http://127.0.0.1:9000": true, "http://localhost:8095": true,
		"https://exit.example.test": false,
	} {
		if got := none.OriginAllowed(origin); got != want {
			t.Errorf("OriginAllowed(%q) with no hosts = %v, want %v", origin, got, want)
		}
	}
}

func TestHostAllowlist(t *testing.T) {
	s := settingsWithHosts("exit.example.test,host.docker.internal:8095")
	for host, want := range map[string]bool{
		"exit.example.test": true, "exit.example.test:443": true, "EXIT.example.test": true,
		"exit.example.test:8095": false, "host.docker.internal:8095": true, "host.docker.internal": false,
		"evil.example.com:8095": false, "exit.example.test@evil.example.com": false, "": false,
		"exit.example.test, evil.example.com": true, // only the first of a comma list counts
		"evil.example.com, exit.example.test": false,
	} {
		if got := s.HostAllowed(host); got != want {
			t.Errorf("HostAllowed(%q) = %v, want %v", host, got, want)
		}
	}
	none := settingsWithHosts("")
	for host, want := range map[string]bool{"127.0.0.1:8095": true, "[::1]:8095": true, "localhost": true, "exit.example.test": false} {
		if got := none.HostAllowed(host); got != want {
			t.Errorf("HostAllowed(%q) with no hosts = %v, want %v", host, got, want)
		}
	}
}

func TestForwardedHostHeaderIsNotTrusted(t *testing.T) {
	s := settingsWithHosts("exit.example.test")
	if !s.OriginAllowed("https://exit.example.test") || s.OriginAllowed("https://evil.example") || s.HostAllowed("evil.example:8095") {
		t.Fatal("the allowlist is wrong")
	}
	none := settingsWithHosts("")
	if none.OriginAllowed("https://exit.example.test") || none.HostAllowed("exit.example.test") {
		t.Fatal("an unlisted name was allowed")
	}
}

func TestSignInPublicHostIsAllowed(t *testing.T) {
	s := &Settings{PublicHosts: parsePublicHosts("", &hostPort{"exit.example.test", -1})}
	if !s.HostAllowed("exit.example.test") || !s.OriginAllowed("https://exit.example.test") {
		t.Fatal("PANEL_PUBLIC_URL's host is not allowed")
	}
}

func TestParseQS(t *testing.T) {
	for _, tc := range []struct {
		in   string
		keep bool
		want map[string][]string
	}{
		{"exit=a&exit=b&x=1", false, map[string][]string{"exit": {"a", "b"}, "x": {"1"}}},
		{"exit=&x", false, map[string][]string{}},
		{"exit=&x", true, map[string][]string{"exit": {""}, "x": {""}}},
		{"a=%41%zz+b&&c=%e2%82", false, map[string][]string{"a": {"A%zz b"}, "c": {"�"}}},
		{"x%20y=1", false, map[string][]string{"x y": {"1"}}},
		{"a=1;b=2", false, map[string][]string{"a": {"1;b=2"}}},
	} {
		if got := parseQS(tc.in, tc.keep); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("parseQS(%q, %v) = %v, want %v", tc.in, tc.keep, got, tc.want)
		}
	}
}

func TestParseSelectForm(t *testing.T) {
	got := parseSelectForm([]byte("server=se-sto-wg-001&csrf_token=abc&server=other&empty=&exit=a%20b\xff"))
	want := map[string]string{"server": "se-sto-wg-001", "csrf_token": "abc", "empty": "", "exit": "a b�"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseSelectForm = %v, want %v", got, want)
	}
}

func TestSplitTarget(t *testing.T) {
	for target, want := range map[string][2]string{
		"/":                               {"/", ""},
		"/api/latency?hosts=a,b&fresh=1":  {"/api/latency", "hosts=a,b&fresh=1"},
		"/static/panel%2ejs":              {"/static/panel%2ejs", ""},
		"//healthz":                       {"", ""},
		"//host/healthz":                  {"/healthz", ""},
		"http://example.test/healthz?x=1": {"/healthz", "x=1"},
		"/x#frag":                         {"/x", ""},
		"/private.example.test?token=ex":  {"/private.example.test", "token=ex"},
	} {
		if path, query := splitTarget(target); path != want[0] || query != want[1] {
			t.Errorf("splitTarget(%q) = %q, %q; want %q, %q", target, path, query, want[0], want[1])
		}
	}
}
