package panel

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/irashack/molebridge/internal/panel/pystr"
)

// Host and Origin checks, ported from app.py. The allowlist never derives
// from request headers: a rebinding page controls them.

// hostPort is a lowercase host name and a port; port is -1 when none was
// given.
type hostPort struct {
	host string
	port int
}

var loopbackHosts = map[string]bool{"localhost": true, "127.0.0.1": true, "::1": true}

// splitHost is _split_host: (hostname, port) from a Host-style value; false
// when malformed.
func splitHost(value string) (hostPort, bool) {
	u, err := url.Parse("//" + pystr.Strip(value))
	if err != nil || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return hostPort{}, false
	}
	port, ok := parsePort(u.Port())
	if !ok {
		return hostPort{}, false
	}
	return hostPort{strings.ToLower(u.Hostname()), port}, true
}

// parsePort reads a URL's port text: -1 when empty, false when it is not a
// number from 0 to 65535 (Python's .port raises ValueError there).
func parsePort(text string) (int, bool) {
	if text == "" {
		return -1, true
	}
	port, err := strconv.Atoi(text)
	if err != nil || port < 0 || port > 65535 || strings.HasPrefix(text, "+") || strings.HasPrefix(text, "-") {
		return 0, false
	}
	return port, true
}

// hostAllowed is _host_allowed with the published hosts in hosts.
func hostAllowed(hosts []hostPort, h hostPort, defaultPort int) bool {
	if loopbackHosts[h.host] {
		return true // any port: SSH forwards and local proxies vary
	}
	for _, allowed := range hosts {
		if h.host != allowed.host {
			continue
		}
		if allowed.port == -1 {
			if h.port == -1 || h.port == defaultPort || h.port == 80 || h.port == 443 {
				return true
			}
		} else if h.port == allowed.port {
			return true
		}
	}
	return false
}

// parsePublicHosts is the list allowed_hosts builds from PANEL_PUBLIC_HOSTS
// (comma-separated Host-style values), plus the sign-in public URL's host
// when one is configured. A malformed entry stops the panel at start:
// app.py ignored one, and every request then got 421 with nothing at start
// to say why.
func parsePublicHosts(raw string, signIn *hostPort) ([]hostPort, error) {
	var hosts []hostPort
	for _, entry := range strings.Split(raw, ",") {
		if pystr.Strip(entry) == "" {
			continue
		}
		h, ok := splitHost(entry)
		if !ok {
			return nil, fmt.Errorf("PANEL_PUBLIC_HOSTS: entries are host names with an optional :port, "+
				"such as exit.example.net or host.docker.internal:8095 (no scheme or path), in %s", pystr.Repr(pystr.Strip(entry)))
		}
		hosts = append(hosts, h)
	}
	if signIn != nil {
		hosts = append(hosts, *signIn)
	}
	return hosts, nil
}

// HostAllowed rejects requests for names the panel is not published under.
// This keeps a DNS-rebinding page from reading status or a token-bearing
// page.
func (s *Settings) HostAllowed(hostHeader string) bool {
	if hostHeader == "" {
		return false
	}
	first, _, _ := strings.Cut(hostHeader, ",")
	h, ok := splitHost(first)
	return ok && hostAllowed(s.PublicHosts, h, -1)
}

// OriginAllowed is true unless an Origin header is present and names a host
// the panel is not published under. Browsers always send Origin on form and
// fetch POSTs; the request's own Host header is deliberately not trusted
// here, because a rebinding page controls it. The CSRF token remains the
// primary control.
func (s *Settings) OriginAllowed(origin string) bool {
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
		return false
	}
	if u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return false
	}
	defaultPort := 80
	if u.Scheme == "https" {
		defaultPort = 443
	}
	port, ok := parsePort(u.Port())
	if !ok {
		return false
	}
	if port <= 0 { // Python: `origin.port or default_port`
		port = defaultPort
	}
	return hostAllowed(s.PublicHosts, hostPort{strings.ToLower(u.Hostname()), port}, defaultPort)
}
