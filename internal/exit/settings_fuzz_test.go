package exit

// FuzzLoadSettings feeds the exit's whole configuration path arbitrary
// environment overrides on top of a good native overlay exit. The
// environment is the operator's, but it is also what a Compose file, an .env
// copied from a forum post or a templating mistake hands the exit, so a bad
// value must end in one refusal line, never a panic, a multi-line message
// or a settings value outside its documented range.

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func FuzzLoadSettings(f *testing.F) {
	for _, seed := range []string{
		"",
		"GUARD_GRACE=5\nROUTING_RECONCILE_INTERVAL=1",
		"GUARD_GRACE=31",
		"GUARD_GRACE=-1\nTUNNEL_BACKEND=wireguard",
		"EXIT_KIND=sidecar\nTUNNEL_BACKEND=native",
		"EXIT_KIND=sidecar\nTUNNEL_BACKEND=gluetun",
		"TUNNEL_BACKEND=gluetun",
		"PROVIDERS=mullvad,pia,nordvpn",
		"PROVIDERS=mullvad,,mullvad",
		"PROVIDER=pia\nPIA_PORT_FORWARD=on",
		"PROVIDER=nordvpn\nEXIT_IF=nordvpn\nNB_EXTRA_IFACE_BLACKLIST=nordvpn",
		"SERVER=se-sto-wg-001",
		"SERVER=../../etc/passwd",
		"SERVER=nordvpn/nl1.nordvpn.com\nPROVIDERS=mullvad,nordvpn",
		"OVERLAY_CIDR=0.0.0.0/0",
		"OVERLAY_CIDR=2001:db8::/32",
		"OVERLAY_CIDR=192.0.2.0/33",
		"OVERLAY_IF=mullvad",
		"EXIT_IF=wt0",
		"EXIT_IF=" + strings.Repeat("x", 40),
		"FAILOVER=on\nFAILOVER_SERVERS=se-sto-wg-001,se-sto-wg-002\nFAILOVER_AFTER=60",
		"FAILOVER=on\nFAILOVER_AFTER=0\nFAILOVER_RETURN=x",
		"STATE_GID=0",
		"STATE_GID=4294967296",
		"EXCHANGE_URL=http://exchange.example.test\nEXCHANGE_TOKEN=x\nEXCHANGE_EXIT_ID=a",
		"NB_ENABLE_ROSENPASS=true",
		"NB_DISABLE_USERSPACE_ROUTING=false",
		"TUNNEL_CONF_DIR=/nonexistent",
		"STATE_DIR=\x00",
		"PROVIDER=\xff\xfe",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, overrides string) {
		if len(overrides) > 4096 {
			return
		}
		fx := newFixture(t)
		for _, line := range strings.Split(overrides, "\n") {
			name, value, ok := strings.Cut(line, "=")
			if !ok || name == "" {
				continue
			}
			// Paths stay inside the fixture: the target is parsing, not the
			// host's file system.
			switch name {
			case "STATE_DIR", "TUNNEL_CONF_DIR", "NB_STATE_DIR", "MOLEBRIDGE_RUN_DIR", "PRIVATE_STATE_DIR":
				value = fx.dir + "/" + strings.ReplaceAll(value, "..", "")
			}
			fx.env[name] = value
		}
		s, err := fx.load()
		if err != nil {
			var refusal *Refusal
			if errors.As(err, &refusal) {
				if refusal.Line == "" || strings.ContainsAny(refusal.Line, "\n\r") {
					t.Fatalf("refusal is not one line: %q", refusal.Line)
				}
			}
			if strings.Contains(err.Error(), zeroKey) {
				t.Fatalf("refusal repeats the tunnel key: %q", err)
			}
			return
		}
		if s.Grace < 5*time.Second || s.Grace > 30*time.Second {
			t.Fatalf("GUARD_GRACE %q accepted as %v", fx.env["GUARD_GRACE"], s.Grace)
		}
		if s.Interval <= 0 {
			t.Fatalf("ROUTING_RECONCILE_INTERVAL %q accepted as %v", fx.env["ROUTING_RECONCILE_INTERVAL"], s.Interval)
		}
		if !s.Overlay() && !s.Routing.IsNativeSidecar() && s.Kind() == "" {
			t.Fatalf("accepted with no kind: %+v", s.Routing)
		}
		if s.MultiProvider() && len(s.Providers) < 2 {
			t.Fatalf("multi-provider with %v", s.Providers)
		}
		seen := map[string]bool{}
		for _, id := range s.Providers {
			if seen[id] {
				t.Fatalf("PROVIDERS %q accepted with a repeat: %v", fx.env["PROVIDERS"], s.Providers)
			}
			seen[id] = true
		}
	})
}
