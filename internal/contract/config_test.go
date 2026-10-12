package contract

// Ported from tools/test_runtime.py (test_unsafe_configuration_is_refused),
// tools/test_gluetun.py (test_gluetun_config_validation,
// test_wireguard_config_ignores_gluetun_settings, test_control_mark_value) and
// tools/test_host_and_routing.py (test_bad_config_makes_no_routing_changes).

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func env(kv map[string]string) func(string) string {
	return func(k string) string { return kv[k] }
}

func base(extra map[string]string) map[string]string {
	m := map[string]string{"OVERLAY_CIDR": "192.0.2.0/24"}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func TestUnsafeConfigurationIsRefused(t *testing.T) { // test_unsafe_configuration_is_refused
	for name, extra := range map[string]map[string]string{
		"table in the reserved range": {"EXIT_TABLE": "254"},
		"table zero":                  {"EXIT_TABLE": "0"},
		"leading zero":                {"EXIT_TABLE": "0256"},
		"default route overlay":       {"OVERLAY_CIDR": "0.0.0.0/0"},
		"overlay named as the tunnel": {"OVERLAY_IF": "mullvad"},
		"path as interface":           {"OVERLAY_IF": "../bad"},
		"IPv6 default route":          {"OVERLAY6_CIDR": "::/0"},
		"host bits":                   {"OVERLAY_CIDR": "192.0.2.5/24"},
		"no overlay":                  {"OVERLAY_CIDR": ""},
		"IPv6 host bits":              {"OVERLAY6_CIDR": "2001:db8:1::5/64"},
		"IPv4 in the IPv6 setting":    {"OVERLAY6_CIDR": "192.0.2.0/24"},
		"table above range":           {"EXIT_TABLE": "2147483648"},
		"non numeric table":           {"EXIT_TABLE": "5x"},
	} {
		if _, err := ConfigFromEnv(env(base(extra))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRefusalMessages(t *testing.T) {
	cases := []struct {
		extra map[string]string
		want  string
	}{
		{map[string]string{"OVERLAY_IF": "../bad"}, "invalid interface name"},
		{map[string]string{"OVERLAY_IF": "mullvad"}, "overlay and exit interfaces must differ"},
		{map[string]string{"EXIT_TABLE": "x"}, "EXIT_TABLE must be numeric"},
		{map[string]string{"EXIT_TABLE": "0256"}, "EXIT_TABLE must be canonical decimal"},
		{map[string]string{"EXIT_TABLE": "254"}, "EXIT_TABLE must be 256..2147483647"},
		{map[string]string{"EXIT_TABLE": "99999999999"}, "EXIT_TABLE must be 256..2147483647"},
		{map[string]string{"OVERLAY_CIDR": "192.0.2.0"}, "OVERLAY_CIDR must be an IPv4 CIDR"},
		{map[string]string{"OVERLAY_CIDR": "192.0.2.0/x"}, "invalid IPv4 prefix"},
		{map[string]string{"OVERLAY_CIDR": "192.0.2.0/"}, "invalid IPv4 prefix"},
		{map[string]string{"OVERLAY_CIDR": "192.0.2.0/33"}, "invalid IPv4 prefix"},
		{map[string]string{"OVERLAY_CIDR": "0.0.0.0/0"}, "IPv4 default routes and leading zeroes are forbidden"},
		{map[string]string{"OVERLAY_CIDR": "192.0.2.0/08"}, "IPv4 default routes and leading zeroes are forbidden"},
		{map[string]string{"OVERLAY_CIDR": "192.0.2/24"}, "IPv4 address needs four octets"},
		{map[string]string{"OVERLAY_CIDR": "192.0.x.0/24"}, "invalid IPv4 octet"},
		{map[string]string{"OVERLAY_CIDR": "192.0.256.0/24"}, "invalid IPv4 octet"},
		{map[string]string{"OVERLAY_CIDR": "192.0.02.0/24"}, "IPv4 leading zeroes are forbidden"},
		{map[string]string{"OVERLAY_CIDR": "192.0.2.5/24"}, "OVERLAY_CIDR must use the network address"},
		{map[string]string{"OVERLAY6_CIDR": "2001:db8:1::"}, "OVERLAY6_CIDR must be an IPv6 CIDR"},
		{map[string]string{"OVERLAY6_CIDR": "::/0"}, "invalid IPv6 prefix"},
		{map[string]string{"OVERLAY6_CIDR": "::1/129"}, "invalid IPv6 prefix"},
		{map[string]string{"OVERLAY6_CIDR": "2001:db8::1::/64"}, "invalid OVERLAY6_CIDR"},
		{map[string]string{"OVERLAY6_CIDR": "2001:db8:g::/64"}, "invalid OVERLAY6_CIDR"},
		{map[string]string{"TUNNEL_BACKEND": "other"}, "TUNNEL_BACKEND must be native or gluetun"},
		{map[string]string{"EXIT_KIND": "other"}, "EXIT_KIND must be overlay or sidecar"},
	}
	for _, c := range cases {
		_, err := ConfigFromEnv(env(base(c.extra)))
		if err == nil || err.Error() != c.want {
			t.Errorf("%v: got %v, want %q", c.extra, err, c.want)
		}
	}
}

func TestNativeDefaults(t *testing.T) {
	c, err := ConfigFromEnv(env(base(map[string]string{"OVERLAY6_CIDR": "2001:DB8:1:0::/64"})))
	if err != nil {
		t.Fatal(err)
	}
	want := nativeConfig()
	if c != want {
		t.Fatalf("%+v\n%+v", c, want)
	}
	// An empty setting is an unset one, as `${NAME:-default}` read it.
	c, err = ConfigFromEnv(env(base(map[string]string{"EXIT_IF": "", "EXIT_TABLE": ""})))
	if err != nil || c.ExitIf != "mullvad" || c.Table != 51821 || c.Overlay6.IsValid() {
		t.Fatalf("%+v %v", c, err)
	}
	// EXIT_IF's default follows the backend: mullvad natively, wg0 with gluetun
	// (as the NetBird profile check and the sidecar already had it); "native" is
	// the Compose files' spelling of the native backend.
	for _, tc := range []struct{ backend, want string }{
		{"", "mullvad"}, {"wireguard", "mullvad"}, {"native", "mullvad"}, {"gluetun", "wg0"},
	} {
		m := base(map[string]string{"TUNNEL_BACKEND": tc.backend, "EXIT_IF": ""})
		if c, err = ConfigFromEnv(env(m)); err != nil || c.ExitIf != tc.want {
			t.Errorf("TUNNEL_BACKEND=%q: EXIT_IF %q, %v; want %q", tc.backend, c.ExitIf, err, tc.want)
		}
	}
	if c, err = ConfigFromEnv(env(base(map[string]string{"OVERLAY_CIDR": "192.0.2.7/32"}))); err != nil || c.Overlay != netip.MustParsePrefix("192.0.2.7/32") {
		t.Fatalf("a host overlay range: %+v %v", c, err)
	}
}

func gl(extra map[string]string) map[string]string {
	m := base(map[string]string{"TUNNEL_BACKEND": "gluetun", "OVERLAY6_CIDR": "2001:db8:1::/64", "EXIT_IF": "wg0"})
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func TestGluetunConfigValidation(t *testing.T) { // test_gluetun_config_validation
	cases := []struct {
		changes map[string]string
		message string
	}{
		{map[string]string{"EXIT_IF": "wg-0"}, "letters, digits"}, {map[string]string{"HOST_IF": "lo"}, "HOST_IF"},
		{map[string]string{"HOST_IF": "wg0"}, "HOST_IF"}, {map[string]string{"HOST_IF": "wt0"}, "HOST_IF"},
		{map[string]string{"HOST_TABLE": "51821"}, "differ"}, {map[string]string{"HOST_TABLE": "7120"}, "taken"},
		{map[string]string{"EXIT_TABLE": "51820"}, "taken"}, {map[string]string{"HOST_TABLE": "200"}, "HOST_TABLE"},
		{map[string]string{"CONTROL_MARK": "0x1bd01"}, "low byte"}, {map[string]string{"CONTROL_MARK": "0x1BD00"}, "hexadecimal"},
		{map[string]string{"CONTROL_MARK": "0x01bd00"}, "hexadecimal"}, {map[string]string{"TUNNEL_BACKEND": "other"}, "TUNNEL_BACKEND"},
		{map[string]string{"HOST_IF": "bad name"}, "invalid HOST_IF"},
		{map[string]string{"CONTROL_MARK": "0x1bd0000000"}, "hexadecimal"},
	}
	for _, c := range cases {
		_, err := ConfigFromEnv(env(gl(c.changes)))
		if err == nil || !strings.Contains(err.Error(), c.message) {
			t.Errorf("%v: got %v, want %q", c.changes, err, c.message)
		}
	}
	c, err := ConfigFromEnv(env(gl(nil)))
	if err != nil || c != gluetunConfig() {
		t.Fatalf("%+v %v", c, err)
	}
	c, err = ConfigFromEnv(env(gl(map[string]string{"HOST_IF": "enp3s0", "HOST_TABLE": "51900", "CONTROL_MARK": "0x2000"})))
	if err != nil || c.HostIf != "enp3s0" || c.HostTable != 51900 || c.ControlMark != 0x2000 {
		t.Fatalf("%+v %v", c, err)
	}
}

func TestWireguardConfigIgnoresGluetunSettings(t *testing.T) { // test_wireguard_config_ignores_gluetun_settings
	c, err := ConfigFromEnv(env(base(map[string]string{"HOST_TABLE": "junk", "EXIT_TABLE": "51820"})))
	if err != nil || c.Backend != Native || c.Table != 51820 || c.IsGluetun() {
		t.Fatalf("%+v %v", c, err)
	}
}

func TestControlMarkValue(t *testing.T) { // test_control_mark_value
	for in, want := range map[string]uint32{"0x1bd00": 0x1BD00, "0xffffff00": 0xFFFFFF00, "0x100": 0x100} {
		if got, err := ControlMarkValue(in); err != nil || got != want {
			t.Errorf("%q: %v %v", in, got, err)
		}
	}
	for _, bad := range []string{"0x0", "0x1bd00 ", "0x100000000", "bd00", "", "0x", "0X1bd00", "0x1bd0g", "0x1bd01"} {
		if _, err := ControlMarkValue(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestSidecarConfig(t *testing.T) {
	c, err := ConfigFromEnv(env(map[string]string{"EXIT_KIND": "sidecar", "TUNNEL_BACKEND": "gluetun"}))
	if err != nil || !c.IsSidecar() || c.ExitIf != "wg0" || c.Overlay.IsValid() {
		t.Fatalf("%+v %v", c, err)
	}
	if got := (Spec{Config: c}).Rules(4); got != nil {
		t.Fatalf("a sidecar has no contract: %v", got)
	}
	for in, want := range map[string]map[string]string{
		"EXIT_KIND=sidecar needs TUNNEL_BACKEND=gluetun":                      {"EXIT_KIND": "sidecar"},
		"with gluetun, EXIT_IF may hold only letters, digits and underscores": {"EXIT_KIND": "sidecar", "TUNNEL_BACKEND": "gluetun", "EXIT_IF": "wg-0"},
	} {
		if _, err := ConfigFromEnv(env(want)); err == nil || err.Error() != in {
			t.Errorf("%v: %v", want, err)
		}
	}
}

func TestReconcileInterval(t *testing.T) {
	for in, want := range map[string]time.Duration{"": 30 * time.Second, "2": 2 * time.Second, "60": time.Minute, "3": 3 * time.Second} {
		if got, err := ReconcileInterval(env(map[string]string{"ROUTING_RECONCILE_INTERVAL": in})); err != nil || got != want {
			t.Errorf("%q: %v %v", in, got, err)
		}
	}
	for _, bad := range []string{"1", "0", "61", "02", "x", "-2", "600", " 2"} {
		if _, err := ReconcileInterval(env(map[string]string{"ROUTING_RECONCILE_INTERVAL": bad})); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
