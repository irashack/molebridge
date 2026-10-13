// Ported from tools/test_host_and_routing.py (the NetBird gate's settings
// tests: test_netbird_gate_refuses_unsupported_netbird_settings,
// test_netbird_gate_accepts_settings_that_keep_kernel_mode), from
// tools/test_gluetun.py (test_gluetun_gate_refuses_bad_settings,
// test_gluetun_gate_accepts_values_netbird_reads_as_false,
// test_gluetun_gate_check_config_covers_the_gluetun_settings) and from the
// gate cases of tools/check-routing.sh. The routing contract's own settings
// (HOST_TABLE, HOST_IF, OVERLAY_CIDR, EXIT_TABLE, CONTRACT_RULES) are the
// routing code's and are not ported here.
package nbprofile

import (
	"strings"
	"testing"
	"time"
)

func baseEnv(extra map[string]string) map[string]string {
	env := map[string]string{
		"NB_INTERFACE_NAME":            "mesh0",
		"NB_DISABLE_USERSPACE_ROUTING": "true",
	}
	for k, v := range extra {
		env[k] = v
	}
	return env
}

func gluetunEnv(extra map[string]string) map[string]string {
	env := map[string]string{
		"TUNNEL_BACKEND":               "gluetun",
		"NB_INTERFACE_NAME":            "wt0",
		"NB_DISABLE_USERSPACE_ROUTING": "true",
		"NB_LOG_FILE":                  "console,/tmp/client.log",
		"NB_FWMARK_BASE":               "0x1bd00",
	}
	for k, v := range extra {
		env[k] = v
	}
	return env
}

func TestNetBirdGateRefusesUnsupportedNetBirdSettings(t *testing.T) {
	for _, c := range []struct{ name, value string }{
		{"NB_FORCE_USERSPACE_FIREWALL", "true"}, {"NB_FORCE_USERSPACE_FIREWALL", "1"},
		{"NB_FORCE_USERSPACE_ROUTER", "True"}, {"NB_USE_NETSTACK_MODE", "true"},
		{"NB_CONFIG", "/var/lib/netbird/peer.json"}, {"NB_CONFIG", ""}, {"WT_CONFIG", "/etc/netbird/config.json"},
		{"NB_PROFILE", "alternate"}, {"WT_PROFILE", ""},
		{"NB_FOREGROUND_MODE", "true"}, {"NB_FOREGROUND_MODE", "1"}, {"WT_FOREGROUND_MODE", "T"},
		{"NB_INTERFACE_NAME", ""}, {"WT_INTERFACE_NAME", "wt0"}, {"WT_INTERFACE_NAME", "other0"},
		{"NB_WG_KERNEL_DISABLED", "true"}, {"NB_ENABLE_ROSENPASS", "true"}, {"NB_ENABLE_ROSENPASS", "t"},
		{"NB_ENABLE_ROSENPASS", "1"}, {"WT_ENABLE_ROSENPASS", "TRUE"},
		{"NB_DISABLE_USERSPACE_ROUTING", "false"}, {"NB_DISABLE_USERSPACE_ROUTING", ""},
		{"NB_DISABLE_USERSPACE_ROUTING", "yes"},
	} {
		t.Run(c.name+"="+c.value, func(t *testing.T) {
			_, err := CheckEnv(baseEnv(map[string]string{c.name: c.value}), "")
			if err == nil {
				t.Fatalf("accepted %s=%q", c.name, c.value)
			}
			msg := err.Error()
			if !strings.HasPrefix(msg, "NetBird gate: refusing to start NetBird: "+c.name) ||
				!strings.HasSuffix(msg, " (see docs/troubleshooting.md)") {
				t.Fatalf("refusal = %q", msg)
			}
		})
	}
}

func TestNetBirdGateAcceptsSettingsThatKeepKernelMode(t *testing.T) {
	for _, c := range []struct{ name, value string }{
		{"NB_FORCE_USERSPACE_FIREWALL", "false"}, {"NB_FORCE_USERSPACE_ROUTER", "0"},
		{"NB_USE_NETSTACK_MODE", ""}, {"NB_ENABLE_ROSENPASS", "false"}, {"NB_ROSENPASS_PERMISSIVE", "true"},
		{"NB_DISABLE_USERSPACE_ROUTING", "1"}, {"NB_DISABLE_USERSPACE_ROUTING", "T"},
		// NetBird turns these two on only for the exact value "true".
		{"NB_USE_NETSTACK_MODE", "TRUE"}, {"NB_USE_NETSTACK_MODE", "1"}, {"NB_WG_KERNEL_DISABLED", "1"},
		{"NB_WG_KERNEL_DISABLED", "True"},
		{"NB_FOREGROUND_MODE", "false"}, {"WT_FOREGROUND_MODE", "0"}, {"WT_INTERFACE_NAME", "mesh0"},
	} {
		t.Run(c.name+"="+c.value, func(t *testing.T) {
			if _, err := CheckEnv(baseEnv(map[string]string{c.name: c.value}), ""); err != nil {
				t.Fatalf("refused %s=%q: %v", c.name, c.value, err)
			}
		})
	}
}

// The exact text of every settings refusal; the documentation quotes them.
func TestGateRefusalMessagesAreVerbatim(t *testing.T) {
	const frame = "NetBird gate: refusing to start NetBird: "
	const tail = " (see docs/troubleshooting.md)"
	kernel := "Molebridge needs kernel WireGuard and NetBird's kernel firewall"
	for _, c := range []struct {
		name    string
		env     map[string]string
		backend string
		want    string
	}{
		{"userspace firewall", baseEnv(map[string]string{"NB_FORCE_USERSPACE_FIREWALL": "t"}), "", frame + "NB_FORCE_USERSPACE_FIREWALL is set; " + kernel + tail},
		{"userspace router", baseEnv(map[string]string{"NB_FORCE_USERSPACE_ROUTER": "T"}), "", frame + "NB_FORCE_USERSPACE_ROUTER is set; " + kernel + tail},
		{"netstack", baseEnv(map[string]string{"NB_USE_NETSTACK_MODE": "true"}), "", frame + "NB_USE_NETSTACK_MODE is set; " + kernel + tail},
		{"kernel module", baseEnv(map[string]string{"NB_WG_KERNEL_DISABLED": "true"}), "", frame + "NB_WG_KERNEL_DISABLED is set; " + kernel + tail},
		{"userspace routing off", baseEnv(map[string]string{"NB_DISABLE_USERSPACE_ROUTING": "no"}), "", frame + `NB_DISABLE_USERSPACE_ROUTING must be "true" (compose.yaml sets it)` + tail},
		{"rosenpass", baseEnv(map[string]string{"WT_ENABLE_ROSENPASS": "1"}), "", frame + "WT_ENABLE_ROSENPASS is set; Rosenpass cannot work on this exit" + tail},
		{"foreground", baseEnv(map[string]string{"NB_FOREGROUND_MODE": "true"}), "", frame + "NB_FOREGROUND_MODE is set; Molebridge supports only NetBird's daemon mode" + tail},
		{"empty interface", baseEnv(map[string]string{"NB_INTERFACE_NAME": ""}), "", frame + "NB_INTERFACE_NAME is empty" + tail},
		{"other interface", baseEnv(map[string]string{"WT_INTERFACE_NAME": "other0"}), "", frame + "WT_INTERFACE_NAME is set and differs from the guarded interface mesh0" + tail},
		{"config path", baseEnv(map[string]string{"NB_CONFIG": "/x"}), "", frame + "NB_CONFIG is set; Molebridge supports only NetBird's default profile" + tail},
		{"profile", baseEnv(map[string]string{"WT_PROFILE": ""}), "", frame + "WT_PROFILE is set; Molebridge supports only NetBird's default profile" + tail},
		{"bad interface name", baseEnv(map[string]string{"NB_INTERFACE_NAME": "-x"}), "", "NetBird gate: invalid interface name"},
		{"long interface name", baseEnv(map[string]string{"NB_INTERFACE_NAME": "abcdefghijklmnop"}), "", "NetBird gate: invalid interface name"},
		{"dotted interface name", baseEnv(map[string]string{"NB_INTERFACE_NAME": "a b"}), "", "NetBird gate: invalid interface name"},
		{"backend", baseEnv(nil), "other", "NetBird gate: TUNNEL_BACKEND must be native or gluetun"},
		{"backend from env", baseEnv(map[string]string{"TUNNEL_BACKEND": "other"}), "", "NetBird gate: TUNNEL_BACKEND must be native or gluetun"},
		{"legacy routing", gluetunEnv(map[string]string{"NB_USE_LEGACY_ROUTING": "true"}), "", frame + "NB_USE_LEGACY_ROUTING is set; the gluetun backend needs NetBird to mark its control traffic" + tail},
		{"socket mark", gluetunEnv(map[string]string{"NB_SKIP_SOCKET_MARK": "1"}), "", frame + "NB_SKIP_SOCKET_MARK is set; the gluetun backend needs NetBird to mark its control traffic" + tail},
		{"custom routing", gluetunEnv(map[string]string{"NB_DISABLE_CUSTOM_ROUTING": "TRUE"}), "", frame + "NB_DISABLE_CUSTOM_ROUTING is set; the gluetun backend needs NetBird to mark its control traffic" + tail},
		{"mark characters", gluetunEnv(map[string]string{"CONTROL_MARK": "0x1BD00"}), "", frame + "CONTROL_MARK must be lowercase hexadecimal like 0x1bd00" + tail},
		{"mark low byte", gluetunEnv(map[string]string{"CONTROL_MARK": "0x1bd01"}), "", frame + "CONTROL_MARK must be lowercase hexadecimal like 0x1bd00, low byte zero" + tail},
		{"mark width", gluetunEnv(map[string]string{"CONTROL_MARK": "0x1bd000000"}), "", frame + "CONTROL_MARK must fit in 32 bits" + tail},
		{"fwmark base", gluetunEnv(map[string]string{"NB_FWMARK_BASE": "0x2bd00"}), "", frame + "NB_FWMARK_BASE must equal CONTROL_MARK (0x1bd00)" + tail},
		{"log file", gluetunEnv(map[string]string{"NB_LOG_FILE": "console"}), "", frame + "NB_LOG_FILE must name a log file; the gate reads it" + tail},
		{"fwmark grace", gluetunEnv(map[string]string{"FWMARK_GRACE": "31"}), "", frame + "FWMARK_GRACE must be 5..30 seconds" + tail},
		{"guard grace", baseEnv(map[string]string{"GUARD_GRACE": "4"}), "", frame + "GUARD_GRACE must be 5..30 seconds" + tail},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := CheckEnv(c.env, c.backend)
			if err == nil || err.Error() != c.want {
				t.Fatalf("CheckEnv error = %v, want %q", err, c.want)
			}
		})
	}
}

func TestGluetunGateRefusesBadSettings(t *testing.T) {
	for _, c := range []struct{ name, value string }{
		{"NB_USE_LEGACY_ROUTING", "true"}, {"NB_SKIP_SOCKET_MARK", "1"}, {"NB_DISABLE_CUSTOM_ROUTING", "T"},
		{"NB_DISABLE_CUSTOM_ROUTING", "TRUE"}, {"NB_FWMARK_BASE", "0x2bd00"}, {"NB_FWMARK_BASE", "0x1BD00"},
		{"NB_FWMARK_BASE", "113920"}, {"CONTROL_MARK", "0x1bd01"}, {"CONTROL_MARK", "0x1bd00 "},
		{"CONTROL_MARK", "0x1BD00"}, {"CONTROL_MARK", "113920"}, {"CONTROL_MARK", "0x01bd00"},
		{"CONTROL_MARK", "0x1bd000000"}, {"CONTROL_MARK", "0x"}, {"CONTROL_MARK", "0x100g"}, {"CONTROL_MARK", "0x0"},
		{"NB_LOG_FILE", "console"}, {"NB_LOG_FILE", "console,relative.log"},
		{"FWMARK_GRACE", "31"}, {"FWMARK_GRACE", "4"}, {"FWMARK_GRACE", "0"}, {"FWMARK_GRACE", "05"},
		{"FWMARK_GRACE", "5s"}, {"FWMARK_GRACE", "-5"}, {"FWMARK_GRACE", "100"},
	} {
		t.Run(c.name+"="+c.value, func(t *testing.T) {
			_, err := CheckEnv(gluetunEnv(map[string]string{c.name: c.value}), "")
			if err == nil || !strings.HasPrefix(err.Error(), "NetBird gate: refusing to start NetBird: ") {
				t.Fatalf("accepted %s=%q (err %v)", c.name, c.value, err)
			}
		})
	}
}

func TestGluetunGateAcceptsValuesNetBirdReadsAsFalse(t *testing.T) {
	for _, c := range []struct{ name, value string }{
		{"NB_USE_LEGACY_ROUTING", "false"}, {"NB_SKIP_SOCKET_MARK", "0"},
		{"NB_DISABLE_CUSTOM_ROUTING", "no"}, {"NB_FWMARK_BASE", ""},
	} {
		t.Run(c.name+"="+c.value, func(t *testing.T) {
			if _, err := CheckEnv(gluetunEnv(map[string]string{c.name: c.value}), ""); err != nil {
				t.Fatalf("refused %s=%q: %v", c.name, c.value, err)
			}
		})
	}
}

// The gluetun settings apply only to the gluetun backend.
func TestGluetunSettingsDoNotApplyToTheNativeBackend(t *testing.T) {
	env := baseEnv(map[string]string{"NB_SKIP_SOCKET_MARK": "1", "CONTROL_MARK": "junk", "FWMARK_GRACE": "1", "NB_LOG_FILE": "console"})
	if _, err := CheckEnv(env, "wireguard"); err != nil {
		t.Fatalf("native backend refused a gluetun-only setting: %v", err)
	}
	env["TUNNEL_BACKEND"] = "gluetun"
	if _, err := CheckEnv(env, ""); err == nil || !strings.Contains(err.Error(), "NB_SKIP_SOCKET_MARK is set") {
		t.Fatalf("gluetun backend from TUNNEL_BACKEND: %v", err)
	}
}

func TestCheckEnvReturnsParsedSettings(t *testing.T) {
	s, err := CheckEnv(baseEnv(map[string]string{"GUARD_GRACE": "12", "EXIT_IF": "pia", "NB_STATE_DIR": "/state"}), "wireguard")
	if err != nil {
		t.Fatal(err)
	}
	want := Settings{OverlayIF: "mesh0", Backend: BackendWireGuard, TunnelIF: "pia", StateDir: "/state", GuardGrace: 12 * time.Second}
	if s != want {
		t.Fatalf("settings = %+v, want %+v", s, want)
	}

	s, err = CheckEnv(map[string]string{
		"NB_DISABLE_USERSPACE_ROUTING": "1", "CONTROL_MARK": "0x2cd00", "NB_FWMARK_BASE": "0x2cd00",
		"FWMARK_GRACE": "5", "NB_LOG_FILE": "console,/var/log/a.log,/var/log/b.log",
	}, "gluetun")
	if err != nil {
		t.Fatal(err)
	}
	want = Settings{OverlayIF: "wt0", Backend: BackendGluetun, TunnelIF: "wg0", StateDir: DefaultStateDir,
		ControlMark: 0x2cd00, FwmarkGrace: 5 * time.Second, WatchLog: "/var/log/a.log"}
	if s != want {
		t.Fatalf("settings = %+v, want %+v", s, want)
	}

	// Defaults: native EXIT_IF mullvad, grace 30, the default mark and log.
	s, err = CheckEnv(map[string]string{"NB_DISABLE_USERSPACE_ROUTING": "true"}, "native")
	if err != nil || s.TunnelIF != "mullvad" || s.GuardGrace != 30*time.Second || s.Backend != BackendWireGuard {
		t.Fatalf("native defaults = %+v, %v", s, err)
	}
	s, err = CheckEnv(map[string]string{"NB_DISABLE_USERSPACE_ROUTING": "true"}, "gluetun")
	if err != nil || s.ControlMark != 0x1bd00 || s.FwmarkGrace != 30*time.Second || s.WatchLog != "/var/log/netbird/client.log" {
		t.Fatalf("gluetun defaults = %+v, %v", s, err)
	}
}

func TestGraceBounds(t *testing.T) {
	for _, c := range []struct {
		text string
		ok   bool
	}{{"5", true}, {"6", true}, {"30", true}, {"29", true}, {"4", false}, {"31", false}, {"0", false}, {"05", false},
		{"99", false}, {"100", false}, {"3 ", false}, {" 5", false}, {"+5", false}, {"٥", false}} {
		_, err := parseGrace(c.text, "GUARD_GRACE")
		if (err == nil) != c.ok {
			t.Errorf("parseGrace(%q) error = %v, want ok=%v", c.text, err, c.ok)
		}
	}
}

func TestValidInterfaceName(t *testing.T) {
	for name, ok := range map[string]bool{
		"wt0": true, "mesh0": true, "_a": true, "a.b-c": true, "a_b": true, "abcdefghijklmno": true,
		"": false, "abcdefghijklmnop": false, ".a": false, "-a": false, "a b": false, "a/b": false, "a:b": false, "é": false,
	} {
		if got := ValidInterfaceName(name); got != ok {
			t.Errorf("ValidInterfaceName(%q) = %v, want %v", name, got, ok)
		}
	}
}

func TestTunnelFromEnv(t *testing.T) {
	for _, c := range []struct {
		env             map[string]string
		backend, tunnel string
		state           string
		err             string
	}{
		{map[string]string{}, BackendWireGuard, "mullvad", DefaultStateDir, ""},
		{map[string]string{"TUNNEL_BACKEND": "native", "EXIT_IF": "pia", "PROVIDER": "pia"}, BackendWireGuard, "pia", DefaultStateDir, ""},
		{map[string]string{"TUNNEL_BACKEND": "gluetun"}, BackendGluetun, "wg0", DefaultStateDir, ""},
		{map[string]string{"TUNNEL_BACKEND": "gluetun", "EXIT_IF": "tun9", "NB_STATE_DIR": "/s"}, BackendGluetun, "tun9", "/s", ""},
		{map[string]string{"TUNNEL_BACKEND": "x"}, "", "", "", "TUNNEL_BACKEND must be native or gluetun"},
		{map[string]string{"EXIT_IF": `a"b`}, "", "", "", "the tunnel interface name is invalid"},
	} {
		backend, tunnel, state, err := TunnelFromEnv(c.env)
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("%v: error = %v, want %q", c.env, err, c.err)
			}
			continue
		}
		if err != nil || backend != c.backend || tunnel != c.tunnel || state != c.state {
			t.Errorf("%v: got %q %q %q %v", c.env, backend, tunnel, state, err)
		}
	}
}
