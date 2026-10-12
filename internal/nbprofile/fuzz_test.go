// Fuzz targets for the NetBird profile reader and environment (the plan's
// fuzz list): no panics, no content in refusals, and agreement with
// encoding/json on what is one JSON object.
package nbprofile

import (
	"encoding/json"
	"strings"
	"testing"
)

func FuzzProfileVerdict(f *testing.F) {
	for _, s := range []string{
		profileText("false"), profileText("true"), `{"WgIface": "mesh0", "wgiface": "x"}`, `{"name": "default"}`,
		`{"RosenpassEnabled": true}`, `{"a": "\ud800"}`, `{`, ``, `[]`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		fx := &fixture{t: t, dir: dir, paths: Paths{StateDir: dir}}
		fx.write("default.json", data)
		fx.write("active_profile.json", data)
		err := CheckProfiles(fx.paths, "mesh0")
		if err == nil {
			var m map[string]json.RawMessage
			if json.Unmarshal(data, &m) != nil {
				t.Fatalf("accepted something that is not a JSON object: %q", data)
			}
			return
		}
		if _, ok := err.(*Refusal); !ok {
			t.Fatalf("not a Refusal: %v", err)
		}
		if msg := err.Error(); len(data) > 12 && strings.Contains(strings.ReplaceAll(msg, dir, ""), string(data[:12])) {
			t.Fatalf("refusal %q holds file content", msg)
		}
	})
}

func FuzzCheckEnv(f *testing.F) {
	f.Add("NB_INTERFACE_NAME", "mesh0", "CONTROL_MARK", "0x1bd00", "gluetun")
	f.Add("NB_FWMARK_BASE", "", "FWMARK_GRACE", "05", "wireguard")
	f.Add("GUARD_GRACE", "30", "NB_LOG_FILE", ",,/a", "native")
	f.Fuzz(func(t *testing.T, k1, v1, k2, v2, backend string) {
		env := map[string]string{"NB_DISABLE_USERSPACE_ROUTING": "true", k1: v1, k2: v2}
		s, err := CheckEnv(env, backend)
		if err != nil {
			if _, ok := err.(*Refusal); !ok {
				t.Fatalf("not a Refusal: %v", err)
			}
			return
		}
		if !ValidInterfaceName(s.OverlayIF) || (s.Backend != BackendWireGuard && s.Backend != BackendGluetun) {
			t.Fatalf("accepted settings %+v", s)
		}
		if s.Backend == BackendGluetun && (s.ControlMark&0xff != 0 || s.ControlMark == 0 || s.WatchLog == "" || s.FwmarkGrace < 5e9 || s.FwmarkGrace > 30e9) {
			t.Fatalf("accepted gluetun settings %+v", s)
		}
		if s.Backend == BackendWireGuard && (s.GuardGrace < 5e9 || s.GuardGrace > 30e9) {
			t.Fatalf("accepted native settings %+v", s)
		}
	})
}
