package applier

// The gluetun scenarios of the golden-record parity test (golden_test.go):
// each mirrors, line for line, the scenario in testdata/records_golden.gen.txt
// that generated its Python record (0.7.0's implementation, commit d553f25; the
// golden is now fixed).

import (
	"testing"

	"github.com/irashack/molebridge/internal/validate"
)

func gluetunGoldenScenarios() map[string]func(t *testing.T) (*Applier, *Record) {
	inspect := func(o glOptions) func(t *testing.T) (*Applier, *Record) {
		return func(t *testing.T) (*Applier, *Record) {
			f := newGluetunFixture(t, o)
			return f.a, f.a.inspect(t)
		}
	}
	scenarios := map[string]func(t *testing.T) (*Applier, *Record){
		"gluetun_inspect": inspect(glOptions{}),
		"gluetun_switch": func(t *testing.T) (*Applier, *Record) {
			f := newGluetunFixture(t, glOptions{})
			return f.a, f.a.switchTo(t, glRequest(hostB))
		},
		"gluetun_mullvad": inspect(glOptions{provider: "mullvad"}),
		"gluetun_nordvpn": inspect(glOptions{provider: "nordvpn"}),
		"gluetun_no_tunnel": func(t *testing.T) (*Applier, *Record) {
			f := newGluetunFixture(t, glOptions{})
			f.k.tunnel = ""
			return f.a, f.a.inspect(t)
		},
		"gluetun_refused": func(t *testing.T) (*Applier, *Record) {
			f := newGluetunFixture(t, glOptions{})
			f.control.fail = true
			return f.a, f.a.switchTo(t, glRequest(hostB))
		},
		"gluetun_elsewhere": func(t *testing.T) (*Applier, *Record) {
			f := newGluetunFixture(t, glOptions{})
			f.control.connectTo = hostC
			return f.a, f.a.switchTo(t, glRequest(hostB))
		},
		"gluetun_host_address": func(t *testing.T) (*Applier, *Record) {
			f := newGluetunFixture(t, glOptions{})
			f.k.egress = glHost4
			return f.a, f.a.inspect(t)
		},
		"gluetun_guard_missing": func(t *testing.T) (*Applier, *Record) {
			f := newGluetunFixture(t, glOptions{})
			f.k.dropRule(6, 88)
			return f.a, f.a.switchTo(t, glRequest(hostB))
		},
		"gluetun_configured": func(t *testing.T) (*Applier, *Record) {
			f := newGluetunFixture(t, glOptions{server: hostB})
			return f.a, mustTick(t, f.a)
		},
		"gluetun_rejected": func(t *testing.T) (*Applier, *Record) {
			f := newGluetunFixture(t, glOptions{})
			desire(t, f.a, glRequest("four.example.test"))
			return f.a, mustTick(t, f.a)
		},
		"gluetun_restore": func(t *testing.T) (*Applier, *Record) {
			f := newGluetunFixture(t, glOptions{})
			settled(t, f, hostB, hostB, hostA)
			return f.a, mustTick(t, f.a)
		},
		"gluetun_updating": func(t *testing.T) (*Applier, *Record) {
			f := staleFixture(t, glOptions{})
			f.update()
			return f.a, f.a.inspect(t)
		},
		"gluetun_update_failed": func(t *testing.T) (*Applier, *Record) {
			f := staleFixture(t, glOptions{})
			f.update()
			f.k.now += 99999
			f.control.updater = "crashed"
			for i := 0; i < 3; i++ {
				f.update()
				f.k.now += 400
				f.update()
				f.k.now += 400
				f.update()
				f.control.updater = "crashed"
			}
			return f.a, f.a.inspect(t)
		},
		"sidecar_provider": func(t *testing.T) (*Applier, *Record) {
			f := sidecarFixture(t, "nordvpn")
			desire(t, f.a, glRequest(hostB))
			return f.a, mustTick(t, f.a)
		},
		"sidecar_tunnel": func(t *testing.T) (*Applier, *Record) {
			f := sidecarFixture(t, "ivpn")
			desire(t, f.a, glRequest(hostB))
			return f.a, mustTick(t, f.a)
		},
		"sidecar_fresh": func(t *testing.T) (*Applier, *Record) {
			f := sidecarFixture(t, "ivpn")
			return f.a, f.a.inspect(t)
		},
		"sidecar_no_tunnel": func(t *testing.T) (*Applier, *Record) {
			f := sidecarFixture(t, "nordvpn")
			f.k.tunnel = ""
			return f.a, f.a.inspect(t)
		},
	}
	reconnect := func(pick func(seen []*Record, final *Record) *Record) func(t *testing.T) (*Applier, *Record) {
		return func(t *testing.T) (*Applier, *Record) {
			f, _ := reconnectingFixture(t)
			var seen []*Record
			f.a.publish = func(r *Record) error { seen = append(seen, r); return nil }
			final := f.a.switchTo(t, glRequest(hostB))
			return f.a, pick(seen, final)
		}
	}
	scenarios["gluetun_reconnecting"] = reconnect(func(seen []*Record, _ *Record) *Record {
		for _, r := range seen {
			if checks, ok := r.Decoded()["checks"].(map[string]any); ok {
				if routing, ok := checks["routing"].(map[string]any); ok && routing["reason"] == "reconnecting" {
					return r
				}
			}
		}
		return nil
	})
	scenarios["gluetun_reconnecting_first"] = reconnect(func(seen []*Record, _ *Record) *Record { return seen[0] })
	scenarios["gluetun_reconnecting_final"] = reconnect(func(_ []*Record, final *Record) *Record { return final })
	scenarios["gluetun_reconnecting_count"] = reconnect(func(seen []*Record, _ *Record) *Record {
		statuses := make([]any, len(seen))
		for i, r := range seen {
			statuses[i] = r.Get("status")
		}
		return &Record{members: validate.Members("count", len(seen), "statuses", statuses)}
	})
	return scenarios
}
