package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/irashack/molebridge/internal/panel"
)

func TestExchangeSettings(t *testing.T) {
	for _, c := range []struct {
		name string
		env  map[string]string
		want string
	}{
		{"no exits", map[string]string{}, "PANEL_EXITS names no exit"},
		{"bad listen", map[string]string{"PANEL_EXITS": "a=mullvad", "EXCHANGE_LISTEN": ":8097"}, "EXCHANGE_LISTEN is host:port"},
		{"cert alone", map[string]string{"PANEL_EXITS": "a=mullvad", "EXCHANGE_CERT_FILE": "/c"}, "go together"},
		{"bad exits", map[string]string{"PANEL_EXITS": "A=mullvad"}, "PANEL_EXITS: exit ids"},
	} {
		if _, err := exchangeFromEnv(c.env); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err %v, want %q", c.name, err, c.want)
		}
	}
	cfg, err := exchangeFromEnv(map[string]string{"PANEL_EXITS": "home=mullvad,work=pia", "STATE_DIR": "/s"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.listen != "0.0.0.0:8097" || cfg.server.TokensDir != "/run/secrets/exchange" || cfg.server.Exits["work"].Dir != "/s/work" || cfg.server.Exits["work"].Provider != "pia" {
		t.Fatalf("defaults: %+v %+v", cfg, cfg.server.Exits)
	}
}

func TestExchangeRefusesCapabilitiesAndRoot(t *testing.T) {
	probe := panel.IsolationProbe{StatusPath: "/nonexistent", UID: func() int { return 0 },
		ReadOnly: func(string) (bool, error) { return true, nil }}
	var out bytes.Buffer
	code := exchangeMain(context.Background(), nil, map[string]string{"PANEL_EXITS": "a=mullvad"}, &out, probe)
	if code != 1 || strings.Count(out.String(), "refusing to start") != 2 {
		t.Fatalf("code %d, output %q", code, out.String())
	}
}
