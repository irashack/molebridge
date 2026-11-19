package verdict

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/validate"
)

var proxyNow = time.Date(2026, 11, 19, 18, 0, 10, 0, time.UTC)

// proxyRecord is the design's example proxy.json, with replacements applied
// to its text.
func proxyRecord(replace ...string) string {
	raw := `{
  "schema": 1, "kind": "proxy", "provider": "mullvad",
  "guarantee": "opt-in",
  "status": "ok", "message": "Serving.",
  "checked_at": "2026-11-19T18:00:00Z",
  "listen": "127.0.0.1:1080",
  "tunnel": {"verdict": "ok", "server": "se-got-wg-001", "checked_at": "2026-11-19T17:59:30Z"},
  "servers": {"known": 512, "benched": [
    {"server": "de-fra-wg-003", "until": "2026-11-19T18:02:00Z", "reason": "handshake timed out"}
  ]},
  "sessions": 3,
  "connections": {"open": 7, "total": 1204, "failed": 12}
}`
	return strings.NewReplacer(replace...).Replace(raw)
}

func writeProxy(t *testing.T, raw string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "proxy.json")
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func assessText(t *testing.T, raw string) ProxyVerdict {
	t.Helper()
	return AssessProxy(ReadProxy(writeProxy(t, raw)), "mullvad", proxyNow)
}

func TestAssessProxyStatuses(t *testing.T) {
	v := assessText(t, proxyRecord())
	if v.State != "ok" || v.Label != "serving" || len(v.Reasons) != 0 || v.Message == nil || *v.Message != "Serving." ||
		v.Tunnel != "ok" || v.Benched != 1 || v.Sessions != 3 || v.Open != 7 {
		t.Fatalf("%+v", v)
	}
	v = assessText(t, proxyRecord(`"status": "ok", "message": "Serving."`,
		`"status": "refusing", "message": "Refusing new connections: the exit's verdict is failed."`,
		`"verdict": "ok"`, `"verdict": "failed"`))
	if v.State != "refusing" || v.Reasons[0] != "tunnel-not-ok" || v.Tunnel != "failed" {
		t.Fatalf("%+v", v)
	}
	v = assessText(t, proxyRecord(`"status": "ok", "message": "Serving."`, `"status": "failed", "message": "The listener is down."`))
	if v.State != "failed" || v.Label != "listener down" {
		t.Fatalf("%+v", v)
	}
	// Any provider when the reader names none; nulls where the tunnel is unknown.
	record := ReadProxy(writeProxy(t, proxyRecord(`"verdict": "ok", "server": "se-got-wg-001", "checked_at": "2026-11-19T17:59:30Z"`,
		`"verdict": null, "server": null, "checked_at": null`)))
	if v := AssessProxy(record, "", proxyNow); v.State != "ok" || v.Tunnel != "" {
		t.Fatalf("%+v", v)
	}
}

func TestAssessProxyUnknown(t *testing.T) {
	cases := map[string]struct {
		raw    string
		reason string
	}{
		"missing":         {"", "no-status"},
		"not an object":   {`[1]`, "no-status"},
		"duplicate key":   {proxyRecord(`"sessions": 3`, `"sessions": 3, "sessions": 4`), "no-status"},
		"nested dup":      {proxyRecord(`"open": 7`, `"open": 7, "open": 8`), "no-status"},
		"trailing junk":   {proxyRecord() + "x", "no-status"},
		"schema 2":        {proxyRecord(`"schema": 1`, `"schema": 2`), "unsupported-schema"},
		"schema text":     {proxyRecord(`"schema": 1`, `"schema": "1"`), "unsupported-schema"},
		"schema float":    {proxyRecord(`"schema": 1`, `"schema": 1.0`), "unsupported-schema"},
		"no schema":       {proxyRecord(`"schema": 1, `, ``), "unsupported-schema"},
		"exit record":     {proxyRecord(`"kind": "proxy"`, `"kind": "overlay"`), "kind-mismatch"},
		"no kind":         {proxyRecord(`"kind": "proxy", `, ``), "kind-mismatch"},
		"other provider":  {proxyRecord(`"provider": "mullvad"`, `"provider": "pia"`), "provider-mismatch"},
		"stale":           {proxyRecord(`"checked_at": "2026-11-19T18:00:00Z"`, `"checked_at": "2026-11-19T17:59:39Z"`), "status-stale"},
		"future":          {proxyRecord(`"checked_at": "2026-11-19T18:00:00Z"`, `"checked_at": "2026-11-19T18:00:11Z"`), "status-stale"},
		"bad time":        {proxyRecord(`"checked_at": "2026-11-19T18:00:00Z"`, `"checked_at": "2026-11-19 18:00:00"`), "invalid-record"},
		"other status":    {proxyRecord(`"status": "ok"`, `"status": "applying"`), "invalid-record"},
		"no message":      {proxyRecord(`"message": "Serving.",`, ``), "invalid-record"},
		"other guarantee": {proxyRecord(`"guarantee": "opt-in"`, `"guarantee": "fail-closed"`), "invalid-record"},
		"no listen":       {proxyRecord(`"listen": "127.0.0.1:1080",`, ``), "invalid-record"},
		"tunnel missing":  {proxyRecord(`"tunnel": {"verdict": "ok", "server": "se-got-wg-001", "checked_at": "2026-11-19T17:59:30Z"},`, ``), "invalid-record"},
		"tunnel partial":  {proxyRecord(`"server": "se-got-wg-001", `, ``), "invalid-record"},
		"tunnel bad time": {proxyRecord(`"checked_at": "2026-11-19T17:59:30Z"`, `"checked_at": 5`), "invalid-record"},
		"known negative":  {proxyRecord(`"known": 512`, `"known": -1`), "invalid-record"},
		"benched object":  {proxyRecord(`"benched": [`, `"benched": {"x": [`, `]},`, `]}},`), "invalid-record"},
		"bench no until":  {proxyRecord(`"until": "2026-11-19T18:02:00Z", `, ``), "invalid-record"},
		"bench no reason": {proxyRecord(`, "reason": "handshake timed out"`, ``), "invalid-record"},
		"sessions float":  {proxyRecord(`"sessions": 3`, `"sessions": 3.5`), "invalid-record"},
		"open missing":    {proxyRecord(`"open": 7, `, ``), "invalid-record"},
		"failed text":     {proxyRecord(`"failed": 12`, `"failed": "12"`), "invalid-record"},
		"control char":    {proxyRecord(`"Serving."`, `"Serv\u0001ing."`), "invalid-record"},
	}
	for name, tc := range cases {
		var record any
		if tc.raw != "" {
			record = ReadProxy(writeProxy(t, tc.raw))
		} else {
			record = ReadProxy(filepath.Join(t.TempDir(), "none.json"))
		}
		v := AssessProxy(record, "mullvad", proxyNow)
		if v.State != "unknown" || len(v.Reasons) != 1 || v.Reasons[0] != tc.reason || v.Message != nil {
			t.Errorf("%s: %+v, want unknown (%s)", name, v, tc.reason)
		}
	}
}

func TestAssessProxyAgeBounds(t *testing.T) {
	record, err := validate.DecodeJSONString(proxyRecord())
	if err != nil {
		t.Fatal(err)
	}
	checked := time.Date(2026, 11, 19, 18, 0, 0, 0, time.UTC)
	if v := AssessProxy(record, "mullvad", checked.Add(ProxyMaxAge*time.Second)); v.State != "ok" {
		t.Fatalf("at 30 s: %+v", v)
	}
	if v := AssessProxy(record, "mullvad", checked.Add((ProxyMaxAge+1)*time.Second)); v.State != "unknown" {
		t.Fatalf("at 31 s: %+v", v)
	}
	if v := AssessProxy(record, "mullvad", checked); v.State != "ok" {
		t.Fatalf("at 0 s: %+v", v)
	}
}

func TestReadProxyIsBounded(t *testing.T) {
	big := proxyRecord(`"handshake timed out"`, `"`+strings.Repeat("a", ProxyMaxBytes)+`"`)
	if ReadProxy(writeProxy(t, big)) != nil {
		t.Fatal("read a file over ProxyMaxBytes")
	}
	dir := t.TempDir()
	target := writeProxy(t, proxyRecord())
	link := filepath.Join(dir, "proxy.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if ReadProxy(link) != nil {
		t.Fatal("followed a symlink")
	}
}
