package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/validate"
)

func TestPortSyncRoleRegistered(t *testing.T) {
	r, ok := roles["port-sync"]
	if !ok {
		t.Fatal("port-sync is not registered")
	}
	if r.help == "" {
		t.Error("port-sync has no help line")
	}
}

func TestPortSyncRefusesBadSettingsWithOneLine(t *testing.T) {
	for _, c := range []struct {
		name string
		env  map[string]string
		want string
	}{
		{"no client", map[string]string{}, "molebridge-port-sync: PORT_SYNC_CLIENT is required (the only client is qbittorrent)\n"},
		{"https", map[string]string{"PORT_SYNC_CLIENT": "qbittorrent", "PORT_SYNC_URL": "https://127.0.0.1"},
			"molebridge-port-sync: PORT_SYNC_URL must be an http URL (https is refused: the application is on a loopback address)\n"},
		{"interval", map[string]string{"PORT_SYNC_CLIENT": "qbittorrent", "PORT_SYNC_INTERVAL": "1"},
			"molebridge-port-sync: PORT_SYNC_INTERVAL must be a whole number of seconds from 10 to 300\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			var stderr bytes.Buffer
			if rc := portSyncMain(context.Background(), nil, c.env, &stderr); rc != 1 || stderr.String() != c.want {
				t.Errorf("rc %d, stderr %q", rc, stderr.String())
			}
		})
	}
}

func TestPortSyncUsage(t *testing.T) {
	var stderr bytes.Buffer
	if rc := portSyncMain(context.Background(), []string{"x"}, nil, &stderr); rc != 2 || !strings.Contains(stderr.String(), "usage: molebridge port-sync") {
		t.Errorf("rc %d, stderr %q", rc, stderr.String())
	}
}

func TestPortSyncRunsAndEndsWithStatusZero(t *testing.T) {
	var port atomic.Int64
	port.Store(6881)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v2/app/preferences":
			fmt.Fprintf(w, `{"listen_port":%d}`, port.Load())
		case "/api/v2/app/setPreferences":
			r.ParseForm()
			var n int64
			fmt.Sscanf(r.PostForm.Get("json"), `{"listen_port":%d`, &n)
			port.Store(n)
		}
	}))
	defer server.Close()
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "applier"), 0o755)
	record := fmt.Sprintf(`{"kind":"sidecar","checked_at":%q,"forwarded_port":40000}`, validate.FormatTime(time.Now()))
	os.WriteFile(filepath.Join(dir, "applier", "result.json"), []byte(record), 0o644)

	ctx, cancel := context.WithCancel(context.Background())
	var stderr bytes.Buffer
	done := make(chan int)
	go func() {
		done <- portSyncMain(ctx, nil, map[string]string{"PORT_SYNC_CLIENT": "qbittorrent", "PORT_SYNC_URL": server.URL, "STATE_DIR": dir}, &stderr)
	}()
	deadline := time.After(5 * time.Second)
	for port.Load() != 40000 {
		select {
		case <-deadline:
			t.Fatal("the port was not set")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	select {
	case rc := <-done:
		if rc != 0 {
			t.Errorf("rc %d", rc)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the role did not stop")
	}
}
