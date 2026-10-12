package panel

// New in 0.8.0: Run, the start of `molebridge panel`.

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestRunRefusesBadSettingsBeforeListening(t *testing.T) {
	var stderr bytes.Buffer
	code := Run(context.Background(), map[string]string{"PROVIDER": "examplevpn", ListenEnv: "127.0.0.1:0"}, &stderr, IsolationProbe{})
	if code != 1 || !strings.HasPrefix(stderr.String(), "molebridge panel: PROVIDER must be one of") {
		t.Fatalf("code %d, stderr %q", code, stderr.String())
	}
}

func TestRunRefusesAnUnisolatedProcessWithFixedMessages(t *testing.T) {
	probe := fakeProbe(t, "CapEff:\t0000000000000fff\n", 0, map[string]bool{"/state/applier": false})
	var stderr bytes.Buffer
	code := Run(context.Background(), map[string]string{"PROVIDER": "mullvad", ListenEnv: "127.0.0.1:0"}, &stderr, probe)
	if code != 1 {
		t.Fatalf("code %d", code)
	}
	for _, want := range []string{refuseCapabilities, refuseRoot, refuseMounts} {
		if !strings.Contains(stderr.String(), "molebridge panel: refusing to start: "+want+"\n") {
			t.Errorf("stderr lacks %q: %q", want, stderr.String())
		}
	}
}

func TestRunServesUntilTheContextEnds(t *testing.T) {
	probe := fakeProbe(t, "CapEff:\t0000000000000000\n", 1000, map[string]bool{"/state/applier": true})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		done <- Run(ctx, map[string]string{"PROVIDER": "mullvad", ListenEnv: address}, &bytes.Buffer{}, probe)
	}()
	var resp *http.Response
	for i := 0; i < 100; i++ {
		if resp, err = http.Get("http://" + address + "/healthz"); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("healthz: %v", err)
	}
	resp.Body.Close()
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit status %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return")
	}
}
