package panel

// New in 0.8.0: Run, the start of `molebridge panel`.

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
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

// New in 0.10.0: answers keep the connection open, and the write timeout
// leaves room for the slowest handler.
func TestServeKeepsConnectionsOpen(t *testing.T) {
	h := newSingleHarness(t, nil)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Serve(ctx, h.srv, listener, &bytes.Buffer{})
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)
	for i := 0; i < 2; i++ {
		fmt.Fprintf(conn, "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatalf("request %d on the same connection: %v", i, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || resp.Close || resp.Header.Get("Connection") != "" {
			t.Fatalf("request %d: %d close=%v Connection=%q", i, resp.StatusCode, resp.Close, resp.Header.Get("Connection"))
		}
	}
	rounds := (maxProbeTargets + probeWorkers - 1) / probeWorkers
	if slowest := time.Duration(rounds*probeAttempts)*probeTimeout + probeWait; writeTimeout <= slowest {
		t.Fatalf("writeTimeout %v is not above the slowest latency request, %v", writeTimeout, slowest)
	}
}
