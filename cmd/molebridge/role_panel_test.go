package main

import (
	"bufio"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The panel runs as a container's PID 1, which ignores SIGTERM without a
// handler. The test binary re-runs itself as `molebridge panel`
// (panel/test_app.py SigtermTests).
func TestPanelRoleStopsCleanlyOnSIGTERM(t *testing.T) {
	if os.Getenv("MOLEBRIDGE_TEST_AS_MAIN") == "1" {
		os.Args = []string{"molebridge", "panel"}
		os.Exit(roles["panel"].run(nil))
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()

	cmd := exec.Command(os.Args[0], "-test.run=^TestPanelRoleStopsCleanlyOnSIGTERM$")
	cmd.Env = append(os.Environ(), "MOLEBRIDGE_TEST_AS_MAIN=1", "STATE_DIR="+t.TempDir(),
		"MOLEBRIDGE_PANEL_LISTEN="+address, "MOLEBRIDGE_PANEL_ISOLATION_CHECK=off")
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill() })
	go func() { // drain the log so the child never blocks on it
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			_ = strings.TrimSpace(scanner.Text())
		}
	}()
	up := false
	for i := 0; i < 200 && !up; i++ {
		if resp, err := http.Get("http://" + address + "/healthz"); err == nil {
			resp.Body.Close()
			up = resp.StatusCode == 200
		} else {
			time.Sleep(25 * time.Millisecond)
		}
	}
	if !up {
		t.Fatal("the panel did not come up")
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("exit: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the panel ignored SIGTERM")
	}
}
