package exit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const procTCPHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

func TestControlServerVerdict(t *testing.T) {
	// 127.0.0.1:8000 is 0100007F:1F40; 0.0.0.0:8000 is 00000000:1F40;
	// 192.0.2.5:8000 is 050200C0:1F40.
	loop4 := procTCPHeader + "   0: 0100007F:1F40 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0\n"
	any4 := procTCPHeader + "   0: 00000000:1F40 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0\n"
	other4 := procTCPHeader + "   0: 050200C0:1F40 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0\n"
	estab4 := procTCPHeader + "   0: 050200C0:1F40 00000000:0000 01 00000000:00000000 00:00000000 00000000     0        0 1 1 0\n"
	elsewhere4 := procTCPHeader + "   0: 050200C0:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0\n"
	loop6 := procTCPHeader + "   0: 00000000000000000000000001000000:1F40 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0\n"
	any6 := procTCPHeader + "   0: 00000000000000000000000000000000:1F40 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0\n"
	mapped6 := procTCPHeader + "   0: 0000000000000000FFFF00000100007F:1F40 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0\n"
	tests := []struct {
		name    string
		tcp4    string
		tcp6    string
		found   bool
		refusal bool
	}{
		{"loopback listener", loop4, procTCPHeader, true, false},
		{"IPv6 loopback listener", procTCPHeader, loop6, true, false},
		{"IPv4-mapped loopback", procTCPHeader, mapped6, true, false},
		{"no listener at all", procTCPHeader, procTCPHeader, false, false},
		{"wildcard listener", any4, procTCPHeader, false, true},
		{"loopback and wildcard", loop4, any6, true, true},
		{"another address", other4, procTCPHeader, false, true},
		{"IPv6 wildcard", procTCPHeader, any6, false, true},
		{"not a listener", estab4, procTCPHeader, false, false},
		{"another port", elsewhere4, procTCPHeader, false, false},
		{"empty tables", "", "", false, false},
		{"garbage", "garbage\nmore garbage", "x", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			found, err := ControlServerVerdict(tt.tcp4, tt.tcp6, 8000)
			if found != tt.found || (err != nil) != tt.refusal {
				t.Fatalf("found %v err %v, want %v %v", found, err, tt.found, tt.refusal)
			}
		})
	}
}

func TestControlPort(t *testing.T) {
	for in, want := range map[string]int{"": 8000, "http://127.0.0.1:8000": 8000, "http://127.0.0.1:9001/": 9001} {
		if got, err := controlPort(in); err != nil || got != want {
			t.Errorf("%q: %d %v", in, got, err)
		}
	}
	for _, in := range []string{"http://127.0.0.1", "http://127.0.0.1:0", "http://127.0.0.1:99999", "::"} {
		if _, err := controlPort(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func appendFile(t *testing.T, path, text string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(text); err != nil {
		t.Fatal(err)
	}
}

func TestLogScannerReadsOnlyThisLaunch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.log")
	appendFile(t, path, "an earlier launch: falling back to legacy routing\n")
	start := fileSize(path)
	sc := newLogScanner(path, start)
	if sc.step() {
		t.Fatal("the previous launch's bytes must not count")
	}
	appendFile(t, path, "INFO all good\n")
	if sc.step() {
		t.Fatal("no match")
	}
	appendFile(t, path, "WARN client/net/env_linux.go:61: advanced routing has been requested to be disabled\n")
	if !sc.step() {
		t.Fatal("the second string must match")
	}
}

func TestLogScannerSeesALineSplitAcrossReads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.log")
	sc := newLogScanner(path, 0)
	appendFile(t, path, "INFO start; falling back to ")
	if sc.step() {
		t.Fatal("half a line")
	}
	appendFile(t, path, "legacy routing\n")
	if !sc.step() {
		t.Fatal("the overlap must let the whole line be seen")
	}
}

func TestLogScannerHandlesTruncationAndMissingFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.log")
	sc := newLogScanner(path, 0)
	if sc.step() {
		t.Fatal("a missing file reads as empty")
	}
	appendFile(t, path, strings.Repeat("x", 4000)+"\n")
	if sc.step() {
		t.Fatal("no match")
	}
	// Rotated: the file starts over, smaller than what was read.
	if err := os.WriteFile(path, []byte("falling back to legacy routing\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !sc.step() {
		t.Fatal("after truncation the new file is read from its start")
	}
}

func TestLogScannerBoundsAStep(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.log")
	appendFile(t, path, strings.Repeat("y", 3000))
	sc := newLogScanner(path, 0)
	sc.perStep = 1000
	appendFile(t, path, "falling back to legacy routing")
	steps := 0
	for !sc.step() {
		steps++
		if steps > 10 {
			t.Fatal("never found it")
		}
	}
	if steps < 3 {
		t.Errorf("a 1000-byte step cannot read 3000 bytes at once: %d", steps)
	}
}
