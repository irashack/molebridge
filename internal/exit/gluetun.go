package exit

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// -- gluetun's control server (start-time check) ---------------------------------

// DefaultGluetunControlURL is where the exit expects gluetun's control server.
const DefaultGluetunControlURL = "http://127.0.0.1:8000"

// listener is one LISTEN socket from /proc/net/tcp or /proc/net/tcp6.
type listener struct {
	ip       []byte // 4 or 16 bytes, in network order
	port     int
	loopback bool
}

// parseProcNet reads /proc/net/tcp (4) or /proc/net/tcp6 (6) text and returns
// the sockets in state LISTEN. The address column is the kernel's hexadecimal
// of the in-memory (little-endian per 32-bit word) address.
func parseProcNet(text string, six bool) []listener {
	var out []listener
	for i, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 4 || f[3] != "0A" {
			continue
		}
		addr, port, ok := strings.Cut(f[1], ":")
		if !ok {
			continue
		}
		raw, err := hex.DecodeString(addr)
		if err != nil || (!six && len(raw) != 4) || (six && len(raw) != 16) {
			continue
		}
		p, err := strconv.ParseUint(port, 16, 16)
		if err != nil {
			continue
		}
		// Each 32-bit word is stored in host (little-endian) byte order.
		ip := make([]byte, len(raw))
		for w := 0; w < len(raw); w += 4 {
			ip[w], ip[w+1], ip[w+2], ip[w+3] = raw[w+3], raw[w+2], raw[w+1], raw[w]
		}
		l := listener{ip: ip, port: int(p)}
		if six {
			l.loopback = bytes.Equal(ip, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}) ||
				(bytes.Equal(ip[:12], []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff}) && ip[12] == 127)
		} else {
			l.loopback = ip[0] == 127
		}
		out = append(out, l)
	}
	return out
}

// controlPort is the port of GLUETUN_CONTROL_URL.
func controlPort(raw string) (int, error) {
	if raw == "" {
		raw = DefaultGluetunControlURL
	}
	u, err := url.Parse(raw)
	if err != nil || u.Port() == "" {
		return 0, fmt.Errorf("GLUETUN_CONTROL_URL must name a port")
	}
	p, err := strconv.Atoi(u.Port())
	if err != nil || p < 1 || p > 65535 {
		return 0, fmt.Errorf("GLUETUN_CONTROL_URL must name a port")
	}
	return p, nil
}

// ControlServerVerdict judges the listeners of the namespace for gluetun's
// control server on port: found reports a loopback listener on it; a listener
// on that port on any other address is a refusal, whether or not the loopback
// one exists.
func ControlServerVerdict(tcp4, tcp6 string, port int) (found bool, refusal error) {
	all := append(parseProcNet(tcp4, false), parseProcNet(tcp6, true)...)
	for _, l := range all {
		if l.port != port {
			continue
		}
		if !l.loopback {
			return found, fmt.Errorf("gluetun's control server port %d has a listener on an address other than loopback; the control server must listen on 127.0.0.1 only (HTTP_CONTROL_SERVER_ADDRESS)", port)
		}
		found = true
	}
	return found, nil
}

// readProcNet reads both listener tables; a missing IPv6 table (a kernel
// without IPv6) is an empty one.
func readProcNet() (tcp4, tcp6 string, err error) {
	b4, err := os.ReadFile("/proc/net/tcp")
	if err != nil {
		return "", "", err
	}
	b6, err := os.ReadFile("/proc/net/tcp6")
	if err != nil && !os.IsNotExist(err) {
		return "", "", err
	}
	return string(b4), string(b6), nil
}

// -- NetBird's log (the fallback from advanced routing) --------------------------

// The two lines NetBird 0.80.0 logs when it will not mark its sockets
// (client/net/env_linux.go:61,66), so its control traffic would be unmarked.
var fallbackStrings = [][]byte{
	[]byte("falling back to legacy routing"),
	[]byte("advanced routing has been requested to be disabled"),
}

// FallbackMessage is the gate's stop reason for a match.
const FallbackMessage = "NetBird logged that it runs without advanced routing, so its control traffic would be unmarked"

// logScanOverlap is how much of the previous read is kept, so a line written
// across two reads is seen whole (the strings are far shorter).
const logScanOverlap = 512

// logScanner reads only one launch's bytes of NetBird's log.
type logScanner struct {
	path string
	// offset is how much of the file has been read; carry the tail of it.
	offset int64
	carry  []byte
	// perStep bounds one step's read.
	perStep int64
}

func newLogScanner(path string, start int64) *logScanner {
	return &logScanner{path: path, offset: start, perStep: 1 << 20}
}

// step reads what the file gained since the last step and reports a match. A
// file smaller than what was read (truncated or rotated) is read again from its
// beginning. A missing or unreadable file reads as empty.
func (l *logScanner) step() bool {
	f, err := os.Open(l.path)
	if err != nil {
		return false
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return false
	}
	size := fi.Size()
	if size < l.offset {
		l.offset, l.carry = 0, nil
	}
	want := size - l.offset
	if want > l.perStep {
		want = l.perStep
	}
	if want <= 0 {
		return false
	}
	buf := make([]byte, want)
	n, _ := f.ReadAt(buf, l.offset)
	buf = buf[:n]
	l.offset += int64(n)
	data := append(l.carry, buf...)
	for _, s := range fallbackStrings {
		if bytes.Contains(data, s) {
			return true
		}
	}
	if len(data) > logScanOverlap {
		data = data[len(data)-logScanOverlap:]
	}
	l.carry = append([]byte(nil), data...)
	return false
}
