//go:build linux

package exit

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A native overlay exit holds NetBird unless the kernel sources ICMP errors
// from the inbound interface's address.
func TestTheReturnPathSysctlIsAPrecondition(t *testing.T) {
	path := filepath.Join(t.TempDir(), "icmp_errors_use_inbound_ifaddr")
	old := returnPathSysctl
	returnPathSysctl = path
	t.Cleanup(func() { returnPathSysctl = old })
	if err := returnPathPrecondition(); err == nil {
		t.Error("an unreadable sysctl passed")
	}
	for value, ok := range map[string]bool{"0\n": false, "1\n": true, "2\n": false, "": false} {
		if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
			t.Fatal(err)
		}
		err := returnPathPrecondition()
		if (err == nil) != ok {
			t.Errorf("%q: %v", value, err)
		}
		if err != nil && !strings.HasPrefix(err.Error(), "net.ipv4.icmp_errors_use_inbound_ifaddr is not 1; ") {
			t.Errorf("%q: %v", value, err)
		}
	}
}

func TestLibraryLinesCarryOnePrefix(t *testing.T) {
	var out bytes.Buffer
	w := &worker{out: &out}
	w.libLogf("molebridge: added %s rule %d", "IPv4", 97)
	w.libLogf("something without the library's prefix")
	if got := out.String(); got != "molebridge-exit: added IPv4 rule 97\nmolebridge-exit: something without the library's prefix\n" {
		t.Fatalf("%q", got)
	}
	if strings.Contains(out.String(), "molebridge-exit: molebridge:") {
		t.Fatal("double prefix")
	}
}
