//go:build linux

package exit

import (
	"bytes"
	"strings"
	"testing"
)

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
