//go:build drill && linux

package drill

// Rules that are really there twice. The kernel refuses an identical rule only
// for a request with NLM_F_EXCL, and `ip rule restore` sends none: restoring a
// saved ruleset adds every rule again (and the kernel's priority-0 rule under a
// new priority). The owner must see the duplicates as they are - a stable
// snapshot of two looks that agree, multiplicity included - and remove them
// through its deletion check, leaving the contract exactly as expected and no
// temporary guard behind.

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func ruleCount(r *rig, family, prefix string) int {
	out, _ := r.exit.TryIP(family, "rule", "show")
	n := 0
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, prefix) {
			n++
		}
	}
	return n
}

func TestRestoredRulesAreDuplicatesAndTheyAreRemoved(t *testing.T) {
	r := newRig(t)
	dir := t.TempDir()
	// Hold the owner so that the duplicates can be seen before they are repaired.
	resume := r.pause()
	defer resume()
	for _, f := range []string{"-4", "-6"} {
		file := filepath.Join(dir, "rules"+f)
		out, err := r.exit.Exec("sh", "-c", "ip "+f+" rule save > "+file+" && ip "+f+" rule restore < "+file)
		if err != nil {
			t.Fatalf("ip %s rule save/restore: %v\n%s", f, err, out)
		}
	}
	for _, f := range []string{"-4", "-6"} {
		for _, p := range []string{"1:", "95:", "97:"} {
			if n := ruleCount(r, f, p); n != 2 {
				out, _ := r.exit.TryIP(f, "rule", "show")
				t.Fatalf("%s rule %s is there %d times after the restore, want 2:\n%s", f, p, n, out)
			}
		}
	}
	resume()
	r.waitHealthy(5 * time.Second)
	for _, f := range []string{"-4", "-6"} {
		for _, p := range []string{"1:", "90:", "95:", "96:", "97:"} {
			if n := ruleCount(r, f, p); n != 1 {
				out, _ := r.exit.TryIP(f, "rule", "show")
				t.Errorf("%s rule %s is there %d times after the repair, want 1:\n%s", f, p, n, out)
			}
		}
		if n := ruleCount(r, f, "80:"); n != 0 {
			t.Errorf("%s: the temporary guard stayed", f)
		}
	}
	if ok, which := r.connected(); !ok {
		t.Errorf("not connected after the repair (%s)", which)
	}
}
