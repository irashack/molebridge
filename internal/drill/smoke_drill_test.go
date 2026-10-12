//go:build drill && linux

package drill

import "testing"

func TestTheRigStartsConnected(t *testing.T) {
	r := newRig(t)
	for _, f := range []string{"-4", "-6"} {
		if !r.ping(f) {
			t.Fatalf("%s: the client cannot reach the destination through the tunnel\n%s", f, r.logs.text())
		}
	}
	if counter(t, r.tun) == 0 {
		t.Error("nothing crossed the tunnel")
	}
	r.held("startup")
	for _, f := range []string{"-4", "-6"} {
		out, _ := r.exit.TryIP(f, "rule", "show")
		t.Logf("%s\n%s", f, out)
		out, _ = r.exit.TryIP(f, "route", "show", "table", "51821")
		t.Logf("%s\n%s", f, out)
	}
}
