//go:build drill

package exit

import (
	"crypto/x509"
	"os"

	"github.com/irashack/molebridge/internal/applier"
)

// drillProviders lets the system rig's fake PIA servers stand in for PIA's:
// MOLEBRIDGE_DRILL_PIA_CA names a PEM file whose certificates replace PIA's
// certificate authority for registration and port forwarding. It exists only
// in binaries built with the drill tag; the release build trusts PIA's own
// CA alone.
func drillProviders(env map[string]string, log func(string), provs ...applier.Provider) {
	path := env["MOLEBRIDGE_DRILL_PIA_CA"]
	if path == "" {
		return
	}
	raw, err := os.ReadFile(path)
	pool := x509.NewCertPool()
	if err != nil || !pool.AppendCertsFromPEM(raw) {
		if log != nil {
			log("drill hook: MOLEBRIDGE_DRILL_PIA_CA is not a PEM certificate file; PIA's own CA stays")
		}
		return
	}
	for _, p := range provs {
		if applier.UsePIARootCAs(p, pool) && log != nil {
			log("drill hook: PIA's registration and port forwarding trust " + path)
		}
	}
}
