package applier

import (
	"context"
	"time"

	"github.com/irashack/molebridge/internal/providers"
)

// nativeCatalog is the relay snapshot of internal/providers as the applier's
// Catalog.
type nativeCatalog struct {
	inner *providers.RelayCatalog
	// exitIPs are exit addresses by server. No native catalogue lists any (the
	// parsers never write them, as in Python); tests and a future catalogue
	// may.
	exitIPs map[string][]string
}

// NativeCatalog reads the snapshot in directory for a native provider. now is
// the wall clock; time.Now when nil.
func NativeCatalog(directory, provider string, portForwardOnly bool, now func() time.Time) Catalog {
	return &nativeCatalog{inner: providers.NewRelayCatalog(directory, provider, portForwardOnly, now)}
}

func (c *nativeCatalog) Usable() bool                   { return c.inner.Usable() }
func (c *nativeCatalog) Relays() *providers.Entries     { return c.inner.Relays }
func (c *nativeCatalog) Snapshot() map[string]any       { return c.inner.Snapshot }
func (c *nativeCatalog) ExitIPs(server string) []string { return c.exitIPs[server] }

func (c *nativeCatalog) Refresh(_ context.Context, fetch func() ([]byte, error)) (bool, error) {
	return c.inner.Refresh(fetch)
}
