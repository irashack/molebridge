package exit

import "github.com/irashack/molebridge/internal/buildgate"

// multiProviderAvailable is the switch for multi-provider exits (PROVIDERS):
// buildgate.MultiProvider, false in the release build until NordVPN's memory
// has been measured on a live exit (docs/design/multi-provider.md, decision
// 4), and true only under the drill build tag. The panel reads the same
// switch, so the two never disagree.
const multiProviderAvailable = buildgate.MultiProvider
