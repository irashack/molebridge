//go:build !drill

package exit

// multiProviderAvailable is the switch for multi-provider exits (PROVIDERS).
// It stays false in the release build until NordVPN's memory has been
// measured on a live exit (docs/design/multi-provider.md, decision 4); a
// later release turns it on. Builds with the drill tag (the rig's
// molebridge-drill, the drills) have it on (multi_available_drill.go).
const multiProviderAvailable = false
