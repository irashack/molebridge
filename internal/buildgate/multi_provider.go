//go:build !drill

// Package buildgate holds the switches a build turns features on or off
// with, so that every binary of one build agrees on them.
package buildgate

// MultiProvider is the switch for multi-provider exits (the exit's
// PROVIDERS, and the panel's id=mullvad+pia+nordvpn exits and PROVIDERS). It
// stays false in the release build until NordVPN's memory has been measured
// on a live exit (docs/design/multi-provider.md, decision 4); a later release
// turns it on. Builds with the drill tag (the rig's molebridge-drill, the
// drills) have it on (multi_provider_drill.go). The exit and the panel both
// read it, so a release-build panel never offers what a release-build exit
// refuses.
const MultiProvider = false
