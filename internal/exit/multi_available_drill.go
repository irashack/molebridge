//go:build drill

package exit

// multiProviderAvailable: the drill build accepts PROVIDERS, so the drills
// and the system rig's molebridge-drill can run a multi-provider exit that
// the release build refuses (multi_available.go).
const multiProviderAvailable = true
