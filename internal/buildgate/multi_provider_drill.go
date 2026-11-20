//go:build drill

package buildgate

// MultiProvider: the drill build accepts multi-provider exits, so the drills
// and the system rig's molebridge-drill can run one that the release build
// refuses (multi_provider.go).
const MultiProvider = true
