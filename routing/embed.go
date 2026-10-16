// Package routing carries routing/gluetun-preflight into the binary, so the
// gluetun-preflight role can write it where no source tree is at hand (a
// Kubernetes init container, for one).
package routing

import _ "embed"

// GluetunPreflight is routing/gluetun-preflight, byte for byte.
//
//go:embed gluetun-preflight
var GluetunPreflight []byte
