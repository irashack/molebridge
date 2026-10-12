//go:build linux

// Package deps pins the vendored netlink and WireGuard modules until each has
// a real importer. It is deleted once internal/rtnl, internal/tunnel and
// internal/nft import them.
package deps

import (
	_ "github.com/google/nftables"
	_ "github.com/mdlayher/netlink"
	_ "github.com/vishvananda/netlink"
	_ "github.com/vishvananda/netns"
	_ "golang.zx2c4.com/wireguard/wgctrl"
)
