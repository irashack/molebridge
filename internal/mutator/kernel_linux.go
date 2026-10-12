//go:build linux

package mutator

import "github.com/irashack/molebridge/internal/rtnl"

var (
	_ Kernel    = (*rtnl.Conn)(nil)
	_ timeouter = (*rtnl.Conn)(nil)
)
