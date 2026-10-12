//go:build linux

package watch

import "github.com/irashack/molebridge/internal/rtnl"

var _ Source = (*rtnl.Subscriber)(nil)
