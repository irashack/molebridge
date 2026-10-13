//go:build drill && linux

package drill

import (
	"sync"
	"syscall"

	"github.com/irashack/molebridge/internal/mutator"
	"github.com/irashack/molebridge/internal/rtnl"
)

// refusingKernel is the real kernel connection with a switch in front of its
// mutations: while a refusal is set, the request does not reach the kernel and
// fails as an allocation failure would. Reads, deadlines and the snapshot
// path are the connection's own (it is embedded), so the owner judges the real
// kernel and can only be kept from repairing it.
type refusingKernel struct {
	*rtnl.Conn
	mu     sync.Mutex
	refuse func(op string, priority uint32) bool
}

func (k *refusingKernel) set(f func(op string, priority uint32) bool) {
	k.mu.Lock()
	k.refuse = f
	k.mu.Unlock()
}

func (k *refusingKernel) check(op string, priority uint32) error {
	k.mu.Lock()
	f := k.refuse
	k.mu.Unlock()
	if f != nil && f(op, priority) {
		return syscall.ENOMEM
	}
	return nil
}

func (k *refusingKernel) AddRule(r rtnl.Rule) error {
	if err := k.check("add", r.Priority); err != nil {
		return err
	}
	return k.Conn.AddRule(r)
}

func (k *refusingKernel) DelRule(r rtnl.Rule) error {
	if err := k.check("del", r.Priority); err != nil {
		return err
	}
	return k.Conn.DelRule(r)
}

func (k *refusingKernel) DelRulePriority(f rtnl.Family, priority uint32) error {
	if err := k.check("del", priority); err != nil {
		return err
	}
	return k.Conn.DelRulePriority(f, priority)
}

func (k *refusingKernel) ReplaceRoute(r rtnl.Route) error {
	if err := k.check("route", 0); err != nil {
		return err
	}
	return k.Conn.ReplaceRoute(r)
}

func (k *refusingKernel) DelRoute(r rtnl.Route) error {
	if err := k.check("route", 0); err != nil {
		return err
	}
	return k.Conn.DelRoute(r)
}

// refusingWrap returns a wrap option and the kernel it will build.
func refusingWrap() (func(*rtnl.Conn) mutator.Kernel, func() *refusingKernel) {
	var k *refusingKernel
	var mu sync.Mutex
	return func(c *rtnl.Conn) mutator.Kernel {
			mu.Lock()
			defer mu.Unlock()
			k = &refusingKernel{Conn: c}
			return k
		}, func() *refusingKernel {
			mu.Lock()
			defer mu.Unlock()
			return k
		}
}

// refuseAll refuses every mutation.
func refuseAll(string, uint32) bool { return true }
