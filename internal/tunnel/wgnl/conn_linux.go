//go:build linux

// Package wgnl talks to the kernel's WireGuard generic netlink family on a
// socket it owns: one connection, an absolute deadline set before every
// request (and before the family lookup that opens it), closed when the
// operation's context ends so that a read that the deadline did not reach is
// unblocked, and replaced the next time. wgctrl offers none of that, and its
// constructor opens a socket and blocks on a family lookup before the caller
// can reach either.
package wgnl

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// ErrNoWireGuard says the kernel has no WireGuard generic netlink family.
var ErrNoWireGuard = errors.New("wgnl: the kernel has no WireGuard")

// ErrBroken says the connection was closed at a deadline or after a failure of
// its stream and must be replaced.
var ErrBroken = errors.New("wgnl: connection closed; open a new one")

// socket is the part of a generic netlink connection the package uses; tests
// supply their own.
type socket interface {
	GetFamily(name string) (genetlink.Family, error)
	Execute(m genetlink.Message, family uint16, flags netlink.HeaderFlags) ([]genetlink.Message, error)
	SetDeadline(t time.Time) error
	Close() error
}

// Conn is one WireGuard generic netlink connection.
type Conn struct {
	mu     sync.Mutex // one request at a time
	s      socket
	family uint16
	broken atomic.Bool
}

// Dial opens a connection in the network namespace netnsFd (0: the caller's)
// and resolves the WireGuard family on it, all under ctx: the deadline is on
// the socket before the lookup, and the socket is closed if ctx ends first.
func Dial(ctx context.Context, netnsFd int) (*Conn, error) {
	g, err := genetlink.Dial(&netlink.Config{NetNS: netnsFd})
	if err != nil {
		return nil, fmt.Errorf("wgnl: open generic netlink: %w", err)
	}
	// Best effort version of netlink.Config.Strict due to CentOS 7 (as wgctrl).
	for _, o := range []netlink.ConnOption{netlink.ExtendedAcknowledge, netlink.GetStrictCheck} {
		_ = g.SetOption(o, true)
	}
	return dialOn(ctx, g)
}

func dialOn(ctx context.Context, s socket) (*Conn, error) {
	c := &Conn{s: s}
	release, err := c.bind(ctx)
	if err != nil {
		_ = s.Close()
		return nil, err
	}
	defer release()
	f, err := s.GetFamily(unix.WG_GENL_NAME)
	if err != nil {
		_ = s.Close()
		if ctx.Err() != nil {
			return nil, deadlineErr(ctx)
		}
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNoWireGuard
		}
		return nil, fmt.Errorf("wgnl: look up the WireGuard family: %w", err)
	}
	c.family = f.ID
	return c, nil
}

func deadlineErr(ctx context.Context) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("wgnl: %w", os.ErrDeadlineExceeded)
	}
	return ctx.Err()
}

// bind puts ctx's deadline on the socket and arranges for the socket to be
// closed if ctx ends before release is called.
func (c *Conn) bind(ctx context.Context) (release func(), err error) {
	if err := ctx.Err(); err != nil {
		return nil, deadlineErr(ctx)
	}
	dl, _ := ctx.Deadline()
	if err := c.s.SetDeadline(dl); err != nil {
		return nil, err
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-ctx.Done():
			c.markBroken()
			_ = c.s.Close()
		case <-stop:
		}
	}()
	return func() { close(stop); <-done }, nil
}

func (c *Conn) markBroken() { c.broken.Store(true) }

// Broken reports that the connection was closed and must be replaced.
func (c *Conn) Broken() bool { return c.broken.Load() }

// Close closes the connection and unblocks a request in flight.
func (c *Conn) Close() error {
	c.markBroken()
	return c.s.Close()
}

// execute runs one request under ctx.
func (c *Conn) execute(ctx context.Context, command uint8, flags netlink.HeaderFlags, attrs []byte) ([]genetlink.Message, error) {
	if c.Broken() {
		return nil, ErrBroken
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	release, err := c.bind(ctx)
	if err != nil {
		return nil, err
	}
	msgs, err := c.s.Execute(genetlink.Message{Header: genetlink.Header{Command: command, Version: unix.WG_GENL_VERSION}, Data: attrs}, c.family, flags)
	release()
	if err == nil {
		return msgs, nil
	}
	if ctx.Err() != nil {
		c.markBroken()
		_ = c.s.Close()
		return nil, deadlineErr(ctx)
	}
	var oerr *netlink.OpError
	if errors.As(err, &oerr) {
		switch oerr.Err {
		// "No such device" and "not a wireguard device" are os.ErrNotExist
		// for easy checking, as wgctrl reports them.
		case unix.ENODEV, unix.ENOTSUP:
			return nil, os.ErrNotExist
		}
		if errors.Is(oerr.Err, os.ErrDeadlineExceeded) {
			c.markBroken()
			_ = c.s.Close()
		}
		return nil, oerr.Err
	}
	// Anything that is not the kernel's refusal leaves the stream in doubt.
	c.markBroken()
	_ = c.s.Close()
	return nil, err
}

// Device reads a WireGuard device (wgctrl's Client.Device).
func (c *Conn) Device(ctx context.Context, name string) (*wgtypes.Device, error) {
	if name == "" {
		return nil, os.ErrNotExist
	}
	b, err := netlink.MarshalAttributes([]netlink.Attribute{{Type: unix.WGDEVICE_A_IFNAME, Data: nlenc.Bytes(name)}})
	if err != nil {
		return nil, err
	}
	msgs, err := c.execute(ctx, unix.WG_CMD_GET_DEVICE, netlink.Request|netlink.Dump, b)
	if err != nil {
		return nil, err
	}
	return parseDevice(msgs)
}

// Configure sets a WireGuard device (wgctrl's Client.ConfigureDevice),
// splitting a large configuration into batches as wgctrl does. ctx covers
// all the batches.
func (c *Conn) Configure(ctx context.Context, name string, cfg wgtypes.Config) error {
	for _, b := range buildBatches(cfg) {
		attrs, err := configAttrs(name, b)
		if err != nil {
			return err
		}
		if _, err := c.execute(ctx, unix.WG_CMD_SET_DEVICE, netlink.Request|netlink.Acknowledge, attrs); err != nil {
			return err
		}
	}
	return nil
}
