//go:build linux

package wgnl

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// A socket that, like a netlink socket, ends a blocked read when it is closed
// or when its deadline passes, and otherwise never answers.
type stall struct {
	mu       sync.Mutex
	deadline time.Time
	closed   chan struct{}
	once     sync.Once
	// answer, if set, replies to Execute instead of blocking.
	answer       func(cmd uint8, flags netlink.HeaderFlags, data []byte) ([]genetlink.Message, error)
	familyAnswer bool
	deadlines    []time.Time
	requests     atomic.Int32
}

func newStall() *stall { return &stall{closed: make(chan struct{})} }

func (s *stall) block() error {
	s.mu.Lock()
	dl := s.deadline
	s.mu.Unlock()
	if dl.IsZero() {
		<-s.closed
		return errors.New("closed")
	}
	select {
	case <-s.closed:
		return errors.New("closed")
	case <-time.After(time.Until(dl)):
		return &netlink.OpError{Op: "receive", Err: os.ErrDeadlineExceeded}
	}
}

func (s *stall) GetFamily(string) (genetlink.Family, error) {
	if s.familyAnswer {
		return genetlink.Family{ID: 42}, nil
	}
	return genetlink.Family{}, s.block()
}

func (s *stall) Execute(m genetlink.Message, family uint16, flags netlink.HeaderFlags) ([]genetlink.Message, error) {
	s.requests.Add(1)
	if s.answer != nil {
		return s.answer(m.Header.Command, flags, m.Data)
	}
	return nil, s.block()
}

func (s *stall) SetDeadline(t time.Time) error {
	s.mu.Lock()
	s.deadline = t
	s.deadlines = append(s.deadlines, t)
	s.mu.Unlock()
	return nil
}

func (s *stall) Close() error { s.once.Do(func() { close(s.closed) }); return nil }

func TestTheFamilyLookupThatOpensTheConnectionIsBounded(t *testing.T) { // finding: wgctrl.New's lookup could not be reached
	s := newStall()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := dialOn(ctx, s)
	if err == nil || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("%v", err)
	}
	if time.Since(start) > 250*time.Millisecond {
		t.Errorf("took %v", time.Since(start))
	}
	select {
	case <-s.closed:
	default:
		t.Error("the socket was left open")
	}
	s.mu.Lock()
	if len(s.deadlines) == 0 || s.deadlines[0].IsZero() {
		t.Error("no deadline was on the socket when the lookup started")
	}
	s.mu.Unlock()
}

func TestALookupThatIgnoresTheDeadlineIsEndedByClosingTheSocket(t *testing.T) {
	s := newStall()
	s.deadline = time.Time{}
	// Context without a deadline, cancelled: nothing but the close can help.
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(40 * time.Millisecond); cancel() }()
	done := make(chan error, 1)
	go func() { _, err := dialOn(ctx, s); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("no error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the lookup outlived the cancellation")
	}
}

func TestAMissingFamilyIsNamed(t *testing.T) {
	s := newStall()
	s.once.Do(func() {}) // not used
	g := &missing{stall: s}
	if _, err := dialOn(context.Background(), g); !errors.Is(err, ErrNoWireGuard) {
		t.Fatalf("%v", err)
	}
}

type missing struct{ *stall }

func (m *missing) GetFamily(string) (genetlink.Family, error) {
	return genetlink.Family{}, os.ErrNotExist
}

func connected(t *testing.T, s *stall) *Conn {
	t.Helper()
	s.familyAnswer = true
	c, err := dialOn(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAStalledRequestEndsAtTheDeadlineAndTheConnectionIsBroken(t *testing.T) {
	s := newStall()
	c := connected(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.Device(ctx, "wt0")
	if err == nil || !errors.Is(err, os.ErrDeadlineExceeded) || time.Since(start) > 250*time.Millisecond {
		t.Fatalf("%v after %v", err, time.Since(start))
	}
	if !c.Broken() {
		t.Error("a connection cut off at a deadline must be replaced")
	}
	if _, err := c.Device(context.Background(), "wt0"); !errors.Is(err, ErrBroken) {
		t.Errorf("a broken connection was used again: %v", err)
	}
	if err := c.Configure(context.Background(), "wt0", wgtypes.Config{}); !errors.Is(err, ErrBroken) {
		t.Errorf("%v", err)
	}
}

func TestEveryRequestIsGivenTheContextsDeadline(t *testing.T) {
	s := newStall()
	s.answer = func(uint8, netlink.HeaderFlags, []byte) ([]genetlink.Message, error) { return nil, nil }
	c := connected(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	want, _ := ctx.Deadline()
	if err := c.Configure(ctx, "wt0", wgtypes.Config{}); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if got := s.deadlines[len(s.deadlines)-1]; !got.Equal(want) {
		t.Errorf("deadline %v, want %v", got, want)
	}
}

func TestACancelledContextSendsNothing(t *testing.T) {
	s := newStall()
	s.answer = func(uint8, netlink.HeaderFlags, []byte) ([]genetlink.Message, error) { return nil, nil }
	c := connected(t, s)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.Configure(ctx, "wt0", wgtypes.Config{}); err == nil || s.requests.Load() != 0 {
		t.Fatalf("%v, %d requests", err, s.requests.Load())
	}
}

func TestKernelRefusalsKeepTheConnection(t *testing.T) {
	s := newStall()
	s.answer = func(cmd uint8, _ netlink.HeaderFlags, _ []byte) ([]genetlink.Message, error) {
		return nil, &netlink.OpError{Op: "receive", Err: unix.ENODEV}
	}
	c := connected(t, s)
	if _, err := c.Device(context.Background(), "gone"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%v", err)
	}
	if c.Broken() {
		t.Error("a refusal replaced the connection")
	}
	s.answer = func(uint8, netlink.HeaderFlags, []byte) ([]genetlink.Message, error) {
		return nil, &netlink.OpError{Op: "receive", Err: unix.EPERM}
	}
	if err := c.Configure(context.Background(), "x", wgtypes.Config{}); !errors.Is(err, unix.EPERM) || c.Broken() {
		t.Fatalf("%v broken=%v", err, c.Broken())
	}
}

// The attributes written for a configuration are those wgctrl writes, and a
// device message is read back into the same values.
func TestConfigureAndDeviceRoundTripTheWireGuardAttributes(t *testing.T) {
	key := wgtypes.Key{1, 2, 3}
	peerKey := wgtypes.Key{9, 9}
	mark := 0x1bd00
	port := 51820
	keepalive := 25 * time.Second
	var sent []byte
	var cmd uint8
	s := newStall()
	s.answer = func(c uint8, _ netlink.HeaderFlags, data []byte) ([]genetlink.Message, error) {
		cmd, sent = c, append([]byte(nil), data...)
		return nil, nil
	}
	c := connected(t, s)
	cfg := wgtypes.Config{PrivateKey: &key, ListenPort: &port, FirewallMark: &mark, ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{{PublicKey: peerKey, ReplaceAllowedIPs: true, PersistentKeepaliveInterval: &keepalive,
			Endpoint:   &net.UDPAddr{IP: net.ParseIP("198.51.100.10"), Port: 51820},
			AllowedIPs: []net.IPNet{{IP: net.ParseIP("0.0.0.0").To4(), Mask: net.CIDRMask(0, 32)}, {IP: net.ParseIP("::"), Mask: net.CIDRMask(0, 128)}}}}}
	if err := c.Configure(context.Background(), "wg0", cfg); err != nil {
		t.Fatal(err)
	}
	if cmd != unix.WG_CMD_SET_DEVICE || len(sent) == 0 {
		t.Fatalf("%d %x", cmd, sent)
	}
	// Read it back as a device message: the same attribute layout.
	reply := genetlink.Message{Data: sent}
	s.answer = func(uint8, netlink.HeaderFlags, []byte) ([]genetlink.Message, error) {
		return []genetlink.Message{reply}, nil
	}
	d, err := c.Device(context.Background(), "wg0")
	if err != nil {
		t.Fatal(err)
	}
	if d.Name != "wg0" || d.PrivateKey != key || d.ListenPort != port || d.FirewallMark != mark || len(d.Peers) != 1 {
		t.Fatalf("%+v", d)
	}
	p := d.Peers[0]
	if p.PublicKey != peerKey || p.PersistentKeepaliveInterval != keepalive || p.Endpoint.String() != "198.51.100.10:51820" || len(p.AllowedIPs) != 2 {
		t.Fatalf("%+v", p)
	}
}
