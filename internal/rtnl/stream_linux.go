//go:build linux

package rtnl

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// This file is the request socket's stream layer. It reads the kernel's
// replies itself, from the raw socket, instead of through
// netlink.Conn.Execute, for three reasons the routing contract depends on:
//
//   - NLMSG_DONE must be seen. The kernel marks a dump that raced with a change
//     with NLM_F_DUMP_INTR on the message that ends it as well as on the
//     entries; the vendored Conn trims the DONE message before the caller can
//     read its flags.
//   - A reply that was never read (a timeout, ENOBUFS) must not be able to
//     answer the next request. Any failure of the stream, as opposed to a
//     refusal from the kernel, closes the socket; the next request opens a
//     fresh one, which has no stale reply queued, and the caller takes the
//     whole snapshot again.
//   - One absolute deadline covers a whole operation: every request, retry and
//     dump of it is bounded by the same instant.

// ErrStream says the request socket's stream could not be trusted (a
// timeout, lost or out-of-sequence replies, a malformed message) and was
// closed. The next request opens a new socket. It wraps the cause.
var ErrStream = errors.New("rtnl: request socket reset")

// errInterrupted is a dump the kernel marked NLM_F_DUMP_INTR.
var errInterrupted = errors.New("rtnl: dump interrupted by a concurrent change")

const recvBuffer = 1 << 17

const (
	nlmsgNoop    = 1
	nlmsgError   = 2
	nlmsgDone    = 3
	nlmsgOverrun = 4

	nlmRequest   = 0x1
	nlmMulti     = 0x2
	nlmAck       = 0x4
	nlmRoot      = 0x100
	nlmMatch     = 0x200
	nlmDump      = nlmRoot | nlmMatch
	nlmReplace   = 0x100
	nlmExcl      = 0x200
	nlmCreate    = 0x400
	nlmDumpIntr  = 0x10
	nlmAckTLVs   = 0x200
	nlmCapped    = 0x100
	nlmsgHdrLen  = 16
	nlmsgerrAMsg = 1
)

// transport is one netlink socket; tests supply their own over a socketpair.
type transport interface {
	send(b []byte) error
	recv(buf []byte) (int, error)
	setDeadline(time.Time) error
	close() error
}

type netlinkTransport struct {
	c  *netlink.Conn
	rc interface {
		Read(func(uintptr) bool) error
		Write(func(uintptr) bool) error
	}
}

func dialNetlink(o Options) (transport, error) {
	c, err := netlink.Dial(unix.NETLINK_ROUTE, &netlink.Config{NetNS: o.NetNS})
	if err != nil {
		return nil, fmt.Errorf("rtnl: open netlink socket: %w", err)
	}
	// Extended acknowledgements make kernel refusals readable; older kernels
	// lack them and that is fine.
	_ = c.SetOption(netlink.ExtendedAcknowledge, true)
	if o.ReadBuffer > 0 {
		_ = c.SetReadBuffer(o.ReadBuffer)
	}
	rc, err := c.SyscallConn()
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("rtnl: open netlink socket: %w", err)
	}
	return &netlinkTransport{c: c, rc: rc}, nil
}

func (t *netlinkTransport) send(b []byte) error {
	var serr error
	err := t.rc.Write(func(fd uintptr) bool {
		serr = unix.Sendto(int(fd), b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})
		return serr != unix.EAGAIN
	})
	if err != nil {
		return err
	}
	return serr
}

func (t *netlinkTransport) recv(buf []byte) (int, error) {
	var n int
	var serr error
	err := t.rc.Read(func(fd uintptr) bool {
		n, _, serr = unix.Recvfrom(int(fd), buf, unix.MSG_TRUNC)
		return serr != unix.EAGAIN
	})
	if err != nil {
		return 0, err
	}
	return n, serr
}

func (t *netlinkTransport) setDeadline(d time.Time) error { return t.c.SetDeadline(d) }
func (t *netlinkTransport) close() error                  { return t.c.Close() }

// Conn is a NETLINK_ROUTE request socket. It is safe for concurrent use;
// requests are serialized. Close may be called from another goroutine to
// unblock a request in flight.
type Conn struct {
	opts Options
	dial func() (transport, error)

	mu      sync.Mutex // one request at a time
	timeout time.Duration
	// deadline is the operation's absolute deadline; zero means none.
	deadline time.Time
	seq      uint32
	resets   int
	// interrupts counts dumps the kernel marked NLM_F_DUMP_INTR.
	interrupts int

	// churn is a private multicast subscription that tells a snapshot whether
	// anything changed while it was being taken. Optional.
	churn  churnSource
	reopen func() (churnSource, error)
	// takeMu serializes snapshots, which use the subscription.
	takeMu  sync.Mutex
	churnMu sync.Mutex

	tmu    sync.Mutex // guards t and closed
	t      transport
	closed bool
}

// Dial opens a request socket.
func Dial(o Options) (*Conn, error) {
	c := &Conn{opts: o, dial: func() (transport, error) { return dialNetlink(o) }, timeout: DefaultTimeout}
	t, err := c.dial()
	if err != nil {
		return nil, err
	}
	c.t = t
	// Best effort: without it a snapshot is judged by two looks that agree.
	c.reopen = func() (churnSource, error) { return Subscribe(o) }
	if sub, err := Subscribe(o); err == nil {
		c.churn = sub
	}
	return c, nil
}

// churnSource is what a Conn needs of its change detector; *Subscriber.
type churnSource interface {
	Next(deadline time.Time) ([]Event, error)
	Close() error
}

// Close closes the socket and unblocks a request in flight.
func (c *Conn) Close() error {
	if ch := c.swapChurn(nil); ch != nil {
		_ = ch.Close()
	}
	c.tmu.Lock()
	defer c.tmu.Unlock()
	c.closed = true
	if c.t == nil {
		return nil
	}
	err := c.t.close()
	c.t = nil
	return err
}

// SetTimeout changes the bound on each request. It is a ceiling per request;
// SetDeadline bounds a whole operation.
func (c *Conn) SetTimeout(d time.Duration) {
	c.mu.Lock()
	c.timeout = d
	c.mu.Unlock()
}

// Interrupts counts the dumps the kernel marked as interrupted by a concurrent
// change, each of which was discarded.
func (c *Conn) Interrupts() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.interrupts
}

// Resets counts how many times the stream has been closed and reopened.
func (c *Conn) Resets() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.resets
}

// SetDeadline sets the absolute deadline of the operation in progress: every
// request, dump and retry made after it ends at that instant at the latest,
// and none starts after it. The zero time removes it.
func (c *Conn) SetDeadline(t time.Time) {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
}

// socket returns the live transport, opening one if the last was closed.
func (c *Conn) socket() (transport, error) {
	c.tmu.Lock()
	defer c.tmu.Unlock()
	if c.closed {
		return nil, errClosed
	}
	if c.t == nil {
		t, err := c.dial()
		if err != nil {
			return nil, err
		}
		c.t = t
		c.resets++
	}
	return c.t, nil
}

// reset closes the socket after its stream failed.
func (c *Conn) reset(cause error) error {
	c.tmu.Lock()
	if c.t != nil {
		_ = c.t.close()
		c.t = nil
	}
	c.tmu.Unlock()
	return fmt.Errorf("%w: %w", ErrStream, cause)
}

var errClosed = errors.New("rtnl: connection closed")

type rawMsg struct {
	typ   uint16
	flags uint16
	seq   uint32
	data  []byte
}

// kernelError is the kernel's refusal of a request: the stream is intact.
type kernelError struct {
	errno   syscall.Errno
	message string
}

func (e *kernelError) Error() string {
	if e.message != "" {
		return fmt.Sprintf("%v (%s)", e.errno, e.message)
	}
	return e.errno.Error()
}
func (e *kernelError) Unwrap() error { return e.errno }

// parseError reads the payload of an NLMSG_ERROR (or the payload of a DONE
// that carries an error number).
func parseError(m rawMsg) (*kernelError, bool) {
	if len(m.data) < 4 {
		return nil, false
	}
	code := int32(native.Uint32(m.data[:4]))
	if code == 0 {
		return nil, true
	}
	e := &kernelError{errno: syscall.Errno(-code)}
	if m.typ == nlmsgError && m.flags&nlmAckTLVs != 0 && len(m.data) >= 4+nlmsgHdrLen {
		off := 4 + nlmsgHdrLen
		if m.flags&nlmCapped == 0 {
			off = 4 + int(native.Uint32(m.data[4:8]))
		}
		if off >= 4 && off <= len(m.data) {
			if attrs, err := parseAttrs(m.data[off:]); err == nil {
				for _, a := range attrs {
					if a.typ == nlmsgerrAMsg {
						if s, ok := attrString(a.data); ok {
							e.message = s
						}
					}
				}
			}
		}
	}
	return e, true
}

// splitMessages takes a datagram apart. Any structural defect is an error.
func splitMessages(b []byte) ([]rawMsg, error) {
	var out []rawMsg
	for len(b) > 0 {
		if len(b) < nlmsgHdrLen {
			return nil, fmt.Errorf("%w: truncated netlink header", ErrMalformed)
		}
		n := int(native.Uint32(b[0:4]))
		if n < nlmsgHdrLen || n > len(b) {
			return nil, fmt.Errorf("%w: netlink message length %d", ErrMalformed, n)
		}
		out = append(out, rawMsg{
			typ:   native.Uint16(b[4:6]),
			flags: native.Uint16(b[6:8]),
			seq:   native.Uint32(b[8:12]),
			data:  cloneBytes(b[nlmsgHdrLen:n]),
		})
		adv := (n + 3) &^ 3
		if adv > len(b) {
			adv = len(b)
		}
		b = b[adv:]
	}
	return out, nil
}

func (c *Conn) effectiveDeadline() (time.Time, error) {
	now := time.Now()
	d := now.Add(c.timeout)
	if !c.deadline.IsZero() {
		if !c.deadline.After(now) {
			return time.Time{}, ErrDeadline
		}
		if c.deadline.Before(d) {
			d = c.deadline
		}
	}
	return d, nil
}

// exchange sends one request and reads its whole reply. A dump's reply ends
// at NLMSG_DONE; any other request's at the acknowledgement. The messages
// that are not control messages are returned, with whether the kernel marked
// the reply interrupted (on any message, DONE included).
func (c *Conn) exchange(ctx context.Context, typ uint16, flags uint16, data []byte) (msgs []rawMsg, interrupted bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
	}
	deadline, err := c.effectiveDeadline()
	if err != nil {
		return nil, false, err
	}
	if ctx != nil {
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
	}
	t, err := c.socket()
	if err != nil {
		return nil, false, err
	}
	if err := t.setDeadline(deadline); err != nil {
		return nil, false, c.reset(err)
	}
	c.seq++
	seq := c.seq
	req := make([]byte, nlmsgHdrLen, nlmsgHdrLen+len(data))
	binary.NativeEndian.PutUint32(req[0:4], uint32(nlmsgHdrLen+len(data)))
	binary.NativeEndian.PutUint16(req[4:6], typ)
	binary.NativeEndian.PutUint16(req[6:8], flags)
	binary.NativeEndian.PutUint32(req[8:12], seq)
	req = append(req, data...)
	if err := t.send(req); err != nil {
		return nil, false, c.reset(streamCause(err))
	}
	isDump := flags&nlmDump == nlmDump
	buf := make([]byte, recvBuffer)
	for {
		n, err := t.recv(buf)
		if err != nil {
			return nil, false, c.reset(streamCause(err))
		}
		if n > len(buf) {
			return nil, false, c.reset(fmt.Errorf("%w: reply larger than %d bytes", ErrMalformed, len(buf)))
		}
		batch, err := splitMessages(buf[:n])
		if err != nil {
			return nil, false, c.reset(err)
		}
		for _, m := range batch {
			if m.seq != seq {
				return nil, false, c.reset(fmt.Errorf("reply with sequence %d while waiting for %d", m.seq, seq))
			}
			if m.flags&nlmDumpIntr != 0 {
				interrupted = true
			}
			switch m.typ {
			case nlmsgNoop:
			case nlmsgOverrun:
				return nil, false, c.reset(errors.New("the kernel reported an overrun"))
			case nlmsgError:
				ke, ok := parseError(m)
				if !ok {
					return nil, false, c.reset(fmt.Errorf("%w: short error message", ErrMalformed))
				}
				if ke != nil {
					return nil, false, ke
				}
				if !isDump {
					return msgs, interrupted, nil
				}
			case nlmsgDone:
				if ke, ok := parseError(m); ok && ke != nil {
					return nil, false, ke
				}
				return msgs, interrupted, nil
			default:
				msgs = append(msgs, m)
				if !isDump && m.flags&nlmMulti == 0 && flags&nlmAck == 0 {
					return msgs, interrupted, nil
				}
			}
		}
	}
}

func streamCause(err error) error {
	if errors.Is(err, unix.ENOBUFS) {
		return fmt.Errorf("receive buffer overrun, replies were lost: %w", err)
	}
	return err
}

// IsStreamError reports a failure of the request stream (ErrStream), after
// which the socket was replaced: the caller must discard what it read and
// start its snapshot again.
func IsStreamError(err error) bool { return errors.Is(err, ErrStream) }

// dump runs one dump request and returns the payloads of the replies of the
// wanted type. A dump marked interrupted is reported as errInterrupted.
func (c *Conn) dump(ctx context.Context, typ, want uint16, data []byte) ([][]byte, error) {
	msgs, interrupted, err := c.exchange(ctx, typ, nlmRequest|nlmDump, data)
	if err != nil {
		return nil, err
	}
	if interrupted {
		c.mu.Lock()
		c.interrupts++
		c.mu.Unlock()
		return nil, errInterrupted
	}
	out := make([][]byte, 0, len(msgs))
	for _, m := range msgs {
		if m.typ == want {
			out = append(out, m.data)
		}
	}
	return out, nil
}

// dumpRetry is a single dump with its own retries, for the public per-object
// calls. Take retries the whole snapshot instead.
func (c *Conn) dumpRetry(ctx context.Context, typ, want uint16, data []byte) ([][]byte, error) {
	for attempt := 0; attempt < maxDumpAttempts; attempt++ {
		out, err := c.dump(ctx, typ, want, data)
		switch {
		case err == nil:
			return out, nil
		case errors.Is(err, errInterrupted), IsStreamError(err) && attempt+1 < maxDumpAttempts && !errors.Is(err, os.ErrDeadlineExceeded):
			continue
		default:
			return nil, err
		}
	}
	return nil, ErrInconsistent
}

func (c *Conn) request(ctx context.Context, typ, flags uint16, data []byte) error {
	_, _, err := c.exchange(ctx, typ, flags, data)
	return err
}

// getChurn and swapChurn guard the pointer: Close may run while a snapshot does.
func (c *Conn) getChurn() churnSource {
	c.churnMu.Lock()
	defer c.churnMu.Unlock()
	return c.churn
}

func (c *Conn) swapChurn(n churnSource) churnSource {
	c.churnMu.Lock()
	defer c.churnMu.Unlock()
	old := c.churn
	c.churn = n
	return old
}
