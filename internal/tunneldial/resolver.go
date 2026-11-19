package tunneldial

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"time"
)

// DefaultResolverTimeout bounds one query exchange when Resolver.Timeout is
// zero.
const DefaultResolverTimeout = 5 * time.Second

// ErrServer is the refusal for a Server that is not an IP literal and port.
var ErrServer = errors.New("tunneldial: DNS server must be an IP literal and a port")

// Resolver resolves names over DNS sent through Dialer to Server (for
// Mullvad 10.64.0.1:53), never the system resolver. It asks over UDP and asks
// again over TCP when the answer is truncated.
type Resolver struct {
	Dialer  *Dialer
	Server  string        // "ip:port"
	Timeout time.Duration // per query exchange, default 5s

	// dial replaces Dialer.DialContext (tests).
	dial func(ctx context.Context, network, address string) (net.Conn, error)
}

// LookupNetIP looks host up: network "ip4" asks for A records, "ip6" for
// AAAA, "ip" for both (A first; one family failing is fine while the other
// answers). host must be a name; IP literals are refused.
func (r *Resolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	name, err := canonicalName(host)
	if err != nil {
		return nil, err
	}
	if _, err := parseLiteral(r.Server); err != nil {
		return nil, ErrServer
	}
	switch network {
	case "ip4":
		return r.query(ctx, name, TypeA)
	case "ip6":
		return r.query(ctx, name, TypeAAAA)
	case "ip":
		v4, err4 := r.query(ctx, name, TypeA)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		v6, err6 := r.query(ctx, name, TypeAAAA)
		if err4 != nil && err6 != nil {
			// The A answer's error says more, unless it only had no address.
			if errors.Is(err4, ErrNoAddress) {
				return nil, err6
			}
			return nil, err4
		}
		return append(v4, v6...), nil
	}
	return nil, ErrNetwork
}

func (r *Resolver) timeout() time.Duration {
	if r.Timeout > 0 {
		return r.Timeout
	}
	return DefaultResolverTimeout
}

func (r *Resolver) dialer() func(ctx context.Context, network, address string) (net.Conn, error) {
	if r.dial != nil {
		return r.dial
	}
	if r.Dialer == nil {
		return func(context.Context, string, string) (net.Conn, error) { return nil, ErrInterface }
	}
	return r.Dialer.DialContext
}

func newID() (uint16, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b[:]), nil
}

// query asks once over UDP and, if the answer is truncated, once over TCP.
func (r *Resolver) query(ctx context.Context, name string, qtype uint16) ([]netip.Addr, error) {
	id, err := newID()
	if err != nil {
		return nil, err
	}
	q := buildQuery(id, name, qtype)
	addrs, err := r.exchange(ctx, "udp", q, id, name, qtype)
	if errors.Is(err, ErrTruncated) {
		if id, err = newID(); err != nil {
			return nil, err
		}
		q = buildQuery(id, name, qtype)
		addrs, err = r.exchange(ctx, "tcp", q, id, name, qtype)
	}
	return addrs, err
}

// exchange sends q and reads the answer within the timeout and ctx. Over UDP
// a datagram that is not an answer to q (another ID or question) is skipped
// and the wait goes on, as a late or forged datagram must not end it.
func (r *Resolver) exchange(ctx context.Context, network string, q []byte, id uint16, name string, qtype uint16) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout())
	defer cancel()
	conn, err := r.dialer()(ctx, network, r.Server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	result, err := r.roundTrip(conn, network, q, id, name, qtype)
	if err != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return result, err
}

func (r *Resolver) roundTrip(conn net.Conn, network string, q []byte, id uint16, name string, qtype uint16) ([]netip.Addr, error) {
	if network == "tcp" {
		framed := binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(q)), uint16(len(q)))
		if _, err := conn.Write(append(framed, q...)); err != nil {
			return nil, err
		}
		var size [2]byte
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return nil, err
		}
		n := int(binary.BigEndian.Uint16(size[:]))
		if n < headerLen || n > MaxMessage {
			return nil, ErrMalformed
		}
		msg := make([]byte, n)
		if _, err := io.ReadFull(conn, msg); err != nil {
			return nil, err
		}
		return parseAnswer(msg, id, name, qtype)
	}
	if _, err := conn.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, MaxMessage+1)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		if n > MaxMessage {
			return nil, ErrMalformed
		}
		addrs, err := parseAnswer(buf[:n], id, name, qtype)
		if errors.Is(err, ErrMismatch) || errors.Is(err, ErrMalformed) && n < headerLen {
			continue
		}
		return addrs, err
	}
}
