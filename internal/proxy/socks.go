package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"syscall"
)

// SOCKS5 (RFC 1928) and its username and password authentication (RFC 1929).
const (
	socksVersion   = 0x05
	authVersion    = 0x01
	methodUserPass = 0x02
	methodNone     = 0xff
	cmdConnect     = 0x01
	atypIPv4       = 0x01
	atypDomain     = 0x03
	atypIPv6       = 0x04

	replySucceeded          = 0x00
	replyGeneralFailure     = 0x01
	replyNetworkUnreachable = 0x03
	replyHostUnreachable    = 0x04
	replyConnectionRefused  = 0x05
	replyCommandUnsupported = 0x07
	replyAddressUnsupported = 0x08
)

type socksConn struct {
	conn net.Conn
	br   *bufio.Reader
	s    *server
}

func (c *socksConn) read() (request, bool) {
	// The greeting: version, and the methods the client offers.
	var head [2]byte
	if _, err := io.ReadFull(c.br, head[:]); err != nil || head[1] == 0 {
		return request{}, false
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(c.br, methods); err != nil {
		return request{}, false
	}
	offered := false
	for _, m := range methods {
		offered = offered || m == methodUserPass
	}
	if !offered {
		c.conn.Write([]byte{socksVersion, methodNone})
		return request{}, false
	}
	if _, err := c.conn.Write([]byte{socksVersion, methodUserPass}); err != nil {
		return request{}, false
	}

	// RFC 1929: version 1, the username, the password.
	username, password, ok := c.readUserPass()
	if !ok {
		return request{}, false
	}
	location, session, ok := c.s.authenticate(username, password)
	if !ok {
		c.conn.Write([]byte{authVersion, 0x01})
		return request{}, false
	}
	if _, err := c.conn.Write([]byte{authVersion, 0x00}); err != nil {
		return request{}, false
	}

	// The request: version, command, reserved, address.
	var req [4]byte
	if _, err := io.ReadFull(c.br, req[:]); err != nil || req[0] != socksVersion || req[2] != 0 {
		return request{}, false
	}
	var host string
	switch req[3] {
	case atypIPv4, atypIPv6:
		size := 4
		if req[3] == atypIPv6 {
			size = 16
		}
		raw := make([]byte, size)
		if _, err := io.ReadFull(c.br, raw); err != nil {
			return request{}, false
		}
		ip, _ := netip.AddrFromSlice(raw)
		host = ip.String()
	case atypDomain:
		n, err := c.br.ReadByte()
		if err != nil || n == 0 {
			return request{}, false
		}
		raw := make([]byte, n)
		if _, err := io.ReadFull(c.br, raw); err != nil {
			return request{}, false
		}
		host = string(raw)
	default:
		c.reply(replyAddressUnsupported)
		return request{}, false
	}
	var portRaw [2]byte
	if _, err := io.ReadFull(c.br, portRaw[:]); err != nil {
		return request{}, false
	}
	port := int(binary.BigEndian.Uint16(portRaw[:]))
	if req[1] != cmdConnect {
		c.reply(replyCommandUnsupported)
		return request{}, false
	}
	if !validTarget(host, port) {
		c.reply(replyAddressUnsupported)
		return request{}, false
	}
	return request{location: location, session: session, target: net.JoinHostPort(host, strconv.Itoa(port))}, true
}

func (c *socksConn) readUserPass() (string, []byte, bool) {
	version, err := c.br.ReadByte()
	if err != nil || version != authVersion {
		return "", nil, false
	}
	field := func() ([]byte, bool) {
		n, err := c.br.ReadByte()
		if err != nil {
			return nil, false
		}
		b := make([]byte, n)
		_, err = io.ReadFull(c.br, b)
		return b, err == nil
	}
	user, ok1 := field()
	pass, ok2 := field()
	if !ok1 || !ok2 {
		return "", nil, false
	}
	return string(user), pass, true
}

// reply writes a reply with an all-zero bound address: the proxy's own
// addresses are not the client's business.
func (c *socksConn) reply(code byte) error {
	_, err := c.conn.Write([]byte{socksVersion, code, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

func (c *socksConn) refuse(err error) { c.reply(socksReplyFor(err)) }

func (c *socksConn) ready() error { return c.reply(replySucceeded) }

// socksReplyFor is the reply for a failed Upstream.Dial: a refused, host- or
// network-unreachable or timed-out connection as such (an Upstream passes
// the far end's answer on by wrapping the matching errno), anything else,
// and a refusal for the tunnel (nil), as a general failure.
func socksReplyFor(err error) byte {
	var ne net.Error
	switch {
	case err == nil:
		return replyGeneralFailure
	case errors.Is(err, syscall.ECONNREFUSED):
		return replyConnectionRefused
	case errors.Is(err, syscall.EHOSTUNREACH):
		return replyHostUnreachable
	case errors.Is(err, syscall.ENETUNREACH):
		return replyNetworkUnreachable
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, syscall.ETIMEDOUT), errors.As(err, &ne) && ne.Timeout():
		return replyHostUnreachable
	}
	return replyGeneralFailure
}
