package relayproxy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
)

// The client side of SOCKS5 (RFC 1928) for a relay proxy: no
// authentication, CONNECT only, the target's host name sent as a domain
// address so it is resolved at the far end.

// SOCKS5 reply codes.
const (
	ReplySucceeded          byte = 0x00
	ReplyGeneralFailure     byte = 0x01
	ReplyNotAllowed         byte = 0x02
	ReplyNetworkUnreachable byte = 0x03
	ReplyHostUnreachable    byte = 0x04
	ReplyConnectionRefused  byte = 0x05
	ReplyTTLExpired         byte = 0x06
	ReplyCommandUnsupported byte = 0x07
	ReplyAddressUnsupported byte = 0x08
)

var replyText = map[byte]string{
	ReplyGeneralFailure:     "general failure",
	ReplyNotAllowed:         "connection not allowed",
	ReplyNetworkUnreachable: "network unreachable",
	ReplyHostUnreachable:    "host unreachable",
	ReplyConnectionRefused:  "connection refused",
	ReplyTTLExpired:         "TTL expired",
	ReplyCommandUnsupported: "command not supported",
	ReplyAddressUnsupported: "address type not supported",
}

// ReplyError is a relay proxy's failure reply to CONNECT.
type ReplyError struct{ Code byte }

func (e *ReplyError) Error() string {
	if text, ok := replyText[e.Code]; ok {
		return "relayproxy: relay proxy replied " + text
	}
	return fmt.Sprintf("relayproxy: relay proxy replied code %d", e.Code)
}

// Unwrap is the errno the proxy maps to its own reply: "connection refused"
// is ECONNREFUSED, "host unreachable" EHOSTUNREACH, "network unreachable"
// ENETUNREACH; other codes wrap nothing.
func (e *ReplyError) Unwrap() error {
	switch e.Code {
	case ReplyConnectionRefused:
		return syscall.ECONNREFUSED
	case ReplyHostUnreachable:
		return syscall.EHOSTUNREACH
	case ReplyNetworkUnreachable:
		return syscall.ENETUNREACH
	}
	return nil
}

// Target reports whether the reply is about the target, not the relay
// proxy: "host unreachable" or "connection refused". Those never bench it.
func (e *ReplyError) Target() bool {
	return e.Code == ReplyHostUnreachable || e.Code == ReplyConnectionRefused
}

// The handshake and target refusals. They never carry what was received.
var (
	ErrTarget    = errors.New("relayproxy: target must be host:port")
	ErrHandshake = errors.New("relayproxy: SOCKS5 handshake with the relay proxy failed")
	ErrNoAuth    = errors.New("relayproxy: relay proxy wants authentication")
)

// ParseTarget splits "host:port": host an IP literal (no zone) or a host
// name of letters, digits, '-', '_' and '.', at most 253 characters; port
// from 1 to 65535.
func ParseTarget(target string) (host string, port uint16, err error) {
	h, p, err := net.SplitHostPort(target)
	if err != nil {
		return "", 0, ErrTarget
	}
	n, err := strconv.ParseUint(p, 10, 16)
	if err != nil || n == 0 {
		return "", 0, ErrTarget
	}
	if ip, err := netip.ParseAddr(h); err == nil {
		if ip.Zone() != "" {
			return "", 0, ErrTarget
		}
		return ip.Unmap().String(), uint16(n), nil
	}
	name := strings.TrimSuffix(h, ".")
	if name == "" || len(name) > 253 || strings.Contains(h, ":") {
		return "", 0, ErrTarget
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return "", 0, ErrTarget
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return "", 0, ErrTarget
			}
		}
	}
	return name, uint16(n), nil
}

// connectRequest is the CONNECT request for host (from ParseTarget) and port.
func connectRequest(host string, port uint16) []byte {
	req := []byte{5, 1, 0}
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Is4() {
			req = append(req, 1)
		} else {
			req = append(req, 4)
		}
		req = append(req, ip.AsSlice()...)
	} else {
		req = append(req, 3, byte(len(host)))
		req = append(req, host...)
	}
	return binary.BigEndian.AppendUint16(req, port)
}

// socksConnect runs the client handshake on conn: the greeting offering no
// authentication, then CONNECT. The caller sets the deadline. A failure
// reply is a *ReplyError; anything else malformed is ErrHandshake.
func socksConnect(conn net.Conn, host string, port uint16) error {
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		return fmt.Errorf("%w: %w", ErrHandshake, err)
	}
	var choice [2]byte
	if _, err := io.ReadFull(conn, choice[:]); err != nil {
		return fmt.Errorf("%w: %w", ErrHandshake, err)
	}
	if choice[0] != 5 {
		return ErrHandshake
	}
	if choice[1] != 0 {
		return ErrNoAuth
	}
	if _, err := conn.Write(connectRequest(host, port)); err != nil {
		return fmt.Errorf("%w: %w", ErrHandshake, err)
	}
	var head [4]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return fmt.Errorf("%w: %w", ErrHandshake, err)
	}
	if head[0] != 5 {
		return ErrHandshake
	}
	if head[1] != ReplySucceeded {
		// The connection is dropped, so the rest of a failure reply is not
		// read: some proxies close without sending it.
		return &ReplyError{Code: head[1]}
	}
	if head[2] != 0 {
		return ErrHandshake
	}
	var rest int
	switch head[3] {
	case 1:
		rest = 4 + 2
	case 4:
		rest = 16 + 2
	case 3:
		var n [1]byte
		if _, err := io.ReadFull(conn, n[:]); err != nil {
			return fmt.Errorf("%w: %w", ErrHandshake, err)
		}
		if n[0] == 0 {
			return ErrHandshake
		}
		rest = int(n[0]) + 2
	default:
		return ErrHandshake
	}
	// The bound address is read and dropped: nothing here needs it.
	if _, err := io.ReadFull(conn, make([]byte, rest)); err != nil {
		return fmt.Errorf("%w: %w", ErrHandshake, err)
	}
	return nil
}
