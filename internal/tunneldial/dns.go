package tunneldial

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
)

// A small, strict DNS client message codec for A and AAAA queries (RFC 1035,
// RFC 3596). Answers are untrusted: every length is checked against the
// message, compression pointers must point backwards, names are bounded, and
// the answer must carry the query's ID and question.

// DNS record types the resolver asks for.
const (
	TypeA     uint16 = 1
	TypeCNAME uint16 = 5
	TypeAAAA  uint16 = 28
	classIN   uint16 = 1
)

const (
	headerLen = 12
	// MaxMessage bounds an answer, over UDP or TCP.
	MaxMessage = 4096
	// maxAnswers bounds the answer records read from one message.
	maxAnswers = 64
	// maxCNAMEs bounds a CNAME chain.
	maxCNAMEs   = 8
	maxNameLen  = 255 // wire length, RFC 1035 2.3.4
	maxPointers = 32
)

// Message errors. They never carry any of the message.
var (
	ErrName      = errors.New("tunneldial: invalid host name")
	ErrMalformed = errors.New("tunneldial: malformed DNS answer")
	ErrMismatch  = errors.New("tunneldial: DNS answer does not match the query")
	ErrTruncated = errors.New("tunneldial: DNS answer truncated")
	ErrServFail  = errors.New("tunneldial: DNS server failure")
	ErrRefused   = errors.New("tunneldial: DNS query refused or failed")
	ErrNotFound  = errors.New("tunneldial: no such host")
	ErrNoAddress = errors.New("tunneldial: no address of the requested family")
)

// canonicalName checks a host name and returns it lowercased without a
// trailing dot: labels of 1 to 63 letters, digits, '-' or '_', not starting
// or ending with '-', at most 253 characters. IP literals are refused.
func canonicalName(host string) (string, error) {
	host = strings.TrimSuffix(host, ".")
	if host == "" || len(host) > 253 {
		return "", ErrName
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return "", ErrName
	}
	host = strings.ToLower(host)
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", ErrName
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return "", ErrName
			}
		}
	}
	return host, nil
}

// buildQuery is a query for name (canonical) and qtype with the given ID and
// recursion desired, without EDNS: a truncated answer is asked again over TCP.
func buildQuery(id uint16, name string, qtype uint16) []byte {
	msg := make([]byte, headerLen, headerLen+len(name)+6)
	binary.BigEndian.PutUint16(msg[0:], id)
	binary.BigEndian.PutUint16(msg[2:], 0x0100) // RD
	binary.BigEndian.PutUint16(msg[4:], 1)      // QDCOUNT
	for _, label := range strings.Split(name, ".") {
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, qtype)
	msg = binary.BigEndian.AppendUint16(msg, classIN)
	return msg
}

// readName decodes the name at off, returning it lowercased and dotted (""
// for the root) and the offset after it in the message. Pointers must point
// strictly before the label they replace, so decoding always ends.
func readName(msg []byte, off int) (string, int, error) {
	var b strings.Builder
	end := -1
	wire := 0
	pointers := 0
	for {
		if off >= len(msg) {
			return "", 0, ErrMalformed
		}
		c := int(msg[off])
		switch {
		case c == 0:
			if end < 0 {
				end = off + 1
			}
			return b.String(), end, nil
		case c&0xC0 == 0xC0:
			if off+1 >= len(msg) {
				return "", 0, ErrMalformed
			}
			target := (c&0x3F)<<8 | int(msg[off+1])
			pointers++
			if target >= off || pointers > maxPointers {
				return "", 0, ErrMalformed
			}
			if end < 0 {
				end = off + 2
			}
			off = target
		case c&0xC0 != 0:
			return "", 0, ErrMalformed // the reserved label types
		default:
			if off+1+c > len(msg) {
				return "", 0, ErrMalformed
			}
			wire += c + 1
			if wire+1 > maxNameLen {
				return "", 0, ErrMalformed
			}
			if b.Len() > 0 {
				b.WriteByte('.')
			}
			for _, ch := range msg[off+1 : off+1+c] {
				if ch <= ' ' || ch >= 0x7f || ch == '.' {
					return "", 0, ErrMalformed
				}
				if ch >= 'A' && ch <= 'Z' {
					ch += 'a' - 'A'
				}
				b.WriteByte(ch)
			}
			off += 1 + c
		}
	}
}

// parseAnswer reads the addresses of type qtype for name in an answer to the
// query with this ID, following CNAMEs within the answer section. A truncated
// answer is ErrTruncated, so the caller can ask over TCP.
func parseAnswer(msg []byte, id uint16, name string, qtype uint16) ([]netip.Addr, error) {
	if len(msg) < headerLen || len(msg) > MaxMessage {
		return nil, ErrMalformed
	}
	if binary.BigEndian.Uint16(msg[0:]) != id {
		return nil, ErrMismatch
	}
	flags := binary.BigEndian.Uint16(msg[2:])
	if flags&0x8000 == 0 || flags>>11&0xF != 0 {
		return nil, ErrMismatch // not a response, or another opcode
	}
	if flags&0x0200 != 0 {
		return nil, ErrTruncated
	}
	qd := binary.BigEndian.Uint16(msg[4:])
	an := int(binary.BigEndian.Uint16(msg[6:]))
	if qd != 1 {
		return nil, ErrMismatch
	}
	qname, off, err := readName(msg, headerLen)
	if err != nil {
		return nil, err
	}
	if off+4 > len(msg) {
		return nil, ErrMalformed
	}
	if qname != name || binary.BigEndian.Uint16(msg[off:]) != qtype || binary.BigEndian.Uint16(msg[off+2:]) != classIN {
		return nil, ErrMismatch
	}
	off += 4
	switch flags & 0xF {
	case 0:
	case 2:
		return nil, ErrServFail
	case 3:
		return nil, ErrNotFound
	default:
		return nil, ErrRefused
	}
	if an > maxAnswers {
		return nil, ErrMalformed
	}
	cnames := map[string]string{}
	addrs := map[string][]netip.Addr{}
	for i := 0; i < an; i++ {
		owner, next, err := readName(msg, off)
		if err != nil {
			return nil, err
		}
		off = next
		if off+10 > len(msg) {
			return nil, ErrMalformed
		}
		rtype := binary.BigEndian.Uint16(msg[off:])
		class := binary.BigEndian.Uint16(msg[off+2:])
		rdlen := int(binary.BigEndian.Uint16(msg[off+8:]))
		off += 10
		if off+rdlen > len(msg) {
			return nil, ErrMalformed
		}
		rdata := msg[off : off+rdlen]
		if class == classIN {
			switch rtype {
			case TypeCNAME:
				target, end, err := readName(msg, off)
				if err != nil || end != off+rdlen || target == "" {
					return nil, ErrMalformed
				}
				if _, dup := cnames[owner]; dup {
					return nil, ErrMalformed
				}
				cnames[owner] = target
			case qtype:
				if rtype == TypeA && rdlen != 4 || rtype == TypeAAAA && rdlen != 16 {
					return nil, ErrMalformed
				}
				ip, _ := netip.AddrFromSlice(rdata)
				addrs[owner] = append(addrs[owner], ip)
			}
		}
		off += rdlen
	}
	target := name
	for hops := 0; ; hops++ {
		if found := addrs[target]; len(found) > 0 {
			return found, nil
		}
		next, ok := cnames[target]
		if !ok {
			return nil, ErrNoAddress
		}
		if hops >= maxCNAMEs {
			return nil, ErrMalformed
		}
		target = next
	}
}
