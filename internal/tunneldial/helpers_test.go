package tunneldial

import (
	"encoding/binary"
	"net/netip"
)

// testRR is an answer record for reply: owner "" means a pointer to the
// question name.
type testRR struct {
	owner string
	rtype uint16
	class uint16
	data  []byte
}

// wireName encodes a dotted name without compression.
func wireName(name string) []byte {
	var out []byte
	if name != "" {
		start := 0
		for i := 0; i <= len(name); i++ {
			if i == len(name) || name[i] == '.' {
				out = append(out, byte(i-start))
				out = append(out, name[start:i]...)
				start = i + 1
			}
		}
	}
	return append(out, 0)
}

// reply answers the query q: its header and question, QR and RA set, rcode,
// and the records given.
func reply(q []byte, rcode uint16, rrs ...testRR) []byte {
	msg := append([]byte(nil), q...)
	binary.BigEndian.PutUint16(msg[2:], 0x8180|rcode)
	binary.BigEndian.PutUint16(msg[6:], uint16(len(rrs)))
	for _, rr := range rrs {
		if rr.owner == "" {
			msg = append(msg, 0xC0, headerLen)
		} else {
			msg = append(msg, wireName(rr.owner)...)
		}
		class := rr.class
		if class == 0 {
			class = classIN
		}
		msg = binary.BigEndian.AppendUint16(msg, rr.rtype)
		msg = binary.BigEndian.AppendUint16(msg, class)
		msg = binary.BigEndian.AppendUint32(msg, 60)
		msg = binary.BigEndian.AppendUint16(msg, uint16(len(rr.data)))
		msg = append(msg, rr.data...)
	}
	return msg
}

func aRecord(ip string) testRR {
	a := netip.MustParseAddr(ip).As4()
	return testRR{rtype: TypeA, data: a[:]}
}
