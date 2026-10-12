package contract

import (
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// OwnerExpiry is how long a native exit's owner record counts, in seconds of
// the boot clock.
const OwnerExpiry = 6

// OwnerRecord is the legacy native-exit owner record (D24): one line,
// rewritten every 2 seconds, read by the 0.7.0 applier and NetBird's gate:
//
//	molebridge-exit 1 <boot id> <boot-clock seconds> <namespace> <generation>
//	  <IPv4 address|-> <IPv6 address|-> <conf|applier> <repairs> <last repair|->
//
// The addresses are the tunnel config's, canonical; "applier" means the
// config has none and the applier owns rules 94 and 98.
type OwnerRecord struct {
	Boot       string
	Stamp      uint64
	NetNS      string
	Generation string
	Addr4      netip.Addr
	Addr6      netip.Addr
	// Rule94 is "conf" or "applier".
	Rule94 string
	// Repairs counts repairs; LastRepair is the boot-clock second of the last
	// one, HasLastRepair false for "-".
	Repairs       uint64
	LastRepair    uint64
	HasLastRepair bool
}

func isHexDash(s string, max int) bool {
	if s == "" || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c == '-') {
			return false
		}
	}
	return true
}

func parseUint12(s string) (uint64, bool) {
	if !isUint(s) || len(s) > 12 {
		return 0, false
	}
	n, err := strconv.ParseUint(s, 10, 64)
	return n, err == nil
}

func validNetNS(s string) bool {
	left, right, ok := strings.Cut(s, ":")
	if !ok {
		return false
	}
	return isUint(left) && len(left) <= 20 && isUint(right) && len(right) <= 20
}

// Canonical6 renders an IPv6 address as iproute2 and RFC 5952 do: lowercase,
// no leading zeroes, the leftmost longest run of two or more zero groups
// written ::. (netip would print an IPv4-mapped address in dotted form.)
func Canonical6(a netip.Addr) string {
	b := a.As16()
	var g [8]uint16
	for i := range g {
		g[i] = uint16(b[2*i])<<8 | uint16(b[2*i+1])
	}
	best, bestLen := -1, 0
	for i := 0; i < 8; {
		if g[i] != 0 {
			i++
			continue
		}
		j := i
		for j < 8 && g[j] == 0 {
			j++
		}
		if j-i > bestLen {
			best, bestLen = i, j-i
		}
		i = j
	}
	var sb strings.Builder
	if bestLen < 2 {
		best = -1
	}
	for i := 0; i < 8; i++ {
		if i == best {
			sb.WriteString("::")
			i += bestLen - 1
			continue
		}
		if sb.Len() > 0 && !strings.HasSuffix(sb.String(), ":") {
			sb.WriteByte(':')
		}
		sb.WriteString(strconv.FormatUint(uint64(g[i]), 16))
	}
	return sb.String()
}

func canonicalAddr(a netip.Addr) string {
	if a.Is4() {
		return a.String()
	}
	return Canonical6(a)
}

// ParseOwnerRecord parses the exact shape the exit writes, or reports false.
func ParseOwnerRecord(text string) (OwnerRecord, bool) {
	var rec OwnerRecord
	if len(text) > 513 || !strings.HasSuffix(text, "\n") || strings.Count(text, "\n") != 1 {
		return rec, false
	}
	parts := strings.Split(text[:len(text)-1], " ")
	if len(parts) != 11 || parts[0] != "molebridge-exit" || parts[1] != "1" {
		return rec, false
	}
	boot, stamp, netns, generation := parts[2], parts[3], parts[4], parts[5]
	addr4, addr6, rule94, repairs, last := parts[6], parts[7], parts[8], parts[9], parts[10]
	if !isHexDash(boot, 64) || !validNetNS(netns) || !isHexDash(generation, 64) || (rule94 != "conf" && rule94 != "applier") {
		return rec, false
	}
	var ok bool
	if rec.Stamp, ok = parseUint12(stamp); !ok {
		return rec, false
	}
	if rec.Repairs, ok = parseUint12(repairs); !ok {
		return rec, false
	}
	if last != "-" {
		if rec.LastRepair, ok = parseUint12(last); !ok {
			return rec, false
		}
		rec.HasLastRepair = true
	}
	for _, slot := range []struct {
		value string
		is4   bool
	}{{addr4, true}, {addr6, false}} {
		if slot.value == "-" {
			continue
		}
		a, err := netip.ParseAddr(slot.value)
		if err != nil || a.Is4() != slot.is4 || a.Is4In6() || a.Zone() != "" || canonicalAddr(a) != slot.value {
			return rec, false
		}
		if slot.is4 {
			rec.Addr4 = a
		} else {
			rec.Addr6 = a
		}
	}
	if rule94 == "applier" && (rec.Addr4.IsValid() || rec.Addr6.IsValid()) {
		return rec, false
	}
	rec.Boot, rec.NetNS, rec.Generation, rec.Rule94 = boot, netns, generation, rule94
	return rec, true
}

// Format renders the record as the line the exit writes, newline included.
func (r OwnerRecord) Format() string {
	a4, a6, last := "-", "-", "-"
	if r.Addr4.IsValid() {
		a4 = canonicalAddr(r.Addr4)
	}
	if r.Addr6.IsValid() {
		a6 = canonicalAddr(r.Addr6)
	}
	if r.HasLastRepair {
		last = strconv.FormatUint(r.LastRepair, 10)
	}
	return fmt.Sprintf("molebridge-exit 1 %s %d %s %s %s %s %s %d %s\n", r.Boot, r.Stamp, r.NetNS, r.Generation,
		a4, a6, r.Rule94, r.Repairs, last)
}

// OwnerSeen is the generation and stamp of the last record a reader accepted.
type OwnerSeen struct {
	Generation string
	Stamp      uint64
}

// OwnerValid is owner_record_valid: the record is a live owner's for this
// boot and network namespace — written at most OwnerExpiry seconds before now
// (whole seconds of the boot clock), at most a second in the future, and,
// within the generation of seen, not older than it.
func OwnerValid(rec OwnerRecord, ok bool, boot string, now uint64, netns string, seen *OwnerSeen) bool {
	if !ok || rec.Boot != boot || rec.NetNS != netns {
		return false
	}
	if rec.Stamp > now+1 || (now >= rec.Stamp && now-rec.Stamp > OwnerExpiry) {
		return false
	}
	if seen != nil && seen.Generation == rec.Generation && rec.Stamp < seen.Stamp {
		return false
	}
	return true
}

// NetNSIdentity returns "<device>:<inode>" of the network namespace object at
// path (the /proc/self/ns/net link is followed): two processes in the same
// namespace read the same value whatever their mount or user namespace.
func NetNSIdentity(path string) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("cannot read the namespace identity of %s", path)
	}
	return fmt.Sprintf("%d:%d", uint64(st.Dev), uint64(st.Ino)), nil
}
