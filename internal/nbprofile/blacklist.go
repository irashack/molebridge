package nbprofile

import (
	"fmt"
	"strings"
)

// DefaultInterfaceBlacklist is NetBird 0.80.0's default list
// (client/internal/profilemanager/config.go:56-59, with
// iface.WgInterfaceDefault = "wt0" from client/iface/configurer/name.go:6).
// NetBird fills it into an empty list at config load
// (config.go:468-473, `len(config.IFaceBlackList) == 0`), so a list holding
// only the tunnel interface would suppress every one of these.
func DefaultInterfaceBlacklist() []string {
	return []string{
		"wt0", "wt", "utun", "tun0", "zt", "ZeroTier", "wg", "ts",
		"Tailscale", "tailscale", "docker", "veth", "br-", "lo",
	}
}

// repairHint names the repair tool in the refusal; the documentation
// anchor is docs/operations.md#netbird-interface-blacklist.
const repairHint = "stop the exit and run fix-blacklist (docs/operations.md#netbird-interface-blacklist)"

// NoIdentityNotice is what the exit says when it finds no stored profile: the
// first start, where NetBird enrolls a new peer.
const NoIdentityNotice = "no NetBird identity found in the state directory or the legacy profile paths; NetBird will enroll a new peer"

// BlacklistResult is the outcome of an accepted blacklist check.
type BlacklistResult struct {
	// Path is the stored profile the daemon will load, empty with NoIdentity.
	Path string
	// NoIdentity is true when no profile exists yet. That is not a refusal;
	// the exit should say plainly that it would enroll a new peer
	// (NoIdentityNotice).
	NoIdentity bool
}

// listState is what a profile's IFaceBlackList holds.
type listState struct {
	member  int      // index of the root member, -1 when absent
	entries []string // the strings, when it is an array of strings
	empty   bool     // absent, null or an empty array: NetBird fills defaults
	elems   []span   // element spans, for an array
}

type span struct{ start, end int }

// blacklistOf reads the root's IFaceBlackList. ok is false when it is
// present but not null and not an array of strings.
func blacklistOf(l loaded) (st listState, ok bool) {
	st.member = -1
	idx := l.root.lookup("ifaceblacklist")
	if len(idx) == 0 {
		st.empty = true
		return st, true
	}
	st.member = idx[0]
	m := l.root.members[idx[0]]
	switch m.kind {
	case kindNull:
		st.empty = true
		return st, true
	case kindArray:
		entries, elems, ok := stringArray(l.data, m)
		if !ok {
			return st, false
		}
		st.entries, st.elems, st.empty = entries, elems, len(entries) == 0
		return st, true
	}
	return st, false
}

// stringArray decodes the array value of m, which scan has validated, and
// reports false when an element is not a string.
func stringArray(data []byte, m member) (entries []string, elems []span, ok bool) {
	s := &scanner{data: data, pos: m.valStart + 1}
	s.skipWS()
	if s.data[s.pos] == ']' {
		return nil, nil, true
	}
	for {
		s.skipWS()
		if s.data[s.pos] != '"' {
			return nil, nil, false
		}
		start := s.pos
		str, _, err := s.str()
		if err != nil {
			return nil, nil, false
		}
		entries = append(entries, str)
		elems = append(elems, span{start, s.pos})
		s.skipWS()
		if s.data[s.pos] == ',' {
			s.pos++
			continue
		}
		return entries, elems, true
	}
}

func contains(list []string, name string) bool {
	for _, s := range list {
		if s == name {
			return true
		}
	}
	return false
}

// checkListFile applies the verdicts every reader of a profile shares
// (unreadable, malformed, a non-ASCII root field name, a repeated checked
// field) and returns the loaded file and its IFaceBlackList.
func checkListFile(path string) (loaded, listState, error) {
	l := load(path, false)
	switch l.verdict {
	case vOK:
	default:
		return l, listState{}, profileRefusal(path, profileVerdict(l, ""), "")
	}
	if l.root.hasNonPlainKey() {
		return l, listState{}, profileRefusal(path, vBadKey, "")
	}
	if len(l.root.lookup("wgiface")) > 1 || len(l.root.lookup("rosenpassenabled")) > 1 {
		return l, listState{}, profileRefusal(path, vDuplicate, "")
	}
	if len(l.root.lookup("ifaceblacklist")) > 1 {
		return l, listState{}, profileRefusal(path, vDupList, "")
	}
	st, ok := blacklistOf(l)
	if !ok {
		return l, st, refuse(fmt.Sprintf("the stored NetBird profile %s has an IFaceBlackList that is not a list of strings; %s", path, repairHint))
	}
	return l, st, nil
}

// CheckBlacklist is the D25 check, run before the NetBird daemon starts. It
// resolves the stored profile the daemon will load (the active-profile state
// must name the default profile; then the default profile, else the legacy
// file NetBird copies into it) and requires its IFaceBlackList to contain the
// tunnel interface: EXIT_IF for the native backend, gluetun's tunnel name for
// the gluetun backend. The host interface is never required: the list
// filters NetBird's connection candidates, and excluding the host interface
// would remove the direct-connection path the gluetun backend relies on.
//
// Entries are compared as exact names. NetBird itself matches by prefix
// (client/internal/stdnet/filter.go:13-35), so a shorter entry such as "wg"
// would also cover "wg0"; the check asks for the interface's own entry
// because that is what `netbird up` with NB_EXTRA_IFACE_BLACKLIST writes and
// what fix-blacklist adds.
//
// A missing entry is refused with a fixed message naming the repair tool;
// nothing from the file is printed. An absent profile is not a refusal:
// NetBird enrolls a new peer, and the result says so.
func CheckBlacklist(p Paths, tunnelIF string) (BlacklistResult, error) {
	if err := checkTunnelName(tunnelIF); err != nil {
		return BlacklistResult{}, err
	}
	if err := CheckActive(p); err != nil {
		return BlacklistResult{}, err
	}
	path, found := p.Resolve()
	if !found {
		return BlacklistResult{NoIdentity: true}, nil
	}
	_, st, err := checkListFile(path)
	if err != nil {
		return BlacklistResult{Path: path}, err
	}
	if !contains(st.entries, tunnelIF) {
		return BlacklistResult{Path: path}, refuse(fmt.Sprintf(
			"the stored NetBird profile %s does not exclude the tunnel interface %s from NetBird's connection candidates; %s",
			path, tunnelIF, repairHint))
	}
	return BlacklistResult{Path: path}, nil
}

// CheckBlacklistAfterUp is the re-read after `netbird up`: the profile must
// exist now, keep Rosenpass off and the guarded interface, and exclude the
// tunnel interface. The exit refuses to admit traffic unless it returns nil.
func CheckBlacklistAfterUp(p Paths, overlayIF, tunnelIF string) error {
	if err := CheckProfiles(p, overlayIF); err != nil {
		return err
	}
	res, err := CheckBlacklist(p, tunnelIF)
	if err != nil {
		return err
	}
	if res.NoIdentity {
		return refuse("NetBird wrote no stored profile after `netbird up`; its interface blacklist cannot be verified")
	}
	return nil
}

// describe is used by tools to print the resolved profile without content.
func (r BlacklistResult) String() string {
	if r.NoIdentity {
		return NoIdentityNotice
	}
	return "stored NetBird profile " + strings.TrimSpace(r.Path)
}
