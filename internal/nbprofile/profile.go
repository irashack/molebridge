package nbprofile

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"syscall"
)

// maxFileSize bounds every file read here. A profile is a few kilobytes; the
// awk reader refused anything over 1 MiB as malformed.
const maxFileSize = 1 << 20

// Default locations. NetBird's daemon keeps profiles under NB_STATE_DIR
// (default /var/lib/netbird, profilemanager/service.go:65-87) and copies a
// legacy default profile in when its own is absent
// (service.go:142-172); the CLI first migrates /etc/wiretrustee to
// /etc/netbird (client/cmd/root.go:128-148,343-350).
const (
	DefaultStateDir = "/var/lib/netbird"
	// DefaultSocket is the daemon's gRPC socket (client/cmd/root.go, the
	// default daemon address).
	DefaultSocket = "/var/run/netbird.sock"
)

// Paths names the files the daemon reads at start. Tests inject their own.
type Paths struct {
	// StateDir holds default.json and active_profile.json.
	StateDir string
	// Legacy lists the profiles NetBird copies into the default profile when
	// that is absent, in the order it considers them.
	Legacy []string
	// Socket is the daemon socket; ProcDir is where process command lines are
	// read from. Only fix-blacklist uses them.
	Socket  string
	ProcDir string
}

// DefaultPaths returns the production locations for a state directory
// (NB_STATE_DIR; empty means /var/lib/netbird).
func DefaultPaths(stateDir string) Paths {
	if stateDir == "" {
		stateDir = DefaultStateDir
	}
	return Paths{
		StateDir: stateDir,
		Legacy:   []string{"/etc/netbird/config.json", "/etc/wiretrustee/config.json"},
		Socket:   DefaultSocket,
		ProcDir:  "/proc",
	}
}

func (p Paths) activeState() string    { return p.StateDir + "/active_profile.json" }
func (p Paths) defaultProfile() string { return p.StateDir + "/default.json" }

// profileFiles lists the files the gate checked, in its order.
func (p Paths) profileFiles() []string {
	return append([]string{p.defaultProfile()}, p.Legacy...)
}

// Resolve returns the stored profile the daemon will load: the default
// profile if it exists, else the legacy file it would copy in. found is false
// when none exists: the first start, where NetBird enrolls a new peer.
func (p Paths) Resolve() (path string, found bool) {
	for _, f := range p.profileFiles() {
		if exists(f) {
			return f, true
		}
	}
	return "", false
}

// exists is the gate's `[ -e f ] || [ -L f ]`, except that a stat failure
// other than "not there" counts as present: the read then fails and the
// profile is refused as unreadable instead of being skipped.
func exists(path string) bool {
	_, err := os.Lstat(path)
	if err == nil {
		return true
	}
	return !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, syscall.ENOTDIR)
}

type verdict string

const (
	vOK        verdict = "ok"
	vMalformed verdict = "malformed"
	vBadKey    verdict = "badkey"
	vDuplicate verdict = "duplicate"
	vRosenpass verdict = "rosenpass"
	vInterface verdict = "interface"
	vOther     verdict = "other"
	// vUnreadable is a file that could not be read as a regular file.
	vUnreadable verdict = "unreadable"
	// vDupList is a repeated IFaceBlackList; the awk reader did not know it.
	vDupList verdict = "duplicate-list"
)

// loaded is one file read and scanned.
type loaded struct {
	data    []byte
	root    *rootInfo
	info    fs.FileInfo
	verdict verdict // vOK, vMalformed, vUnreadable or vDuplicate (deep, with dupAny)
}

// readBounded reads path as a regular file of at most maxFileSize bytes. The
// gate used `[ -r ]` and followed symlinks; this refuses them (O_NOFOLLOW),
// because the file is the peer's identity and a link could redirect a later
// rewrite. A file over the bound is reported with tooLarge.
func readBounded(path string) (data []byte, info fs.FileInfo, tooLarge bool, err error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, false, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err = f.Stat()
	if err != nil {
		return nil, nil, false, err
	}
	if !info.Mode().IsRegular() {
		return nil, nil, false, fmt.Errorf("not a regular file")
	}
	data, err = io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return nil, nil, false, err
	}
	if len(data) > maxFileSize {
		return nil, info, true, nil
	}
	return data, info, false, nil
}

// load reads and scans one file. dupAny also reports exact repeated keys at
// any depth (fix-blacklist).
func load(path string, dupAny bool) loaded {
	data, info, tooLarge, err := readBounded(path)
	if err != nil {
		return loaded{verdict: vUnreadable}
	}
	if tooLarge {
		return loaded{info: info, verdict: vMalformed}
	}
	root, err := scan(data, dupAny)
	switch {
	case errors.Is(err, errDuplicateDeep):
		return loaded{data: data, root: root, info: info, verdict: vDuplicate}
	case err != nil:
		return loaded{data: data, info: info, verdict: vMalformed}
	}
	return loaded{data: data, root: root, info: info, verdict: vOK}
}

// profileVerdict is the awk reader's "profile" mode, in its order: a file
// that is not one valid JSON object, a root field name outside printable
// ASCII, a checked field repeated in any case, Rosenpass present and not
// false, an interface other than the guarded one. Absent or empty WgIface
// means wt0 (profilemanager/config.go:397-405, iface/configurer/name.go:6).
func profileVerdict(l loaded, overlayIF string) verdict {
	if l.verdict != vOK && l.verdict != vDuplicate {
		return l.verdict
	}
	if l.root.hasNonPlainKey() {
		return vBadKey
	}
	wg, rosen := l.root.lookup("wgiface"), l.root.lookup("rosenpassenabled")
	if l.verdict == vDuplicate || len(wg) > 1 || len(rosen) > 1 {
		return vDuplicate
	}
	if len(rosen) == 1 && l.root.members[rosen[0]].kind != kindFalse {
		return vRosenpass
	}
	value := "wt0"
	if len(wg) == 1 {
		m := l.root.members[wg[0]]
		if m.kind != kindString || !m.strPlain {
			return vInterface
		}
		if m.str != "" {
			value = m.str
		}
	}
	if value != overlayIF {
		return vInterface
	}
	return vOK
}

// activeVerdict is the reader's "active" mode: the active-profile state must
// name the default profile, by an absent or empty name or "default" (the
// field is matched without regard to case, like the daemon's `json:"name"`).
func activeVerdict(l loaded) verdict {
	if l.verdict != vOK {
		return l.verdict
	}
	if l.root.hasNonPlainKey() {
		return vBadKey
	}
	name := l.root.lookup("name")
	if len(name) > 1 {
		return vDuplicate
	}
	if len(name) == 1 {
		m := l.root.members[name[0]]
		if m.kind != kindString || !m.strPlain {
			return vOther
		}
		if m.str != "" && m.str != "default" {
			return vOther
		}
	}
	return vOK
}

// CheckActive refuses an active-profile state that names another profile. An
// absent file means the default profile (service.go:212-243). Nothing from
// the file is printed.
func CheckActive(p Paths) error {
	path := p.activeState()
	if !exists(path) {
		return nil
	}
	switch activeVerdict(load(path, false)) {
	case vOK:
		return nil
	case vOther:
		return refuse(fmt.Sprintf("the active NetBird profile is not the default profile (%s)", path))
	case vUnreadable:
		return refuse(fmt.Sprintf("cannot read the active NetBird profile state %s", path))
	}
	return refuse(fmt.Sprintf("the active NetBird profile state %s is not a valid JSON object", path))
}

// CheckProfiles is the gate's stored-profile check: the active-profile state,
// then the default profile and the legacy files NetBird copies into it, each
// that exists. A profile must keep Rosenpass off and name the guarded
// interface. Nothing from the files is printed: profiles also hold the
// peer's private key.
func CheckProfiles(p Paths, overlayIF string) error {
	if err := CheckActive(p); err != nil {
		return err
	}
	for _, file := range p.profileFiles() {
		if !exists(file) {
			continue
		}
		if err := profileRefusal(file, profileVerdict(load(file, false), overlayIF), overlayIF); err != nil {
			return err
		}
	}
	return nil
}

func profileRefusal(file string, v verdict, overlayIF string) error {
	switch v {
	case vOK:
		return nil
	case vRosenpass:
		return refuse("Rosenpass is enabled in a stored NetBird profile (RosenpassEnabled)")
	case vInterface:
		return refuse(fmt.Sprintf("a stored NetBird profile (%s) uses a WireGuard interface other than %s (WgIface)", file, overlayIF))
	case vDuplicate:
		return refuse(fmt.Sprintf("the stored NetBird profile %s repeats WgIface or RosenpassEnabled", file))
	case vDupList:
		return refuse(fmt.Sprintf("the stored NetBird profile %s repeats IFaceBlackList", file))
	case vBadKey:
		return refuse(fmt.Sprintf("the stored NetBird profile %s has a field name outside printable ASCII", file))
	case vUnreadable:
		return refuse(fmt.Sprintf("cannot read the stored NetBird profile %s", file))
	}
	return refuse(fmt.Sprintf("the stored NetBird profile %s is not a valid JSON object", file))
}
