package nbprofile

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// FixOptions injects the system calls fix-blacklist makes, for tests. The
// zero value uses the real ones.
type FixOptions struct {
	// Fchown sets a file's owner and group. Default: (*os.File).Chown.
	Fchown func(f *os.File, uid, gid int) error
	// Owner reports a file's owner and group. Default: the Stat_t behind
	// os.FileInfo. ok is false when it cannot be read.
	Owner func(fi fs.FileInfo) (uid, gid int, ok bool)
	// SocketAnswers reports whether something answers on the daemon socket.
	// Default: connect to the unix socket.
	SocketAnswers func(path string) bool

	// beforeRename runs after the replacement is complete, for tests.
	beforeRename func()
}

// FixResult says what FixBlacklist did.
type FixResult struct {
	// Path is the profile it examined.
	Path string
	// Changed is false when the tunnel interface was already excluded and
	// nothing was written.
	Changed bool
}

func ownerOf(fi fs.FileInfo) (int, int, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true
}

func socketAnswers(path string) bool {
	conn, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func fixErr(format string, args ...any) error {
	return errors.New("fix-blacklist: " + fmt.Sprintf(format, args...))
}

// daemonVisible reports whether a NetBird daemon can be seen from here: its
// socket answers, or a process named netbird exists. This is best effort and
// cannot prove the daemon is stopped: the repair container has its own
// filesystem and process table, so a daemon in the exit's container is
// invisible to it. The operator stops the exit first (operations.md).
func daemonVisible(p Paths, o FixOptions) (string, bool) {
	if p.Socket != "" && o.SocketAnswers(p.Socket) {
		return "the NetBird daemon socket " + p.Socket + " answers", true
	}
	if p.ProcDir == "" {
		return "", false
	}
	entries, err := os.ReadDir(p.ProcDir)
	if err != nil {
		return "", false
	}
	self := strconv.Itoa(os.Getpid())
	for _, e := range entries {
		name := e.Name()
		if name == self || name == "" || name[0] < '0' || name[0] > '9' {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(p.ProcDir, name, "cmdline"))
		if err != nil {
			continue
		}
		argv0, _, _ := bytes.Cut(raw, []byte{0})
		if filepath.Base(string(argv0)) == "netbird" {
			return "a NetBird process (pid " + name + ") is running", true
		}
	}
	return "", false
}

// FixBlacklist is the operator's repair tool (D25): it adds the tunnel
// interface to the IFaceBlackList of the stored profile the daemon will load,
// and changes nothing else.
//
// It refuses, changing nothing, when the daemon is visible (see
// daemonVisible for the limit), when the active profile is not the default,
// when no identity exists (it never creates one), when the file is not one
// valid, unambiguous JSON object (a repeated key at any depth, a
// case-variant repeat of a checked field, a root field name outside printable
// ASCII), when IFaceBlackList is not a list of strings, and when it cannot
// give the replacement the original's mode, owner and group.
//
// When the list is absent, null or empty it first reproduces NetBird's
// default filling (DefaultInterfaceBlacklist): NetBird fills the defaults
// only into an empty list, so a bare append would suppress them. Existing
// entries are kept. Every byte outside the one edited span is preserved: the
// raw text is spliced, not re-encoded.
//
// The replacement is a temporary file in the same directory, owned and moded
// like the original before any content is written, fsynced, renamed over the
// original, with the directory fsynced. Extended attributes, ACLs and
// security labels are not copied.
func FixBlacklist(p Paths, tunnelIF string) (FixResult, error) {
	return FixBlacklistWith(p, tunnelIF, FixOptions{})
}

// FixBlacklistWith is FixBlacklist with injected system calls.
func FixBlacklistWith(p Paths, tunnelIF string, o FixOptions) (FixResult, error) {
	if o.Fchown == nil {
		o.Fchown = func(f *os.File, uid, gid int) error { return f.Chown(uid, gid) }
	}
	if o.Owner == nil {
		o.Owner = ownerOf
	}
	if o.SocketAnswers == nil {
		o.SocketAnswers = socketAnswers
	}
	if err := checkTunnelName(tunnelIF); err != nil {
		return FixResult{}, err
	}
	if why, seen := daemonVisible(p, o); seen {
		return FixResult{}, fixErr("%s; stop the exit first", why)
	}
	if err := CheckActive(p); err != nil {
		return FixResult{}, err
	}
	path, found := p.Resolve()
	if !found {
		return FixResult{}, fixErr("no NetBird identity found; refusing to create one (the stored profile is created when NetBird enrolls)")
	}
	res := FixResult{Path: path}
	l := load(path, true)
	switch l.verdict {
	case vOK:
	case vUnreadable:
		return res, fixErr("cannot read the stored NetBird profile %s as a regular file", path)
	case vDuplicate:
		return res, fixErr("the stored NetBird profile %s repeats a key within one object", path)
	default:
		return res, fixErr("the stored NetBird profile %s is not a valid JSON object", path)
	}
	if l.root.hasNonPlainKey() {
		return res, fixErr("the stored NetBird profile %s has a field name outside printable ASCII", path)
	}
	for _, name := range []string{"ifaceblacklist", "wgiface", "rosenpassenabled"} {
		if len(l.root.lookup(name)) > 1 {
			return res, fixErr("the stored NetBird profile %s repeats a field in another case", path)
		}
	}
	st, ok := blacklistOf(l)
	if !ok {
		return res, fixErr("the stored NetBird profile %s has an IFaceBlackList that is not a list of strings", path)
	}
	if contains(st.entries, tunnelIF) {
		return res, nil
	}
	out, err := spliceBlacklist(l, st, tunnelIF)
	if err != nil {
		return res, err
	}
	if err := replaceFile(path, l, out, o); err != nil {
		return res, err
	}
	res.Changed = true
	return res, nil
}

// spliceBlacklist returns the profile text with the tunnel interface added to
// IFaceBlackList. Only one span of l.data is replaced or inserted into.
func spliceBlacklist(l loaded, st listState, tunnel string) ([]byte, error) {
	data, root := l.data, l.root
	unit, sep := styleOf(data, root)
	var start, end int
	var repl string

	switch {
	case st.member >= 0 && len(st.entries) > 0:
		// A populated list: keep it and append after the last element,
		// repeating the whitespace that precedes it.
		last := st.elems[len(st.elems)-1]
		lead := leadBefore(data, last.start)
		if lead == "" && len(st.elems) == 1 {
			lead = sep
		}
		start, end, repl = last.end, last.end, ","+lead+quote(tunnel)
	case st.member >= 0:
		// Null or empty: NetBird would fill its defaults, so write them.
		m := root.members[st.member]
		lead := leadBefore(data, m.keyStart)
		start, end = m.valStart, m.valEnd
		repl = arrayText(withTunnel(DefaultInterfaceBlacklist(), tunnel), lead, unit, sep)
	case len(root.members) > 0:
		last := root.members[len(root.members)-1]
		lead := leadBefore(data, last.keyStart)
		colon := string(data[last.keyEnd:last.valStart])
		start, end = last.valEnd, last.valEnd
		repl = "," + lead + quote("IFaceBlackList") + colon +
			arrayText(withTunnel(DefaultInterfaceBlacklist(), tunnel), lead, unit, sep)
	default:
		// An empty root object.
		inner := string(data[root.open+1 : root.close])
		lead := ""
		if strings.Contains(inner, "\n") {
			lead = "\n" + unit
			if strings.Contains(inner, "\r\n") {
				lead = "\r\n" + unit
			}
		}
		start, end = root.open+1, root.open+1
		repl = lead + quote("IFaceBlackList") + ":" + sep +
			arrayText(withTunnel(DefaultInterfaceBlacklist(), tunnel), lead, unit, sep)
	}

	out := make([]byte, 0, len(data)+len(repl))
	out = append(out, data[:start]...)
	out = append(out, repl...)
	out = append(out, data[end:]...)

	// Check the result before anything is written: still one valid,
	// unambiguous object, with the entry in place and the old entries kept.
	again, err := scan(out, true)
	if err != nil {
		return nil, fixErr("internal error: the edited profile would not be valid JSON")
	}
	chk, ok := blacklistOf(loaded{data: out, root: again})
	if !ok || !contains(chk.entries, tunnel) || len(again.members) < len(root.members) {
		return nil, fixErr("internal error: the edited profile would not hold the entry")
	}
	for _, old := range st.entries {
		if !contains(chk.entries, old) {
			return nil, fixErr("internal error: the edited profile would lose an entry")
		}
	}
	return out, nil
}

func withTunnel(list []string, tunnel string) []string {
	if !contains(list, tunnel) {
		list = append(list, tunnel)
	}
	return list
}

func quote(s string) string { return `"` + s + `"` }

// leadBefore returns the run of JSON whitespace that ends at pos.
func leadBefore(data []byte, pos int) string {
	i := pos
	for i > 0 {
		switch data[i-1] {
		case ' ', '\t', '\n', '\r':
			i--
			continue
		}
		break
	}
	return string(data[i:pos])
}

// styleOf finds the file's indentation unit (the whitespace before its first
// root member, when that starts a line) and whether it puts a space after a
// colon. NetBird writes profiles with MarshalIndent.
func styleOf(data []byte, root *rootInfo) (unit, sep string) {
	unit, sep = "    ", " "
	if len(root.members) == 0 {
		return unit, sep
	}
	first := root.members[0]
	if lead := leadBefore(data, first.keyStart); strings.Contains(lead, "\n") {
		if ind := lead[strings.LastIndexByte(lead, '\n')+1:]; ind != "" {
			unit = ind
		}
	}
	if colon := string(data[first.keyEnd:first.valStart]); !strings.ContainsAny(colon, " \t\n") {
		sep = ""
	}
	return unit, sep
}

// arrayText renders a string array. When lead (the whitespace before the key
// that owns the array) has a line break, the array goes one element per line,
// indented one unit deeper than the key; otherwise it stays on one line.
func arrayText(elems []string, lead, unit, sep string) string {
	q := make([]string, len(elems))
	for i, e := range elems {
		q[i] = quote(e)
	}
	idx := strings.LastIndexByte(lead, '\n')
	if idx < 0 {
		return "[" + strings.Join(q, ","+sep) + "]"
	}
	nl := "\n"
	if idx > 0 && lead[idx-1] == '\r' {
		nl = "\r\n"
	}
	indent := lead[idx+1:]
	return "[" + nl + indent + unit + strings.Join(q, ","+nl+indent+unit) + nl + indent + "]"
}

// replaceFile atomically replaces path, whose current state is l, with
// content, giving the replacement the same mode, owner and group. Nothing is
// written to the replacement until its ownership and mode are confirmed, and
// the original is untouched until the final rename.
func replaceFile(path string, l loaded, content []byte, o FixOptions) (err error) {
	uid, gid, ok := o.Owner(l.info)
	if !ok {
		return fixErr("cannot read the owner of %s", path)
	}
	const modeBits = os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky
	mode := l.info.Mode() & modeBits

	var token [6]byte
	if _, err := rand.Read(token[:]); err != nil {
		return fixErr("no random source for a temporary name")
	}
	dir, base := filepath.Split(path)
	tmp := filepath.Join(dir, "."+base+".fix-blacklist-"+hex.EncodeToString(token[:]))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fixErr("cannot create a replacement beside %s: %v", path, err)
	}
	renamed := false
	defer func() {
		if !renamed {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()

	if err := o.Fchown(f, uid, gid); err != nil {
		return fixErr("cannot give the replacement the owner and group of %s (%v); nothing was changed. Run the tool as the profile's owner", path, err)
	}
	if err := f.Chmod(mode); err != nil {
		return fixErr("cannot give the replacement the mode of %s (%v); nothing was changed", path, err)
	}
	fi, err := f.Stat()
	if err != nil {
		return fixErr("cannot inspect the replacement: %v", err)
	}
	nu, ng, ok := o.Owner(fi)
	if !ok || nu != uid || ng != gid || fi.Mode()&modeBits != mode {
		return fixErr("the replacement for %s does not have the original's owner, group and mode; nothing was changed", path)
	}
	if _, err := f.Write(content); err != nil {
		return fixErr("cannot write the replacement: %v", err)
	}
	if err := f.Sync(); err != nil {
		return fixErr("cannot sync the replacement: %v", err)
	}
	if err := f.Close(); err != nil {
		return fixErr("cannot close the replacement: %v", err)
	}
	if o.beforeRename != nil {
		o.beforeRename()
	}
	// The original must be the file that was read.
	now, err := os.Lstat(path)
	if err != nil || !os.SameFile(now, l.info) || now.Size() != l.info.Size() || !now.ModTime().Equal(l.info.ModTime()) {
		return fixErr("%s changed while it was being edited; nothing was changed", path)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fixErr("cannot replace %s: %v", path, err)
	}
	renamed = true
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fixErr("replaced %s but cannot open its directory to sync it: %v", path, err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fixErr("replaced %s but cannot sync its directory: %v", path, err)
	}
	return nil
}
