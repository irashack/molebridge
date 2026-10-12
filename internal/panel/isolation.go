package panel

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// The panel checks its own isolation at start (plan: "Upgrade from 0.7.x"):
// no capabilities, not uid 0 unless PANEL_USER says so, and every exit state
// mount read-only except the panel directory. It cannot see what else was
// mounted into it, so credential-mount separation stays a host check
// (documented with its command in docs/operations.md).
//
// How the panel learns what PANEL_USER says: the Compose file passes it into
// the panel's environment as PANEL_USER, the same value it gives to `user:`.
// uid 0 is accepted only when that variable is present and names uid 0
// ("0", "0:0" or "0:<gid>"), which is the documented override for a rootless
// engine, where container root is the host user. A non-root PANEL_USER does
// not excuse a root process: the two must agree.

// IsolationOffEnv switches the self-check off. It exists for the Node tests
// and for running the panel by hand outside a container; the Compose file
// never sets it, and a start with it set says so on stderr.
const IsolationOffEnv = "MOLEBRIDGE_PANEL_ISOLATION_CHECK"

// The fixed refusals. Nothing from the environment or the mount table is
// repeated in them.
const (
	refuseCapabilities = "the panel must run with no capabilities (cap_drop: [ALL]); its effective capability set is not empty"
	refuseCapUnknown   = "the panel cannot read its capability set from /proc/self/status, so it cannot show it has none"
	refuseRoot         = "the panel must not run as root; set PANEL_USER to the uid:gid that owns state/panel (0:0 only on a rootless engine, and only explicitly)"
	refuseMounts       = "an exit's applier state must be mounted read-only into the panel; only its panel directory may be writable"
	refuseMountUnknown = "the panel cannot tell whether an exit's applier state is mounted read-only"
)

// MountState is what the panel could learn about one directory it must not
// be able to write.
type MountState struct {
	Label string // the exit, for the message: an exit id or "the exit"
	// Known is false when the directory could not be examined.
	Known    bool
	ReadOnly bool
}

// IsolationInputs are the facts CheckIsolation decides from.
type IsolationInputs struct {
	UID int
	// CapEff is the effective capability set; CapKnown is false when it could
	// not be read.
	CapEff    uint64
	CapKnown  bool
	PanelUser string // PANEL_USER from the environment ("" when unset)
	// Applier lists every exit's applier directory.
	Applier []MountState
}

// panelUserIsRoot reports whether PANEL_USER explicitly names uid 0.
func panelUserIsRoot(value string) bool {
	uid, _, _ := strings.Cut(strings.TrimSpace(value), ":")
	n, err := strconv.Atoi(uid)
	return err == nil && n == 0 && strings.TrimLeft(uid, "0") == ""
}

// CheckIsolation returns the fixed refusals that apply to the inputs, in a
// stable order; empty means the panel may start.
func CheckIsolation(in IsolationInputs) []string {
	var refusals []string
	switch {
	case !in.CapKnown:
		refusals = append(refusals, refuseCapUnknown)
	case in.CapEff != 0:
		refusals = append(refusals, refuseCapabilities)
	}
	if in.UID == 0 && !panelUserIsRoot(in.PanelUser) {
		refusals = append(refusals, refuseRoot)
	}
	writable, unknown := false, false
	for _, m := range in.Applier {
		switch {
		case !m.Known:
			unknown = true
		case !m.ReadOnly:
			writable = true
		}
	}
	if writable {
		refusals = append(refusals, refuseMounts)
	}
	if unknown {
		refusals = append(refusals, refuseMountUnknown)
	}
	return refusals
}

// ParseCapEff reads the CapEff line of /proc/<pid>/status.
func ParseCapEff(status io.Reader) (uint64, bool) {
	scanner := bufio.NewScanner(status)
	for scanner.Scan() {
		line := scanner.Text()
		if value, ok := strings.CutPrefix(line, "CapEff:"); ok {
			n, err := strconv.ParseUint(strings.TrimSpace(value), 16, 64)
			return n, err == nil
		}
	}
	return 0, false
}

// IsolationProbe reads the facts from the running process.
type IsolationProbe struct {
	StatusPath string                         // /proc/self/status
	UID        func() int                     // os.Getuid
	ReadOnly   func(dir string) (bool, error) // statfs-based
}

// DefaultProbe is the probe for the real process.
func DefaultProbe() IsolationProbe {
	return IsolationProbe{StatusPath: "/proc/self/status", UID: os.Getuid, ReadOnly: readOnlyMount}
}

// Gather builds the inputs for a panel with the given exits.
func (p IsolationProbe) Gather(env map[string]string, exits []Exit, stateDir string) IsolationInputs {
	in := IsolationInputs{UID: p.UID(), PanelUser: env["PANEL_USER"]}
	if f, err := os.Open(p.StatusPath); err == nil {
		in.CapEff, in.CapKnown = ParseCapEff(f)
		f.Close()
	}
	dirs := map[string]string{}
	if len(exits) == 0 {
		dirs["the exit"] = filepath.Join(stateDir, "applier")
	}
	for _, ex := range exits {
		dirs[ex.ID] = filepath.Join(stateDir, ex.ID, "applier")
	}
	for label, dir := range dirs {
		readOnly, err := p.ReadOnly(dir)
		if errors.Is(err, fs.ErrNotExist) {
			// Nothing mounted there: nothing of the exit's the panel could write.
			readOnly, err = true, nil
		}
		in.Applier = append(in.Applier, MountState{Label: label, Known: err == nil, ReadOnly: readOnly})
	}
	return in
}

// ErrIsolation is returned when the self-check refuses.
type ErrIsolation struct{ Refusals []string }

func (e *ErrIsolation) Error() string { return strings.Join(e.Refusals, "; ") }

// VerifyIsolation runs the self-check and returns an *ErrIsolation to refuse.
func VerifyIsolation(env map[string]string, exits []Exit, stateDir string, probe IsolationProbe, warn io.Writer) error {
	if env[IsolationOffEnv] == "off" {
		fmt.Fprintln(warn, "molebridge panel: the isolation self-check is switched off; do not run a deployed panel this way")
		return nil
	}
	if refusals := CheckIsolation(probe.Gather(env, exits, stateDir)); len(refusals) > 0 {
		return &ErrIsolation{Refusals: refusals}
	}
	return nil
}

var errNotDirectory = errors.New("not a directory")
