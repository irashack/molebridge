package proxy

import (
	"errors"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/irashack/molebridge/internal/jsonfile"
	"github.com/irashack/molebridge/internal/state"
	"github.com/irashack/molebridge/internal/validate"
	"github.com/irashack/molebridge/internal/verdict"
)

// TunnelState is the exit's verdict as the proxy last read it.
type TunnelState struct {
	Verdict   string // the exit's verdict state: "ok", "failed", "unknown", "applying", ...
	Server    string // the exit's server when its record names one, else ""
	CheckedAt string // the record's checked_at when valid, else ""
	// Unreadable says why result.json could not be read (which file, and
	// the reason: permission denied, missing, too large), "" when it was
	// read. The verdict is then "unknown".
	Unreadable string
}

// resultMaxBytes is the bound every reader of result.json uses
// (applier.ResultMaxBytes).
const resultMaxBytes = 16384

// TunnelFromResult judges the exit's status record (result.json, decoded)
// as `molebridge status` does: verdict.Assess for the exit's provider and
// kind, against the configured lock the record states, if any. The proxy
// has no panel request to hold the record to (it never reads
// panel/desired.json), so a switch the panel asked for and the exit has not
// yet acknowledged does not hold it back; the exit's own record does.
//
// An empty exit.Kind takes the kind the record states, when it is one of
// verdict.Kinds (else "overlay"): the proxy joins an overlay exit or a native
// sidecar alike, and the record is the exit's own, mounted read-only from its
// applier directory. Provider and backend are still held to exit.Provider.
func TunnelFromResult(exit verdict.ExitConfig, result any, now time.Time) TunnelState {
	if exit.Kind == "" {
		exit.Kind = "overlay"
		if record, ok := result.(map[string]any); ok {
			if kind, ok := record["kind"].(string); ok && slices.Contains(verdict.Kinds, kind) {
				exit.Kind = kind
			}
		}
	}
	v := verdict.Assess(exit, result, verdict.TargetForPanel(result, nil, exit.Provider), now)
	t := TunnelState{Verdict: v.State}
	if record, ok := result.(map[string]any); ok {
		if server, ok := record["server"].(string); ok && state.ValidServerName(server, exit.Provider) {
			t.Server = server
		}
		if _, ok := validate.ParseTime(record["checked_at"]); ok {
			t.CheckedAt = record["checked_at"].(string)
		}
	}
	return t
}

// unreadable is TunnelState.Unreadable for path and the error reading it:
// "can't read <path>: permission denied". A permission error adds what
// usually causes it on Kubernetes, where the exit's state directory is
// root's: the exit's STATE_GID.
func unreadable(path string, err error) string {
	var pe *os.PathError
	if errors.As(err, &pe) {
		err = pe.Err
	}
	text := "can't read " + path + ": " + err.Error()
	if errors.Is(err, os.ErrPermission) {
		text += " (run the proxy in the exit's STATE_GID group; docs/proxy.md)"
	}
	return text
}

// resultGateEvery is how often ResultGate reads result.json again.
const resultGateEvery = time.Second

// ResultGate is a Config.Tunnel that reads the exit's result.json at path
// (state/applier/result.json, mounted read-only) at most once a second and
// judges it with TunnelFromResult. A nil now is time.Now.
func ResultGate(path string, exit verdict.ExitConfig, now func() time.Time) func() TunnelState {
	if now == nil {
		now = time.Now
	}
	var (
		mu     sync.Mutex
		last   TunnelState
		readAt time.Time
	)
	return func() TunnelState {
		mu.Lock()
		defer mu.Unlock()
		t := now()
		if readAt.IsZero() || t.Sub(readAt) >= resultGateEvery || t.Before(readAt) {
			raw, err := jsonfile.ReadBytesErr(path, resultMaxBytes)
			if err != nil {
				last = TunnelFromResult(exit, nil, t)
				last.Unreadable = unreadable(path, err)
			} else {
				// A document that doesn't decode is judged as no record,
				// as jsonfile.Read gives it.
				result, _ := validate.DecodeJSON(raw)
				last = TunnelFromResult(exit, result, t)
			}
			readAt = t
		}
		return last
	}
}
