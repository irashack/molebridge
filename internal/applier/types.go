package applier

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/irashack/molebridge/internal/jsonfile"
	"github.com/irashack/molebridge/internal/state"
	"github.com/irashack/molebridge/internal/validate"
	"github.com/irashack/molebridge/internal/verdict"
)

// Timing and wording of the pipeline, as applier/apply.py has them.
const (
	// HandshakeFreshSec: a handshake this old or older is stale.
	HandshakeFreshSec = verdict.HandshakeFreshSec
	// A health check whose egress check gets no usable answer (a timeout, a
	// refused or reset connection, an HTTP error, a malformed reply) asks once
	// more after EgressRetrySec before it publishes a failure, unless the first
	// attempt took longer than EgressRetryWithinSec. The second attempt starts
	// no request after EgressRetryBudgetSec, so with one request's own limit a
	// check stays well inside the 150 seconds after which readers call a result
	// unknown.
	EgressRetrySec       = 10
	EgressRetryWithinSec = 15
	EgressRetryBudgetSec = 30
	// RefreshSec is how often a settled selection is re-checked.
	RefreshSec = 60
	// PollSec is how often the exit worker calls Tick.
	PollSec = 5
	// FreshRequestSec: a panel request this recent is the operator asking now:
	// it is applied even when the server is already live (a PIA region
	// registers anew). An older one, as after an upgrade, is re-inspected first.
	FreshRequestSec = 150
	// ServerReportChars: a valid provider hostname fits within 253 characters.
	// Invalid input is bounded too, so even JSON-escaped Unicode fits the
	// readers' 16 KiB status limit.
	ServerReportChars = 256
	// ResultMaxBytes is the readers' bound on result.json.
	ResultMaxBytes = 16384
	// ReturnPathSysctl is the file whose content "1" makes the kernel source
	// ICMP errors from the inbound interface's address.
	ReturnPathSysctl = "/proc/sys/net/ipv4/icmp_errors_use_inbound_ifaddr"
)

// SwitchTimeoutSec is the native backend's switch timeout.
var SwitchTimeoutSec = float64(state.SwitchTimeouts["native"])

// Messages published verbatim.
const (
	NetbirdModeFailed = "NetBird is not running kernel WireGuard with its kernel firewall on the overlay " +
		"interface; see the troubleshooting guide."
	RoutingFailed  = "Routing protection is incomplete; run the recovery helper."
	InvalidDesired = "Invalid desired-state file; no change applied."
	Unlisted       = "Requested server is not in a fresh trusted relay catalogue; no change applied."
	// EgressFailedMessage is what an inspection says when a call failed.
	EgressFailedMessage = "Tunnel inspection or egress check failed."
)

// MutationRefused wraps (with %w) the error of a change refused before it took
// effect: a definite outcome.
var ErrMutationRefused = errors.New("the change was refused before it took effect")

// ErrCredentialRejected is a MutationRefused too: the provider refused the
// account's login, so retrying can't help until the credentials change or the
// operator retries.
var ErrCredentialRejected = fmt.Errorf("%w: the provider refused the login", ErrMutationRefused)

// ioError marks a failure of the applier's own file I/O (reading a credential
// file, writing state). In Python these were OSError, which the pipeline's
// `except (RuntimeError, ValueError, UnicodeError)` does not catch: they leave
// the control cycle (Tick returns them) with the attempt as it was saved.
type ioError struct{ err error }

func (e *ioError) Error() string { return e.err.Error() }
func (e *ioError) Unwrap() error { return e.err }

func wrapIO(err error) error {
	if err == nil {
		return nil
	}
	return &ioError{err}
}

// caught is true for the errors the pipeline handles as a failed step: every
// error except the applier's own file I/O failures and a canceled context.
func caught(err error) bool {
	var io *ioError
	return !errors.As(err, &io) && !errors.Is(err, context.Canceled)
}

// Exit is the part of the exit worker's configuration the applier reads.
type Exit struct {
	// ExitIf is the tunnel interface, OverlayIf the NetBird interface and Table
	// the exit routing table (decimal).
	ExitIf, OverlayIf, Table string
	// Overlay is the IPv4 overlay network in CIDR form.
	Overlay string
	// Kind is "overlay" (a NetBird exit) or "sidecar" (an ordinary gluetun
	// other containers share).
	Kind string
}

// Gatus is the monitoring push's settings (GATUS_URL, GATUS_TOKEN,
// GATUS_ENDPOINT); with no URL or no token nothing is pushed.
type Gatus struct {
	URL, Token, Endpoint string
}

// Config builds an Applier.
type Config struct {
	// StateDir is the state directory; the applier's files live in
	// StateDir/applier and the panel's request in StateDir/panel/desired.json.
	StateDir string
	Exit     Exit
	// Provider is the hooks for the provider the exit serves.
	Provider Provider
	System   System
	// Server is the SERVER setting: when set it is the only server the exit
	// serves and the panel's request is never read.
	Server string
	// BootID is this boot's id; empty reads it from the kernel.
	BootID string
	// Monotonic is the boot clock in seconds (CLOCK_MONOTONIC); BootClock when
	// nil. Wall is the wall clock, time.Now when nil. Sleep waits; the default
	// waits on a timer or the context.
	Monotonic func() float64
	Wall      func() time.Time
	Sleep     func(ctx context.Context, d time.Duration)
	// Publish receives every status record the applier builds. The supervisor
	// writes result.json (decision D7); the applier does not. The check the
	// supervisor owns, owner_record, is left "unknown" in the records built
	// here.
	Publish func(*Record) error
	// OwnerCheck is the supervisor's owner_record check as it would write it
	// now ({state, at, expires_at}), or nil. The applier leaves the check
	// "unknown" in the records it hands to Publish; it judges a record for
	// the Gatus push and PIA's port forwarding as the supervisor will publish
	// it, with this check in place of the unknown one. Nil judges the record
	// as built.
	OwnerCheck func() validate.Obj
	// Log receives the applier's few progress lines ("applier: ..."); stdout
	// when nil.
	Log   func(string)
	Gatus Gatus
}

// Selection is a target with its identity: a panel request's token,
// "configured:<server>" or "restore:<server>". A new identity is a new target
// for the pipeline.
type Selection struct {
	Server  string
	Source  string
	Request *state.Request
}

// Key identifies the selection.
func (s *Selection) Key() string {
	if s.Source == "panel" && s.Request != nil {
		return state.RequestToken(*s.Request)
	}
	return s.Source + ":" + s.Server
}

func (s *Selection) target() verdict.Target {
	if s == nil {
		return verdict.Target{}
	}
	return verdict.Target{Server: s.Server, Source: s.Source, Request: s.Request}
}

// Finding is one inspection's findings (measure); emit publishes it.
type Finding struct {
	Status  string
	Message string
	Server  string // "" for none
	Checks  validate.Obj
	Fields  validate.Obj
	// Safe is false when a protective guard is lost; Guard says which message
	// then stands.
	Safe  bool
	Guard string
	// Peers is the number of peers seen, -1 for none measured.
	Peers int
	// Age is the handshake age in seconds, nil for none.
	Age *int
	// At is the boot clock when the inspection started.
	At float64
}

// EgressResult is a provider's egress answer.
type EgressResult struct {
	EgressIP      string // "" for none
	EgressCity    *string
	EgressCountry *string
	// ExitConfirmed: the provider itself confirmed the egress.
	ExitConfirmed bool
	// EgressTier is "tunnel" when the tunnel checks passed, else "".
	EgressTier string
	// EgressIPs and Families are keyed "4" and "6", in ascending order.
	EgressIPs validate.Obj
	Families  validate.Obj
	Reason    string
	Message   string
}

func (e EgressResult) family(f string) (string, bool) {
	for _, p := range e.Families {
		if p.Key == f {
			s, _ := p.Value.(string)
			return s, true
		}
	}
	return "", false
}

// Record is a status record in the member order Python's dict had.
type Record struct{ members validate.Obj }

// JSONObject implements validate.ObjectMarshaler.
func (r *Record) JSONObject() validate.Obj { return r.members }

// Get returns a member, nil when absent.
func (r *Record) Get(key string) any {
	if r == nil {
		return nil
	}
	for _, p := range r.members {
		if p.Key == key {
			return p.Value
		}
	}
	return nil
}

// Decoded is the record as a reader sees it: the encoded JSON decoded again.
func (r *Record) Decoded() map[string]any {
	if r == nil {
		return nil
	}
	raw, err := validate.MarshalJSON(r)
	if err != nil {
		return nil
	}
	value, err := validate.DecodeJSON(raw)
	if err != nil {
		return nil
	}
	m, _ := value.(map[string]any)
	return m
}

// ResultPath is state/applier/result.json under a state directory.
func ResultPath(stateDir string) string { return filepath.Join(stateDir, "applier", "result.json") }

// WriteResult writes a record as result.json: atomically, readable by the
// non-root panel (0644). The supervisor calls it (decision D7); the applier
// never does.
func WriteResult(stateDir string, record *Record) error {
	return jsonfile.Write(ResultPath(stateDir), record, jsonfile.Options{Public: true})
}

// orNull is nil for the empty string (Python's None).
func orNull(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func strPtr(s string) *string { return &s }

func ptrOrNull(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}

func intPtr(n int) *int { return &n }

// truncateChars is s[:n] in code points.
func truncateChars(s string, n int) string {
	count := 0
	for i := 0; i < len(s); {
		if count == n {
			return s[:i]
		}
		_, size := validate.NextRune(s[i:])
		i += size
		count++
	}
	return s
}

// surrogateEscape is what Python's os.environ does with bytes that are not
// UTF-8: each becomes a lone surrogate (here in its WTF-8 form), so the text
// can be reported escaped.
func surrogateEscape(s string) string {
	var b strings.Builder
	for len(s) > 0 {
		r, size := validate.NextRune(s)
		if r == 0xFFFD && size == 1 {
			c := rune(0xDC00) + rune(s[0])
			b.WriteByte(0xE0 | byte(c>>12))
			b.WriteByte(0x80 | byte(c>>6)&0x3F)
			b.WriteByte(0x80 | byte(c)&0x3F)
		} else {
			b.WriteString(s[:size])
		}
		s = s[size:]
	}
	return b.String()
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
