package exit

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/irashack/molebridge/internal/validate"
)

// MaxLine is the longest line either side accepts, newline excluded. A longer
// one is a protocol violation: the supervisor treats it as a worker failure.
const MaxLine = 64 * 1024

// Message types. Worker to supervisor: renew, ready, unready, status, log.
// Supervisor to worker: ack, stop, netbird.
const (
	TypeRenew   = "renew"
	TypeReady   = "ready"
	TypeUnready = "unready"
	TypeStatus  = "status"
	TypeLog     = "log"
	TypeAck     = "ack"
	TypeStop    = "stop"
	TypeNetBird = "netbird"
)

// NetBird states the supervisor reports.
const (
	// NBLaunching: a launch begins now (its log offset and boot-clock time
	// are in the message), before the daemon is even started, so the worker's
	// monitors count from the launch itself, as the gate's did.
	NBLaunching = "launching"
	NBStarted   = "started"
	NBStopped   = "stopped"
	NBFailed    = "failed"
)

// Msg is one decoded message. Only the fields of its Type are set.
type Msg struct {
	Type string
	// Gen is the launch generation (32 hex characters); empty for stop.
	Gen string
	// Seq is the worker's sequence number (renew, status) or the sequence of
	// the renewal an ack answers.
	Seq uint64
	// Loops: renew only, loop name to the boot clock (nanoseconds) of its last
	// completed step.
	Loops map[string]int64
	// Reason: unready.
	Reason string
	// Record: status only, a schema-2 record as decoded.
	Record map[string]any
	// Rec is the record to encode, in its member order (a validate.Obj or an
	// ObjectMarshaler); encoding falls back to Record.
	Rec any
	// Level and Text: log. Text is also the NetBird message's detail.
	Level, Text string
	// ExpiryBootNs: ack, the accepted expiry on the boot clock.
	ExpiryBootNs int64
	// Launch, State and LogOffset: netbird.
	Launch    int
	State     string
	LogOffset int64
	// AtBootNs: the boot-clock time the launch began (netbird messages).
	AtBootNs int64
}

// ErrProtocol wraps every decoding failure; the text never carries input.
var ErrProtocol = errors.New("protocol violation")

func violation(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrProtocol, fmt.Sprintf(format, a...))
}

func validGen(s string) bool {
	if len(s) != 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Encode renders a message as one line (newline included).
func (m Msg) Encode() ([]byte, error) {
	var o validate.Obj
	switch m.Type {
	case TypeRenew:
		names := make([]string, 0, len(m.Loops))
		for n := range m.Loops {
			names = append(names, n)
		}
		sort.Strings(names)
		loops := validate.Obj{}
		for _, n := range names {
			loops = append(loops, validate.Pair{Key: n, Value: m.Loops[n]})
		}
		o = validate.Members("type", m.Type, "gen", m.Gen, "seq", m.Seq, "loops", loops)
	case TypeReady:
		o = validate.Members("type", m.Type, "gen", m.Gen)
	case TypeUnready:
		o = validate.Members("type", m.Type, "gen", m.Gen, "reason", m.Reason)
	case TypeStatus:
		var rec any = m.Record
		if m.Rec != nil {
			rec = m.Rec
		}
		o = validate.Members("type", m.Type, "gen", m.Gen, "seq", m.Seq, "record", rec)
	case TypeLog:
		o = validate.Members("type", m.Type, "gen", m.Gen, "level", m.Level, "msg", m.Text)
	case TypeAck:
		o = validate.Members("type", m.Type, "gen", m.Gen, "seq", m.Seq, "expiry_boot_ns", m.ExpiryBootNs)
	case TypeStop:
		o = validate.Members("type", m.Type)
	case TypeNetBird:
		o = validate.Members("type", m.Type, "gen", m.Gen, "launch", m.Launch, "state", m.State, "log_offset", m.LogOffset, "at_boot_ns", m.AtBootNs)
	default:
		return nil, fmt.Errorf("exit: unknown message type %q", m.Type)
	}
	b, err := validate.MarshalJSON(o)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxLine {
		return nil, fmt.Errorf("exit: a %s message of %d bytes exceeds the %d-byte line limit", m.Type, len(b), MaxLine)
	}
	return append(b, '\n'), nil
}

// fields checks that an object has exactly the wanted members.
func fields(o map[string]any, want ...string) error {
	if len(o) != len(want) {
		return violation("wrong member set")
	}
	for _, w := range want {
		if _, ok := o[w]; !ok {
			return violation("wrong member set")
		}
	}
	return nil
}

func str(o map[string]any, key string, max int) (string, error) {
	s, ok := o[key].(string)
	if !ok || len(s) > max {
		return "", violation("%s is not a string of at most %d bytes", key, max)
	}
	return s, nil
}

func num(o map[string]any, key string) (int64, error) {
	n, ok := validate.IsInt(o[key])
	if !ok || n < 0 {
		return 0, violation("%s is not a non-negative integer", key)
	}
	return n, nil
}

// printable reports text without control characters; log lines and reasons
// are shown to the operator and must not carry terminal escapes.
func printable(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// Decode parses one line (without its newline) strictly: duplicate members,
// invalid UTF-8, unknown members, wrong types and unknown message types are
// all violations. Messages of the wrong direction are decoded by the other
// side's DecodeFromWorker/DecodeFromSupervisor; each accepts only its own.
func decode(line []byte, from map[string]bool) (Msg, error) {
	if len(line) > MaxLine {
		return Msg{}, violation("line longer than %d bytes", MaxLine)
	}
	v, err := validate.DecodeJSON(line)
	if err != nil {
		return Msg{}, violation("not a JSON object")
	}
	o, ok := v.(map[string]any)
	if !ok {
		return Msg{}, violation("not a JSON object")
	}
	t, ok := o["type"].(string)
	if !ok || !from[t] {
		return Msg{}, violation("unknown message type")
	}
	m := Msg{Type: t}
	switch t {
	case TypeRenew:
		if err = fields(o, "type", "gen", "seq", "loops"); err != nil {
			return Msg{}, err
		}
		loops, ok := o["loops"].(map[string]any)
		if !ok || len(loops) > 8 {
			return Msg{}, violation("loops is not an object of at most 8 members")
		}
		m.Loops = map[string]int64{}
		for name, raw := range loops {
			n, ok := validate.IsInt(raw)
			if !ok || n < 0 || len(name) > 32 || !printable(name) {
				return Msg{}, violation("a loop time is not a non-negative integer")
			}
			m.Loops[name] = n
		}
	case TypeReady:
		err = fields(o, "type", "gen")
	case TypeUnready:
		if err = fields(o, "type", "gen", "reason"); err == nil {
			if m.Reason, err = str(o, "reason", 1024); err == nil && !printable(m.Reason) {
				err = violation("reason has control characters")
			}
		}
	case TypeStatus:
		if err = fields(o, "type", "gen", "seq", "record"); err == nil {
			if m.Record, ok = o["record"].(map[string]any); !ok {
				err = violation("record is not an object")
			}
		}
	case TypeLog:
		if err = fields(o, "type", "gen", "level", "msg"); err == nil {
			if m.Level, err = str(o, "level", 8); err == nil {
				if m.Level != "info" && m.Level != "warn" && m.Level != "error" {
					err = violation("unknown log level")
				} else if m.Text, err = str(o, "msg", 4096); err == nil && !printable(m.Text) {
					err = violation("log text has control characters")
				}
			}
		}
	case TypeAck:
		if err = fields(o, "type", "gen", "seq", "expiry_boot_ns"); err == nil {
			m.ExpiryBootNs, err = num(o, "expiry_boot_ns")
		}
	case TypeStop:
		err = fields(o, "type")
	case TypeNetBird:
		if err = fields(o, "type", "gen", "launch", "state", "log_offset", "at_boot_ns"); err == nil {
			var launch int64
			if launch, err = num(o, "launch"); err == nil {
				m.Launch = int(launch)
				if m.State, err = str(o, "state", 16); err == nil {
					if m.State != NBLaunching && m.State != NBStarted && m.State != NBStopped && m.State != NBFailed {
						err = violation("unknown NetBird state")
					} else if m.LogOffset, err = num(o, "log_offset"); err == nil {
						m.AtBootNs, err = num(o, "at_boot_ns")
					}
				}
			}
		}
	}
	if err != nil {
		return Msg{}, err
	}
	if _, hasGen := o["gen"]; hasGen {
		if m.Gen, err = str(o, "gen", 32); err != nil || !validGen(m.Gen) {
			return Msg{}, violation("gen is not a 128-bit hex string")
		}
	}
	if t == TypeRenew || t == TypeStatus || t == TypeAck {
		var n int64
		if n, err = num(o, "seq"); err != nil {
			return Msg{}, err
		}
		m.Seq = uint64(n)
	}
	return m, nil
}

var (
	fromWorker     = map[string]bool{TypeRenew: true, TypeReady: true, TypeUnready: true, TypeStatus: true, TypeLog: true}
	fromSupervisor = map[string]bool{TypeAck: true, TypeStop: true, TypeNetBird: true}
)

// DecodeFromWorker parses a line the supervisor read.
func DecodeFromWorker(line []byte) (Msg, error) { return decode(line, fromWorker) }

// DecodeFromSupervisor parses a line the worker read.
func DecodeFromSupervisor(line []byte) (Msg, error) { return decode(line, fromSupervisor) }

// LineReader reads newline-delimited lines of at most MaxLine bytes.
type LineReader struct {
	r *bufio.Reader
}

// NewLineReader wraps r.
func NewLineReader(r io.Reader) *LineReader {
	// One byte for the newline beyond the longest line.
	return &LineReader{r: bufio.NewReaderSize(r, MaxLine+1)}
}

// Next returns the next line without its newline. A line longer than MaxLine is
// a violation; io.EOF ends the stream (a final line without a newline is a
// violation too: a writer that died mid-line left half a message).
func (l *LineReader) Next() ([]byte, error) {
	line, err := l.r.ReadSlice('\n')
	switch {
	case err == nil:
		return append([]byte(nil), line[:len(line)-1]...), nil
	case errors.Is(err, bufio.ErrBufferFull):
		return nil, violation("line longer than %d bytes", MaxLine)
	case errors.Is(err, io.EOF) && len(line) > 0:
		return nil, violation("a line ended without a newline")
	}
	return nil, err
}

// Sender writes messages to one pipe; it is safe for concurrent use.
type Sender struct {
	mu sync.Mutex
	w  io.Writer
}

// NewSender wraps w.
func NewSender(w io.Writer) *Sender { return &Sender{w: w} }

// Send writes one message.
func (s *Sender) Send(m Msg) error {
	b, err := m.Encode()
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.w.Write(b)
	return err
}

// sanitize makes operator-facing text safe for a log line.
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, s)
}
