package exit

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/irashack/molebridge/internal/exchange"
	"github.com/irashack/molebridge/internal/netx"
	"github.com/irashack/molebridge/internal/proc"
)

// ExchangeSettings are the network exchange's settings
// (docs/network-exchange-design.md): nil in Settings when EXCHANGE_URL is
// unset, and the exit then exchanges files only.
type ExchangeSettings struct {
	URL     string
	ExitID  string
	Token   string
	CAFile  string
	TLSName string
}

// markEnv carries the control mark to the exchange child, which reads no
// routing settings of its own.
const markEnv = "MOLEBRIDGE_EXCHANGE_MARK"

// loadExchange reads EXCHANGE_URL, EXCHANGE_EXIT_ID, EXCHANGE_TOKEN (from
// secrets/applier.env, like GATUS_TOKEN), EXCHANGE_CA_FILE and
// EXCHANGE_TLS_NAME.
func loadExchange(env map[string]string) (*ExchangeSettings, error) {
	raw := env["EXCHANGE_URL"]
	if raw == "" {
		return nil, nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, refuse("EXCHANGE_URL must be an http:// or https:// URL with a host and no credentials, query or fragment")
	}
	x := &ExchangeSettings{URL: raw, ExitID: env["EXCHANGE_EXIT_ID"], Token: env["EXCHANGE_TOKEN"],
		CAFile: env["EXCHANGE_CA_FILE"], TLSName: env["EXCHANGE_TLS_NAME"]}
	if !exchange.ValidExitID(x.ExitID) {
		return nil, refuse("EXCHANGE_EXIT_ID must be the exit's id at the exchange: 1-32 of a-z, 0-9 and -")
	}
	if !validToken(x.Token) {
		return nil, refuse("EXCHANGE_TOKEN (in secrets/applier.env) must be at least %d printable characters with no spaces", exchange.MinTokenBytes)
	}
	if x.CAFile != "" {
		if _, err := loadCA(x.CAFile); err != nil {
			return nil, refuse("EXCHANGE_CA_FILE: %v", err)
		}
	}
	return x, nil
}

func validToken(t string) bool {
	if len(t) < exchange.MinTokenBytes || len(t) > exchange.TokenLimit {
		return false
	}
	for i := 0; i < len(t); i++ {
		if t[i] <= ' ' || t[i] > '~' {
			return false
		}
	}
	return true
}

func loadCA(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read the file")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no PEM certificate in the file")
	}
	return pool, nil
}

// plainRemote is whether u is http:// to a host other than localhost or a
// loopback address: the token would cross a network unencrypted.
func plainRemote(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return false
	}
	ip := net.ParseIP(host)
	return ip == nil || !ip.IsLoopback()
}

// ExchangeEnv is the exchange child's environment: its own settings, where
// the state is, the provider, the control mark and nothing else. It never sees
// the tunnel key, the provider's credentials, NetBird's setup key or the
// Gatus token.
func ExchangeEnv(s *Settings) []string {
	out := map[string]string{"PATH": "/usr/local/bin:/usr/bin:/bin", "STATE_DIR": s.StateDir, "PROVIDER": s.Provider,
		markEnv: strconv.FormatUint(uint64(s.Routing.ControlMark), 10)}
	for _, k := range []string{"EXCHANGE_URL", "EXCHANGE_EXIT_ID", "EXCHANGE_TOKEN", "EXCHANGE_CA_FILE", "EXCHANGE_TLS_NAME", "TZ"} {
		if v, ok := s.Env[k]; ok {
			out[k] = v
		}
	}
	return flatten(out)
}

// RunExchange is `molebridge exit --exchange`, the supervisor's exchange
// child: it runs the client's rounds until SIGTERM. It touches no routing and
// holds no lease; the supervisor restarts it when it ends.
func RunExchange(environ []string, stderr io.Writer) int {
	env := EnvMap(environ)
	x, err := loadExchange(env)
	if err != nil || x == nil {
		fmt.Fprintln(stderr, prefix+"exchange: not configured")
		return 1
	}
	mark, err := strconv.ParseUint(env[markEnv], 10, 32)
	if err != nil {
		fmt.Fprintln(stderr, prefix+"exchange: no control mark")
		return 1
	}
	c := &exchange.Client{URL: x.URL, ExitID: x.ExitID, Token: x.Token, StateDir: orDefault(env["STATE_DIR"], DefaultStateDir),
		Provider: orDefault(env["PROVIDER"], "mullvad"), ServerName: x.TLSName, SocketMark: uint32(mark), Fetch: netx.Client{}.Fetch}
	if x.CAFile != "" {
		if c.RootCAs, err = loadCA(x.CAFile); err != nil {
			fmt.Fprintf(stderr, prefix+"exchange: EXCHANGE_CA_FILE: %v\n", err)
			return 1
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	c.Run(ctx, func(format string, a ...any) { fmt.Fprintf(stderr, prefix+format+"\n", a...) })
	return 0
}

// exchangeRunner keeps the exchange child running: started once the worker
// is, restarted after it ends (one second, doubling to a minute, back to one
// second after it ran a minute), and stopped first in the stop sequence. Its
// failure stops nothing else.
type exchangeRunner struct {
	start func() (*proc.Process, error)
	logf  func(format string, a ...any)
	// Backoff bounds (tests shorten them).
	first, max time.Duration

	mu      sync.Mutex
	closed  bool
	current *proc.Process
	// quit is closed by Close; done by Run when it returns.
	quit chan struct{}
	done chan struct{}
}

func newExchangeRunner(start func() (*proc.Process, error), logf func(string, ...any)) *exchangeRunner {
	return &exchangeRunner{start: start, logf: logf, first: time.Second, max: time.Minute,
		quit: make(chan struct{}), done: make(chan struct{})}
}

func (r *exchangeRunner) Run() {
	defer close(r.done)
	delay := r.first
	for {
		r.mu.Lock()
		if r.closed {
			r.mu.Unlock()
			return
		}
		p, err := r.start()
		r.current = p
		r.mu.Unlock()
		began := time.Now()
		if err != nil {
			r.logf("exchange: cannot start: %v", err)
		} else {
			<-p.Reaped()
			r.mu.Lock()
			closed := r.closed
			r.mu.Unlock()
			if closed {
				return
			}
			ws, _ := p.Status()
			r.logf("exchange: ended with status %d; starting it again", proc.ExitCode(ws))
		}
		if time.Since(began) >= r.max {
			delay = r.first
		}
		select {
		case <-time.After(delay):
		case <-r.quit:
			return
		}
		if delay *= 2; delay > r.max {
			delay = r.max
		}
	}
}

// Close signals the child and returns at once: the stop sequence's signals
// come first and never wait. A child still there after two seconds is killed.
func (r *exchangeRunner) Close() {
	r.mu.Lock()
	if !r.closed {
		r.closed = true
		close(r.quit)
	}
	p := r.current
	r.mu.Unlock()
	if p != nil {
		_ = p.SignalGroup(syscall.SIGTERM)
		go func() {
			if !p.WaitGone(2 * time.Second) {
				_ = p.KillGroup()
			}
		}()
	}
}

// exchangeWarnings are the start-up warnings about the exchange's settings.
func exchangeWarnings(x *ExchangeSettings) []string {
	if x != nil && plainRemote(x.URL) {
		return []string{"exchange: warning: EXCHANGE_URL is plain http:// to a host other than loopback; the exchange token crosses the network unencrypted (use https://)"}
	}
	return nil
}
