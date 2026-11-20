package proxy

import (
	"context"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/irashack/molebridge/internal/jsonfile"
	"github.com/irashack/molebridge/internal/validate"
	"github.com/irashack/molebridge/internal/verdict"
)

// The status record, proxy.json (docs/design/menu.md, "The proxy's status").
// It is a file of its own, never part of result.json; verdict.AssessProxy
// judges it.

// Bounds on what the record repeats from the Upstream.
const (
	maxBenchedListed = 1000
	maxReasonBytes   = 200
)

// statusRecord is proxy.json for the given status, as of now, with the
// signature of what makes a change worth publishing at once (the benched
// servers and the tunnel's verdict).
func (s *server) statusRecord(status, message string) (validate.Obj, string) {
	now := s.cfg.Now()
	tunnel := s.cfg.Tunnel()
	servers := s.cfg.Upstream.Servers()
	var benched []ServerState
	for _, st := range servers {
		if st.Benched && st.BenchedUntil.After(now) {
			benched = append(benched, st)
		}
	}
	sort.Slice(benched, func(i, j int) bool { return benched[i].Server < benched[j].Server })
	if len(benched) > maxBenchedListed {
		benched = benched[:maxBenchedListed]
	}
	var sig strings.Builder
	sig.WriteString(tunnel.Verdict + "\x00" + tunnel.Unreadable)
	list := make([]any, 0, len(benched))
	for _, b := range benched {
		until := validate.FormatTime(b.BenchedUntil)
		list = append(list, validate.Members("server", b.Server, "until", until, "reason", shortReason(b.Reason)))
		sig.WriteString("\x00" + b.Server + "\x00" + until)
	}
	record := validate.Members(
		"schema", verdict.ProxySchema, "kind", "proxy", "provider", s.cfg.Provider,
		"guarantee", "opt-in",
		"status", status, "message", message,
		"checked_at", validate.FormatTime(now),
		"listen", s.cfg.Listen,
		"tunnel", validate.Members("verdict", orNull(tunnel.Verdict), "server", orNull(tunnel.Server),
			"checked_at", orNull(tunnel.CheckedAt)),
		"servers", validate.Members("known", len(servers), "benched", list),
		"sessions", s.sessions.active(),
		"connections", validate.Members("open", s.open.Load(), "total", s.total.Load(), "failed", s.failed.Load()),
	)
	return record, sig.String()
}

func orNull(v string) any {
	if v == "" {
		return nil
	}
	return v
}

// shortReason is the Upstream's reason as one bounded line of text.
func shortReason(reason string) string {
	reason = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, strings.ToValidUTF8(reason, "?"))
	if len(reason) > maxReasonBytes {
		cut := maxReasonBytes
		for cut > 0 && !utf8.RuneStart(reason[cut]) {
			cut--
		}
		reason = reason[:cut]
	}
	if reason == "" {
		return "unknown"
	}
	return reason
}

// servingStatus is the status while the listener is up.
func (s *server) servingStatus() (string, string) {
	if t := s.cfg.Tunnel(); t.Verdict != "ok" {
		v := t.Verdict
		if v == "" {
			v = "unknown"
		}
		if t.Unreadable != "" {
			return "refusing", "Refusing new connections: the exit's verdict is " + v + ": " + shortReason(t.Unreadable) + "."
		}
		return "refusing", "Refusing new connections: the exit's verdict is " + v + "."
	}
	return "ok", "Serving."
}

// publish writes proxy.json; a failure is logged, and the next write tries
// again.
func (s *server) publish(status, message string) string {
	record, sig := s.statusRecord(status, message)
	if s.cfg.StatusPath == "" {
		return sig
	}
	if err := jsonfile.Write(s.cfg.StatusPath, record,
		jsonfile.Options{Public: true, NoSync: true, MaxBytes: verdict.ProxyMaxBytes}); err != nil {
		s.cfg.Logf("proxy: writing %s: %v", s.cfg.StatusPath, err)
	}
	return sig
}

// statusCheckEvery is how often the status loop looks for a bench, a
// recovery or a change of the tunnel's verdict between the regular writes.
const statusCheckEvery = time.Second

// statusLoop publishes proxy.json at once, every StatusInterval, and
// whenever a server is benched or recovers or the tunnel's verdict changes
// (checked every second and after every dial).
func (s *server) statusLoop(ctx context.Context) {
	last := s.publish(s.servingStatus())
	written := time.Now()
	check := time.NewTicker(statusCheckEvery)
	defer check.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-check.C:
		case <-s.kick:
		}
		if time.Since(written) >= s.cfg.StatusInterval {
			last, written = s.publish(s.servingStatus()), time.Now()
			continue
		}
		if _, sig := s.statusRecord(s.servingStatus()); sig != last {
			last, written = s.publish(s.servingStatus()), time.Now()
		}
	}
}
