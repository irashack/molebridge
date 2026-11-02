package exchange

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/irashack/molebridge/internal/jsonfile"
	"github.com/irashack/molebridge/internal/netx"
	"github.com/irashack/molebridge/internal/state"
	"github.com/irashack/molebridge/internal/validate"
)

// Fetcher sends one request: netx.Client.Fetch, or a test's fake.
type Fetcher func(ctx context.Context, req netx.Request) (netx.Response, error)

// Client is one exit's side of the exchange.
type Client struct {
	// URL is the exchange's base URL (EXCHANGE_URL), http:// or https://.
	URL string
	// ExitID is the exit's id at the exchange; Token its bearer token.
	ExitID string
	Token  string
	// StateDir is the exit's state directory: the request is written to
	// panel/desired.json under it, and the published files read from applier/.
	StateDir string
	// Provider names the exit's provider: the catalog's size limit, and the
	// rule the request's server name must meet.
	Provider string
	// RootCAs and ServerName pin the exchange's TLS certificate
	// (EXCHANGE_CA_FILE, EXCHANGE_TLS_NAME); nil and empty use the system's.
	RootCAs    *x509.CertPool
	ServerName string
	// SocketMark marks every connection and its name lookup, so the requests
	// take the exit's host path (the control mark).
	SocketMark uint32
	Fetch      Fetcher
	// Now is the wall clock sent in SentAtHeader (time.Now when nil).
	Now func() time.Time
}

// Errors a round returns. None carries the URL, the token or a body.
var (
	ErrAnswer  = errors.New("the exchange's answer is not a valid schema 1 answer")
	ErrRequest = errors.New("the panel's request is not valid for this exit")
)

// StatusError is an HTTP status outside 2xx from the exchange.
type StatusError struct{ Status int }

func (e StatusError) Error() string {
	if e.Status == 401 {
		return "the exchange answered HTTP 401 (check EXCHANGE_TOKEN and EXCHANGE_EXIT_ID)"
	}
	return fmt.Sprintf("the exchange answered HTTP %d", e.Status)
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Client) request(method, path string, body []byte, maxBytes int64, timeout time.Duration) netx.Request {
	header := map[string]string{
		"Authorization": "Bearer " + c.Token,
		SentAtHeader:    c.now().UTC().Format(time.RFC3339Nano),
		"Accept":        "application/json",
	}
	if body != nil {
		header["Content-Type"] = "application/json"
		header[SHA256Header] = Hash(body)
	}
	return netx.Request{
		URL: strings.TrimRight(c.URL, "/") + "/v1/exits/" + url.PathEscape(c.ExitID) + path, Method: method,
		Header: header, Body: body, MaxBytes: maxBytes, Timeout: timeout, AllowHTTP: true, AnyStatus: true,
		RootCAs: c.RootCAs, ServerName: c.ServerName, SocketMark: c.SocketMark, MarkResolver: c.SocketMark != 0,
	}
}

// Round is one exchange: it fetches the panel's request and the hashes of the
// copies the exchange holds, writes the request to the exit's desired.json
// when it is new, and sends each published file whose copy differs. It
// stops at the first failed request; the next round starts over.
func (c *Client) Round(ctx context.Context) error {
	resp, err := c.Fetch(ctx, c.request("GET", "", nil, AnswerLimit, 10*time.Second))
	if err != nil {
		return err
	}
	if resp.Status != 200 {
		return StatusError{resp.Status}
	}
	desired, have, err := parseAnswer(resp.Body)
	if err != nil {
		return err
	}
	// A request the exit can't take is reported, but the files still go: the
	// panel must keep seeing the exit's status.
	var requestErr error
	if desired != nil {
		requestErr = c.takeRequest(desired)
	}
	for _, name := range Files {
		limit, _ := FileLimit(name, c.Provider)
		data, ok := jsonfile.ReadBytes(filepath.Join(c.StateDir, "applier", name), limit)
		if !ok || have[name] == Hash(data) {
			continue
		}
		timeout := 10 * time.Second
		if name == FileRelays {
			timeout = 60 * time.Second
		}
		resp, err := c.Fetch(ctx, c.request("PUT", "/files/"+name, data, 4096, timeout))
		if err != nil {
			return err
		}
		if resp.Status != 204 && resp.Status != 200 {
			return StatusError{resp.Status}
		}
	}
	return requestErr
}

// parseAnswer reads a GET answer: exactly schema 1, desired (an object or
// null) and have (file names to hashes).
func parseAnswer(body []byte) (desired any, have map[string]string, err error) {
	value, err := validate.DecodeJSON(body)
	m, ok := value.(map[string]any)
	if err != nil || !ok || len(m) != 3 {
		return nil, nil, ErrAnswer
	}
	if schema, ok := m["schema"].(int64); !ok || schema != Schema {
		return nil, nil, ErrAnswer
	}
	d, present := m["desired"]
	if _, isObject := d.(map[string]any); !present || (d != nil && !isObject) {
		return nil, nil, ErrAnswer
	}
	h, ok := m["have"].(map[string]any)
	if !ok {
		return nil, nil, ErrAnswer
	}
	have = map[string]string{}
	for name, v := range h {
		s, isString := v.(string)
		if _, known := FileLimit(name, ""); !known || !isString || !hashRE.MatchString(s) {
			return nil, nil, ErrAnswer
		}
		have[name] = s
	}
	return d, have, nil
}

// takeRequest writes the panel's request to the exit's desired.json when it
// differs from the one there. It never deletes the file: an exchange with no
// request leaves the exit on its last one.
func (c *Client) takeRequest(desired any) error {
	request, ok := state.DesiredRequest(desired, c.Provider)
	if !ok {
		return ErrRequest
	}
	path := filepath.Join(c.StateDir, "panel", "desired.json")
	if local, ok := state.DesiredRequest(jsonfile.Read(path, DesiredLimit), c.Provider); ok &&
		local.Server == request.Server && state.RequestToken(local) == state.RequestToken(request) {
		return nil
	}
	return state.WriteJSONAtomic(path, request, false, DesiredLimit)
}

// Run runs a round every Every until ctx ends, logging through logf a failure
// when it starts, when its reason changes and every 10 minutes while it
// lasts, and the recovery once.
func (c *Client) Run(ctx context.Context, logf func(format string, a ...any)) {
	tick := time.NewTicker(Every)
	defer tick.Stop()
	var failing string
	var loggedAt time.Time
	for {
		err := c.Round(ctx)
		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			reason := errorText(err)
			if reason != failing || time.Since(loggedAt) >= 10*time.Minute {
				logf("exchange: round failed: %s", reason)
				failing, loggedAt = reason, time.Now()
			}
		case failing != "":
			logf("exchange: works again")
			failing = ""
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// errorText is the error's text without a path: a write error names its
// cause only.
func errorText(err error) string {
	if err == io.EOF {
		return "unexpected end of the answer"
	}
	return pathless(err).Error()
}
