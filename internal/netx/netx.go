// Package netx is the one HTTP client of the exit worker: net/http with an
// explicit Transport per request, standing in for the curl calls of the
// Python applier.
//
// Each request says exactly what curl was told: the address family (-4, -6),
// the interface or socket mark the connection is bound to (--interface; the
// gluetun host marks), a pinned certificate authority and TLS name with an
// address to connect to (--cacert, --connect-to), a size bound
// (--max-filesize), a deadline (--max-time) and whether non-HTTPS URLs are
// accepted (--proto). Every request ignores proxy settings (--noproxy '*') and
// none follows a redirect: a 3xx answer is returned as it is and the caller
// judges the status, as it did with curl's --write-out '%{http_code}'.
//
// Errors never carry the URL, the headers or any part of the body: a URL can
// hold a token, and an answer can hold anything. They say only what kind of
// failure it was (ErrTimeout, ErrTooLarge, ErrStatus, ErrTransport, ErrScheme).
//
// The interface and mark bindings use SO_BINDTODEVICE and SO_MARK on Linux
// (bind_linux.go); on other systems the bindings are accepted and ignored, so
// tests run anywhere.
//
// The package offers Client (Fetch), Request, Response and the error values.
package netx

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Errors Fetch returns. None of them carries any part of the request or the
// answer.
var (
	// ErrScheme: the URL is not one the request allows (HTTPS only unless
	// AllowHTTP is set).
	ErrScheme = errors.New("netx: URL scheme not allowed")
	// ErrTimeout: the deadline passed (the request's Timeout or its context).
	ErrTimeout = errors.New("netx: request timed out")
	// ErrTooLarge: the answer is larger than MaxBytes.
	ErrTooLarge = errors.New("netx: response exceeds its size limit")
	// ErrStatus: the server answered with an HTTP status of 400 or more and
	// the request did not accept any status.
	ErrStatus = errors.New("netx: HTTP error status")
	// ErrTransport: connecting, the TLS handshake or reading failed.
	ErrTransport = errors.New("netx: request failed")
	// ErrCanceled: the request's context was canceled.
	ErrCanceled = errors.New("netx: request canceled")
)

// DefaultConnectTimeout bounds the connection attempt when a request names no
// ConnectTimeout (curl's own default is longer; every Python call that cared
// said --connect-timeout 10).
const DefaultConnectTimeout = 10 * time.Second

// Request is one HTTP request.
type Request struct {
	// URL is absolute. Only https is accepted unless AllowHTTP is set.
	URL string
	// Method is GET when empty.
	Method string
	// Header holds extra request headers (Authorization, Content-Type ...).
	Header map[string]string
	// UserAgent replaces Go's default when set.
	UserAgent string
	// Body is sent as the request body.
	Body []byte

	// Family restricts the connection to IPv4 (4) or IPv6 (6); 0 is either.
	Family int
	// BindInterface binds the connection to this network interface
	// (SO_BINDTODEVICE; curl --interface). Empty is not bound.
	BindInterface string
	// SocketMark sets this firewall mark on the connection (SO_MARK). Zero is
	// no mark.
	SocketMark uint32

	// RootCAs, when set, is the only authority the server's certificate is
	// verified against (curl --cacert); otherwise the system roots are used.
	RootCAs *x509.CertPool
	// ServerName is the TLS name to verify and send; the URL's host when empty.
	ServerName string
	// ConnectAddr, when set, is the "host:port" actually connected to in place
	// of the URL's host and port (curl --connect-to).
	ConnectAddr string

	// MaxBytes bounds the answer's body. Zero means 1 MiB.
	MaxBytes int64
	// Timeout is the deadline of the whole request (curl --max-time). Zero
	// means 10 seconds.
	Timeout time.Duration
	// ConnectTimeout bounds connecting; DefaultConnectTimeout when zero.
	ConnectTimeout time.Duration

	// AllowHTTP accepts an http URL too (curl --proto =http,https).
	AllowHTTP bool
	// AnyStatus returns the answer whatever its status instead of failing
	// with ErrStatus from 400 (curl without -f).
	AnyStatus bool
}

// Response is an answer within its size bound.
type Response struct {
	Status int
	Body   []byte
}

// Client sends requests. The zero value is ready to use; it keeps no
// connections between requests.
type Client struct{}

// Fetch sends req and returns the answer.
func (Client) Fetch(ctx context.Context, req Request) (Response, error) {
	parsed, err := url.Parse(req.URL)
	if err != nil || parsed.Host == "" {
		return Response{}, ErrScheme
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https":
	case "http":
		if !req.AllowHTTP {
			return Response{}, ErrScheme
		}
	default:
		return Response{}, ErrScheme
	}
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	limit := req.MaxBytes
	if limit <= 0 {
		limit = 1 << 20
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	var body io.Reader
	if req.Body != nil {
		body = bytes.NewReader(req.Body)
	}
	httpRequest, err := http.NewRequestWithContext(ctx, method, req.URL, body)
	if err != nil {
		return Response{}, ErrScheme
	}
	for name, value := range req.Header {
		httpRequest.Header.Set(name, value)
	}
	if req.UserAgent != "" {
		httpRequest.Header.Set("User-Agent", req.UserAgent)
	}

	connectTimeout := req.ConnectTimeout
	if connectTimeout <= 0 {
		connectTimeout = DefaultConnectTimeout
	}
	dialer := &net.Dialer{Timeout: connectTimeout, Control: bindControl(req.BindInterface, req.SocketMark)}
	network := "tcp"
	switch req.Family {
	case 4:
		network = "tcp4"
	case 6:
		network = "tcp6"
	}
	transport := &http.Transport{
		// --noproxy '*': the environment's proxy settings never apply.
		Proxy: nil,
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			if req.ConnectAddr != "" {
				address = req.ConnectAddr
			}
			return dialer.DialContext(ctx, network, address)
		},
		TLSClientConfig:       &tls.Config{RootCAs: req.RootCAs, ServerName: req.ServerName, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   connectTimeout,
		DisableKeepAlives:     true,
		DisableCompression:    true,
		ForceAttemptHTTP2:     false,
		ResponseHeaderTimeout: timeout,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		// A redirect is an answer, not an instruction.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	response, err := client.Do(httpRequest)
	if err != nil {
		return Response{}, classify(ctx, err)
	}
	defer response.Body.Close()
	if response.ContentLength > limit {
		return Response{}, ErrTooLarge
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return Response{}, classify(ctx, err)
	}
	if int64(len(raw)) > limit {
		return Response{}, ErrTooLarge
	}
	if response.StatusCode >= 400 && !req.AnyStatus {
		return Response{}, ErrStatus
	}
	return Response{Status: response.StatusCode, Body: raw}, nil
}

func classify(ctx context.Context, err error) error {
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded):
		return ErrTimeout
	case errors.Is(ctx.Err(), context.Canceled) || errors.Is(err, context.Canceled):
		return ErrCanceled
	}
	var timeout interface{ Timeout() bool }
	if errors.As(err, &timeout) && timeout.Timeout() {
		return ErrTimeout
	}
	return ErrTransport
}
