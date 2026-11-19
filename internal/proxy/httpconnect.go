package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"syscall"
)

// HTTP CONNECT, with Proxy-Authorization: Basic. Nothing else is proxied: no
// plain HTTP requests, no other method.
type httpConn struct {
	conn net.Conn
	br   *bufio.Reader
	s    *server
}

const proxyRealm = `Basic realm="molebridge", charset="UTF-8"`

func (c *httpConn) read() (request, bool) {
	// The reader under c.br stops after maxHandshakeBytes, so a request whose
	// line and headers are longer fails here.
	req, err := http.ReadRequest(c.br)
	if err != nil {
		c.respond(http.StatusBadRequest, "")
		return request{}, false
	}
	if req.Method != http.MethodConnect {
		c.respond(http.StatusMethodNotAllowed, "Allow: CONNECT\r\n")
		return request{}, false
	}
	if req.ContentLength != 0 || len(req.TransferEncoding) > 0 {
		c.respond(http.StatusBadRequest, "")
		return request{}, false
	}
	host, portText, err := net.SplitHostPort(req.RequestURI)
	port, perr := strconv.Atoi(portText)
	if err != nil || perr != nil || strconv.Itoa(port) != portText || !validTarget(host, port) {
		c.respond(http.StatusBadRequest, "")
		return request{}, false
	}
	username, password, ok := basicAuth(req.Header.Values("Proxy-Authorization"))
	location, session, valid := c.s.authenticate(username, password)
	if !ok || !valid {
		c.respond(http.StatusProxyAuthRequired, "Proxy-Authenticate: "+proxyRealm+"\r\n")
		return request{}, false
	}
	return request{location: location, session: session, target: net.JoinHostPort(host, portText)}, true
}

// basicAuth reads exactly one "Basic" credential.
func basicAuth(values []string) (string, []byte, bool) {
	if len(values) != 1 {
		return "", nil, false
	}
	scheme, encoded, found := strings.Cut(strings.TrimSpace(values[0]), " ")
	if !found || !strings.EqualFold(scheme, "Basic") {
		return "", nil, false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return "", nil, false
	}
	user, pass, found := strings.Cut(string(raw), ":")
	if !found {
		return "", nil, false
	}
	return user, []byte(pass), true
}

// respond writes a response without a body and closes the exchange.
func (c *httpConn) respond(code int, headers string) {
	fmt.Fprintf(c.conn, "HTTP/1.1 %d %s\r\n%sContent-Length: 0\r\nConnection: close\r\n\r\n",
		code, http.StatusText(code), headers)
}

// refuse: 503 while the tunnel is not ok, 504 for a dial that timed out,
// 502 for any other failure of the Upstream.
func (c *httpConn) refuse(err error) {
	var ne net.Error
	switch {
	case err == nil:
		c.respond(http.StatusServiceUnavailable, "")
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout(), errors.Is(err, syscall.ETIMEDOUT):
		c.respond(http.StatusGatewayTimeout, "")
	default:
		c.respond(http.StatusBadGateway, "")
	}
}

func (c *httpConn) ready() error {
	_, err := c.conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	return err
}
