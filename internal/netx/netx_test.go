// Tests for internal/netx. There is no Python counterpart: the Python applier
// ran curl, whose flags these tests pin down by behavior (the command-line
// assertions of tools/test_runtime.py test_catalogue_fetch_is_bounded_and_
// does_not_follow_redirect and tools/test_pia.py's pinned-CA calls).
// Everything here talks to loopback servers only.
package netx

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"
)

// authority makes a throwaway CA and a server certificate for name valid on
// 127.0.0.1.
func authority(t testing.TB, name string) (pool *x509.CertPool, server tls.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Example Test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	pool = x509.NewCertPool()
	pool.AddCert(caCert)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return pool, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func tlsServer(t testing.TB, cert tls.Certificate, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func TestPinnedAuthorityAndConnectAddress(t *testing.T) {
	pool, cert := authority(t, "example401")
	var seen *http.Request
	server := tlsServer(t, cert, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r
		io.WriteString(w, `{"status": "OK"}`)
	}))
	// The URL names example401; the connection goes to the test server.
	response, err := Client{}.Fetch(context.Background(), Request{
		URL: "https://example401:1337/addKey?pt=x", RootCAs: pool, ConnectAddr: server.Listener.Addr().String(),
		UserAgent: "molebridge-applier/0.2"})
	if err != nil || response.Status != 200 || string(response.Body) != `{"status": "OK"}` {
		t.Fatalf("%v %+v", err, response)
	}
	if seen.URL.Path != "/addKey" || seen.URL.Query().Get("pt") != "x" || seen.Host != "example401:1337" ||
		seen.Header.Get("User-Agent") != "molebridge-applier/0.2" {
		t.Errorf("request: %+v", seen)
	}
}

func TestAnotherAuthorityIsRefusedAndTheNameMustMatch(t *testing.T) {
	_, cert := authority(t, "example401")
	otherPool, _ := authority(t, "example401")
	server := tlsServer(t, cert, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	pool, _ := authority(t, "x")
	addr := server.Listener.Addr().String()
	for name, request := range map[string]Request{
		"another CA":      {URL: "https://example401/", RootCAs: otherPool, ConnectAddr: addr},
		"unrelated CA":    {URL: "https://example401/", RootCAs: pool, ConnectAddr: addr},
		"system roots":    {URL: "https://example401/", ConnectAddr: addr},
		"wrong name":      {URL: "https://other.example.test/", RootCAs: otherPool, ConnectAddr: addr},
		"wrong server id": {URL: "https://example401/", RootCAs: otherPool, ServerName: "other.example.test", ConnectAddr: addr},
	} {
		if _, err := (Client{}).Fetch(context.Background(), request); !errors.Is(err, ErrTransport) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestServerNameOverridesTheURLHost(t *testing.T) {
	pool, cert := authority(t, "example401")
	server := tlsServer(t, cert, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	response, err := Client{}.Fetch(context.Background(), Request{
		URL: "https://" + server.Listener.Addr().String() + "/", RootCAs: pool, ServerName: "example401"})
	if err != nil || string(response.Body) != "ok" {
		t.Fatalf("%v %+v", err, response)
	}
}

func TestOnlyHTTPSUnlessAllowed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer server.Close()
	if _, err := (Client{}).Fetch(context.Background(), Request{URL: server.URL}); !errors.Is(err, ErrScheme) {
		t.Errorf("http: %v", err)
	}
	for _, bad := range []string{"ftp://example.test/", "file:///etc/passwd", "example.test", "", "https:///x"} {
		if _, err := (Client{}).Fetch(context.Background(), Request{URL: bad, AllowHTTP: true}); !errors.Is(err, ErrScheme) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	response, err := Client{}.Fetch(context.Background(), Request{URL: server.URL, AllowHTTP: true})
	if err != nil || string(response.Body) != "ok" {
		t.Errorf("allowed http: %v %+v", err, response)
	}
}

func TestRedirectsAreAnswersNotInstructions(t *testing.T) {
	followed := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/next" {
			followed = true
			return
		}
		http.Redirect(w, r, "/next", http.StatusFound)
	}))
	defer server.Close()
	response, err := Client{}.Fetch(context.Background(), Request{URL: server.URL, AllowHTTP: true})
	if err != nil || response.Status != http.StatusFound || followed {
		t.Fatalf("%v %+v followed=%v", err, response, followed)
	}
}

func TestErrorStatusFailsUnlessAnyStatusIsAccepted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"message": "unauthorized"}`)
	}))
	defer server.Close()
	if _, err := (Client{}).Fetch(context.Background(), Request{URL: server.URL, AllowHTTP: true}); !errors.Is(err, ErrStatus) {
		t.Errorf("-f: %v", err)
	}
	response, err := Client{}.Fetch(context.Background(), Request{URL: server.URL, AllowHTTP: true, AnyStatus: true})
	if err != nil || response.Status != 401 || !strings.Contains(string(response.Body), "unauthorized") {
		t.Errorf("any status: %v %+v", err, response)
	}
}

func TestTheBodyIsBounded(t *testing.T) {
	chunked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.(http.Flusher).Flush() // no Content-Length
		for i := 0; i < 20; i++ {
			w.Write(bytes.Repeat([]byte("x"), 1024))
		}
	}))
	defer chunked.Close()
	sized := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(bytes.Repeat([]byte("x"), 100))
	}))
	defer sized.Close()
	for name, url := range map[string]string{"chunked": chunked.URL, "sized": sized.URL} {
		_, err := Client{}.Fetch(context.Background(), Request{URL: url, AllowHTTP: true, MaxBytes: 50})
		if !errors.Is(err, ErrTooLarge) {
			t.Errorf("%s: %v", name, err)
		}
	}
	response, err := Client{}.Fetch(context.Background(), Request{URL: sized.URL, AllowHTTP: true, MaxBytes: 100})
	if err != nil || len(response.Body) != 100 {
		t.Errorf("exactly the limit: %v %d", err, len(response.Body))
	}
}

// readBody reads whatever the body holds, up to one byte past the limit,
// whatever length it announced; the announced length only sizes the buffer.
func TestReadBodyIgnoresAWrongLength(t *testing.T) {
	body := bytes.Repeat([]byte("x"), 100)
	for _, tc := range []struct {
		size, limit, length int64
		want                int
	}{
		{100, 100, 100, 100}, {100, 100, -1, 100}, {100, 100, 10, 100}, {100, 100, 0, 100},
		{100, 1000, 1000, 100}, {100, 99, 99, 100}, {100, 50, 10, 51}, {100, 50, -1, 51},
		{0, 100, 0, 0}, {0, 100, -1, 0},
	} {
		got, err := readBody(iotest.HalfReader(bytes.NewReader(body[:tc.size])), tc.limit, tc.length)
		if err != nil || len(got) != tc.want {
			t.Errorf("%+v: %d bytes, %v", tc, len(got), err)
		}
	}
	failing := io.MultiReader(bytes.NewReader(body), iotest.ErrReader(io.ErrUnexpectedEOF))
	if _, err := readBody(failing, 1000, 200); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("a failed read: %v", err)
	}
}

// An announced length within the limit is read into one buffer of that size.
func TestReadBodyAllocatesTheAnnouncedLengthOnce(t *testing.T) {
	body := bytes.Repeat([]byte("x"), 1<<20)
	allocated := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if got, err := readBody(bytes.NewReader(body), 2<<20, int64(len(body))); err != nil || len(got) != len(body) {
				b.Fatal(len(got), err)
			}
		}
	}).AllocedBytesPerOp()
	if allocated > int64(len(body))+64*1024 {
		t.Errorf("%d bytes allocated for a body of %d", allocated, len(body))
	}
}

func TestTheDeadlineBoundsTheWholeRequest(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer server.Close()
	defer close(release)
	start := time.Now()
	_, err := Client{}.Fetch(context.Background(), Request{URL: server.URL, AllowHTTP: true, Timeout: 100 * time.Millisecond})
	if !errors.Is(err, ErrTimeout) || time.Since(start) > 3*time.Second {
		t.Errorf("%v after %v", err, time.Since(start))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (Client{}).Fetch(ctx, Request{URL: server.URL, AllowHTTP: true}); !errors.Is(err, ErrCanceled) {
		t.Errorf("canceled: %v", err)
	}
}

func TestProxySettingsAreIgnored(t *testing.T) {
	proxied := false
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { proxied = true }))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("http_proxy", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("ALL_PROXY", proxy.URL)
	// 192.0.2.1 is TEST-NET-1 and not routable; the proxy must not be asked about it either.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "direct") }))
	defer server.Close()
	response, err := Client{}.Fetch(context.Background(), Request{URL: server.URL, AllowHTTP: true})
	if err != nil || string(response.Body) != "direct" || proxied {
		t.Fatalf("%v %+v proxied=%v", err, response, proxied)
	}
}

func TestMethodHeadersAndBodyAreSent(t *testing.T) {
	var method, auth, kind string
	var body []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, auth, kind = r.Method, r.Header.Get("Authorization"), r.Header.Get("Content-Type")
		body, _ = io.ReadAll(r.Body)
	}))
	defer server.Close()
	_, err := Client{}.Fetch(context.Background(), Request{URL: server.URL, AllowHTTP: true, Method: "POST",
		Header: map[string]string{"Authorization": "Bearer example", "Content-Type": "text/plain"}, Body: []byte("payload")})
	if err != nil || method != "POST" || auth != "Bearer example" || kind != "text/plain" || string(body) != "payload" {
		t.Errorf("%v %s %s %s %q", err, method, auth, kind, body)
	}
}

func TestFamilyRestrictsTheConnection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "v4") }))
	defer server.Close()
	if response, err := (Client{}).Fetch(context.Background(), Request{URL: server.URL, AllowHTTP: true, Family: 4}); err != nil || string(response.Body) != "v4" {
		t.Errorf("-4: %v %+v", err, response)
	}
	// An IPv4 literal cannot be reached over IPv6.
	if _, err := (Client{}).Fetch(context.Background(), Request{URL: server.URL, AllowHTTP: true, Family: 6}); !errors.Is(err, ErrTransport) {
		t.Errorf("-6: %v", err)
	}
}

func TestErrorsCarryNoRequestData(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close() // nothing listens now
	_, err = Client{}.Fetch(context.Background(), Request{
		URL: "http://" + address + "/path?pt=SECRET-TOKEN", AllowHTTP: true,
		Header: map[string]string{"Authorization": "Bearer SECRET-TOKEN"}})
	if err == nil || strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), address) {
		t.Errorf("%v", err)
	}
}

func TestResponseHeadersAreReturned(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "SID=abc; HttpOnly")
		io.WriteString(w, "Ok.")
	}))
	defer server.Close()
	response, err := Client{}.Fetch(context.Background(), Request{URL: server.URL, AllowHTTP: true})
	if err != nil || response.Header.Get("Set-Cookie") != "SID=abc; HttpOnly" {
		t.Errorf("%v %+v", err, response)
	}
}

// fakeResolver answers every A question with 127.0.0.2, where nothing
// listens, then 127.0.0.1, and any other with no answer, over UDP and TCP on the same port, and counts the questions each
// transport was asked. With truncate, every UDP answer is truncated (TC set,
// no answer), so the client must ask again over TCP.
func fakeResolver(t *testing.T, truncate bool) (addr string, udp, tcp *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	conn, err := net.ListenPacket("udp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	udp, tcp = new(atomic.Int32), new(atomic.Int32)
	answer := func(q []byte, truncated bool) []byte {
		if len(q) < 12 {
			return nil
		}
		end := 12
		for end < len(q) && q[end] != 0 {
			end += int(q[end]) + 1
		}
		end += 5 // the root label, the type and the class
		if end > len(q) {
			return nil
		}
		out := append([]byte{q[0], q[1], 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0}, q[12:end]...)
		if truncated {
			out[2] |= 0x02
			return out
		}
		if q[end-4] == 0 && q[end-3] == 1 {
			out[7] = 2
			for _, last := range []byte{2, 1} {
				out = append(out, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, last)
			}
		}
		return out
	}
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			udp.Add(1)
			if a := answer(buf[:n], truncate); a != nil {
				_, _ = conn.WriteTo(a, from)
			}
		}
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				for {
					var size [2]byte
					if _, err := io.ReadFull(c, size[:]); err != nil {
						return
					}
					q := make([]byte, int(size[0])<<8|int(size[1]))
					if _, err := io.ReadFull(c, q); err != nil {
						return
					}
					tcp.Add(1)
					a := answer(q, false)
					_, _ = c.Write(append([]byte{byte(len(a) >> 8), byte(len(a))}, a...))
				}
			}()
		}
	}()
	return ln.Addr().String(), udp, tcp
}

// refusingResolver is an address nothing listens on: a lookup there fails at
// once (the port is unreachable).
func refusingResolver(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := conn.LocalAddr().String()
	conn.Close()
	return addr
}

func fetchByName(t *testing.T, resolvers []string) (Response, error) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	t.Cleanup(server.Close)
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	return Client{}.Fetch(context.Background(), Request{
		URL: "http://molebridge-resolver.test:" + port + "/", AllowHTTP: true, Family: 4,
		Resolvers: resolvers, Timeout: 30 * time.Second,
	})
}

func TestResolversReplaceTheSystemsNameServers(t *testing.T) {
	// Two that fail, then one that answers: each is asked in its own right,
	// whatever /etc/resolv.conf says about servers and attempts. Its first
	// address refuses the connection: Go's dialer goes on to the next.
	resolver, udp, _ := fakeResolver(t, false)
	resp, err := fetchByName(t, []string{refusingResolver(t), refusingResolver(t), resolver})
	if err != nil || string(resp.Body) != "ok" {
		t.Fatalf("Fetch: %v %q", err, resp.Body)
	}
	if udp.Load() == 0 {
		t.Error("the configured resolver was never asked")
	}
}

func TestResolversKeepTheTCPRetryOnTheSameServer(t *testing.T) {
	resolver, udp, tcp := fakeResolver(t, true)
	resp, err := fetchByName(t, []string{resolver, refusingResolver(t)})
	if err != nil || string(resp.Body) != "ok" {
		t.Fatalf("Fetch: %v %q", err, resp.Body)
	}
	if udp.Load() == 0 || tcp.Load() == 0 {
		t.Errorf("questions: %d over UDP, %d over TCP; want both on the truncating server", udp.Load(), tcp.Load())
	}
}

func TestResolversThatAllFail(t *testing.T) {
	if _, err := fetchByName(t, []string{refusingResolver(t)}); err == nil {
		t.Fatal("a name no resolver answered was connected to")
	}
}
