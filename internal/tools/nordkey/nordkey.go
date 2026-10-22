// Package nordkey is the nordvpn-key role: tools/nordvpn-key.py as a
// container tool. It fetches the account's NordLynx private key with a
// NordVPN access token and writes Molebridge's tunnel config for NordVPN. It
// prints one fixed line and no token, key or response.
package nordkey

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"syscall"
	"time"

	"github.com/irashack/molebridge/internal/tools/prepareconfig"
	"github.com/irashack/molebridge/internal/tools/privfile"
	"github.com/irashack/molebridge/internal/validate"
)

// Limits and constants of the request.
const (
	CredentialsURL   = "https://api.nordvpn.com/v1/users/services/credentials"
	TokenMaxBytes    = 512
	ResponseMaxBytes = 65536
	Timeout          = 20 * time.Second
	// OKLine is the one line printed on success.
	OKLine = "wrote the NordVPN tunnel config (mode 0600)"
)

// Help is the usage text; it documents the mounts.
const Help = `Usage: molebridge nordvpn-key TOKEN_FILE OUTPUT
       printf %s "$TOKEN" | molebridge nordvpn-key - OUTPUT

Fetches your NordLynx private key with a NordVPN access token (Nord Account,
NordVPN, Advanced settings, Get access token) and writes Molebridge's tunnel
config for NordVPN.

TOKEN_FILE holds the access token and must be mode 0600 or stricter. With -
the token is read from standard input (run the container with -i). It is
never read from the command line or the environment. OUTPUT is created with
mode 0600 and is never overwritten; it carries the private key and the
NordLynx tunnel address (10.5.0.2/32) but no peer: the applier sets the peer
when you pick a server. The exit table comes from EXIT_TABLE (default 51821).

Prints one fixed line and no token, key or response. Delete the token file, or
revoke the token in your Nord Account, once this succeeds: only the key is
needed afterwards. Both paths are inside the container, so mount them, and
run as yourself so the output is not owned by root (on rootless Podman drop
--user: the default mapping makes the container's root you):

  docker run --rm --user "$(id -u):$(id -g)" \
    -v "$PWD/tunnel/wg_confs:/out" -v "$PWD/nordvpn-token:/token:ro" \
    ghcr.io/irashack/molebridge:<tag> nordvpn-key /token /out/nordvpn.conf

  printf %s "$TOKEN" | docker run --rm -i --user "$(id -u):$(id -g)" \
    -v "$PWD/tunnel/wg_confs:/out" \
    ghcr.io/irashack/molebridge:<tag> nordvpn-key - /out/nordvpn.conf
`

// Error is a failure with a fixed, value-free message.
type Error string

func (e Error) Error() string { return string(e) }

// Fixed messages.
const (
	errExists = Error("the output file exists; keep it, or remove it deliberately")
	errFetch  = Error("the request to NordVPN failed")
)

// Token characters: printable ASCII without quote or backslash.
var tokenRE = regexp.MustCompile(`^[\x21\x23-\x5b\x5d-\x7e]{1,256}$`)

// ReadToken is read_token: the access token from a mode-0600 file, or from
// stdin for "-".
func ReadToken(source string, stdin io.Reader) (string, error) {
	var raw []byte
	if source == "-" {
		var err error
		if raw, err = io.ReadAll(io.LimitReader(stdin, TokenMaxBytes+1)); err != nil {
			return "", Error("the token could not be read")
		}
	} else {
		f, err := os.OpenFile(source, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return "", Error("the token could not be read")
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil {
			return "", Error("the token could not be read")
		}
		if !info.Mode().IsRegular() {
			return "", Error("the token file is not a regular file")
		}
		if info.Mode().Perm()&0o077 != 0 {
			return "", Error("the token file must be mode 0600 or stricter")
		}
		if raw, err = io.ReadAll(io.LimitReader(f, TokenMaxBytes+1)); err != nil {
			return "", Error("the token could not be read")
		}
	}
	if len(raw) > TokenMaxBytes {
		return "", Error("the token is too long")
	}
	for _, c := range raw {
		if c >= 0x80 {
			return "", Error("the token is not valid")
		}
	}
	token := string(raw)
	if n := len(token); n > 0 && token[n-1] == '\n' {
		token = token[:n-1]
	}
	if n := len(token); n > 0 && token[n-1] == '\r' {
		token = token[:n-1]
	}
	if !tokenRE.MatchString(token) {
		return "", Error("the token is not valid")
	}
	return token, nil
}

// NewClient is the HTTP client the tool uses: no proxy from the environment
// (curl's --noproxy '*'), TLS 1.2 or later, no redirects followed (curl's
// default), no connection reuse, and the request deadline.
func NewClient() *http.Client {
	return &http.Client{
		Timeout: Timeout,
		Transport: &http.Transport{
			Proxy:             nil,
			DialContext:       (&net.Dialer{Timeout: Timeout}).DialContext,
			TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// FetchCredentials is fetch_credentials: GET the credentials document with
// the token as the HTTP Basic credential "token:<token>". The token goes in
// the request header only. Any failure is the same fixed error.
func FetchCredentials(client *http.Client, url, token string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), Timeout+5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, errFetch
	}
	req.SetBasicAuth("token", token)
	resp, err := client.Do(req)
	if err != nil {
		return nil, errFetch
	}
	defer resp.Body.Close()
	// curl -f fails from status 400; a 3xx body is returned (and then fails
	// to parse as the credentials).
	if resp.StatusCode >= 400 || resp.ContentLength > ResponseMaxBytes {
		return nil, errFetch
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, ResponseMaxBytes+1))
	if err != nil || len(body) > ResponseMaxBytes {
		return nil, errFetch
	}
	return body, nil
}

// ParsePrivateKey is parse_private_key: only "nordlynx_private_key"; nothing
// else in the response is used.
func ParsePrivateKey(raw []byte) (string, error) {
	data, err := validate.DecodeJSON(raw)
	if err != nil {
		return "", Error("the NordVPN response is not valid")
	}
	object, _ := data.(map[string]any)
	key := object["nordlynx_private_key"]
	if !validate.ValidKey(key) {
		return "", Error("the NordVPN response has no usable key")
	}
	return key.(string), nil
}

// BuildNordConf is build_nord_conf: the config prepare-config --nordvpn also
// writes, with this tool named in the header.
func BuildNordConf(privateKey, table string) (string, error) {
	if !validate.ValidKey(privateKey) {
		return "", prepareconfig.ConfigError("PrivateKey is missing or is not a WireGuard key")
	}
	return prepareconfig.BuildNordConf(privateKey, table, "nordvpn-key")
}

// Options are what Main needs from its surroundings.
type Options struct {
	Env    map[string]string
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	// Fetch replaces the HTTP call in tests; nil means the real one.
	Fetch func(token string) ([]byte, error)
}

// Defaults returns Options for the real process.
func Defaults(env map[string]string, stdin io.Reader, stdout, stderr io.Writer) Options {
	return Options{Env: env, Stdin: stdin, Stdout: stdout, Stderr: stderr}
}

// Main runs the role: 0 on success, 1 on a refusal, 2 on a usage error.
func Main(args []string, o Options) int {
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		io.WriteString(o.Stdout, Help)
		return 0
	}
	if len(args) != 2 {
		fmt.Fprintln(o.Stderr, "usage: molebridge nordvpn-key TOKEN_FILE|- OUTPUT")
		return 2
	}
	output := args[1]
	table := prepareconfig.DefaultTable
	if v, ok := o.Env["EXIT_TABLE"]; ok {
		table = v
	}
	err := run(args[0], output, table, o)
	if err != nil {
		var fixed Error
		if errors.As(err, &fixed) {
			fmt.Fprintf(o.Stderr, "error: %s\n", fixed)
		} else {
			fmt.Fprintln(o.Stderr, "error: the tunnel config could not be written")
		}
		return 1
	}
	fmt.Fprintln(o.Stdout, OKLine)
	return 0
}

func run(source, output, table string, o Options) error {
	if _, err := os.Lstat(output); err == nil {
		return errExists
	}
	token, err := ReadToken(source, o.Stdin)
	if err != nil {
		return err
	}
	fetch := o.Fetch
	if fetch == nil {
		client := NewClient()
		fetch = func(token string) ([]byte, error) { return FetchCredentials(client, CredentialsURL, token) }
	}
	raw, err := fetch(token)
	if err != nil {
		return err
	}
	key, err := ParsePrivateKey(raw)
	if err != nil {
		return err
	}
	content, err := BuildNordConf(key, table)
	if err != nil {
		return err
	}
	if err := privfile.WriteNew(output, []byte(content)); err != nil {
		switch {
		case errors.Is(err, privfile.ErrExists):
			return errExists
		case errors.Is(err, privfile.ErrCreate):
			return Error("the output file could not be created")
		}
		return err
	}
	return nil
}
