// Package portsync keeps an application's listening port on the port the
// exit's provider forwarded (PIA's port forwarding in a native sidecar). It
// reads state/applier/result.json, never writes it, and speaks only to the
// application's own API on a loopback address. The only client is qBittorrent
// (Web API v2).
//
// Settings are read by LoadSettings from the process environment; every
// refusal is an error whose text the role prints after the prefix Prefix. A
// Syncer does one pass with Step and loops with Run; both take their clock and
// HTTP client from the Syncer so tests need neither the network nor time.
package portsync

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Prefix starts every line the role prints.
const Prefix = "molebridge-port-sync: "

// Defaults and limits of the settings.
const (
	DefaultURL      = "http://127.0.0.1:8080"
	DefaultStateDir = "/state"
	DefaultInterval = 30 * time.Second
	MinInterval     = 10 * time.Second
	MaxInterval     = 300 * time.Second
	// MaxCredentialBytes bounds a credential file.
	MaxCredentialBytes = 1024
)

// Settings are the validated settings of the role.
type Settings struct {
	Client   string
	URL      string // as given; the Referer qBittorrent compares with Host
	StateDir string
	Interval time.Duration
	// UsernameFile and PasswordFile are both set or both empty.
	UsernameFile string
	PasswordFile string
}

// LoadSettings validates the environment. It reads the credential files once,
// only to refuse a missing or unusable one at start; the values are dropped.
func LoadSettings(env map[string]string) (Settings, error) {
	s := Settings{
		Client:       env["PORT_SYNC_CLIENT"],
		URL:          env["PORT_SYNC_URL"],
		StateDir:     env["STATE_DIR"],
		UsernameFile: env["PORT_SYNC_USERNAME_FILE"],
		PasswordFile: env["PORT_SYNC_PASSWORD_FILE"],
		Interval:     DefaultInterval,
	}
	switch s.Client {
	case "":
		return Settings{}, errors.New("PORT_SYNC_CLIENT is required (the only client is qbittorrent)")
	case "qbittorrent":
	default:
		return Settings{}, errors.New("PORT_SYNC_CLIENT must be qbittorrent")
	}
	if s.URL == "" {
		s.URL = DefaultURL
	}
	if err := checkURL(s.URL); err != nil {
		return Settings{}, err
	}
	if s.StateDir == "" {
		s.StateDir = DefaultStateDir
	}
	if (s.UsernameFile == "") != (s.PasswordFile == "") {
		return Settings{}, errors.New("PORT_SYNC_USERNAME_FILE and PORT_SYNC_PASSWORD_FILE must be set together or not at all")
	}
	if s.UsernameFile != "" {
		for _, f := range []struct{ name, path string }{
			{"PORT_SYNC_USERNAME_FILE", s.UsernameFile}, {"PORT_SYNC_PASSWORD_FILE", s.PasswordFile}} {
			if _, err := ReadCredential(f.path); err != nil {
				return Settings{}, fmt.Errorf("%s: %v", f.name, err)
			}
		}
	}
	if v := env["PORT_SYNC_INTERVAL"]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || strings.TrimSpace(v) != v || strings.HasPrefix(v, "+") ||
			n < int(MinInterval/time.Second) || n > int(MaxInterval/time.Second) {
			return Settings{}, errors.New("PORT_SYNC_INTERVAL must be a whole number of seconds from 10 to 300")
		}
		s.Interval = time.Duration(n) * time.Second
	}
	return s, nil
}

// checkURL accepts an http URL to a loopback IP address, with no userinfo,
// path, query or fragment.
func checkURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.Opaque != "" || u.Host == "" {
		return errors.New("PORT_SYNC_URL must be an http URL (https is refused: the application is on a loopback address)")
	}
	if u.User != nil {
		return errors.New("PORT_SYNC_URL must not contain a user name or password")
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") {
		return errors.New("PORT_SYNC_URL must not contain a query or fragment")
	}
	if u.Path != "" && u.Path != "/" {
		return errors.New("PORT_SYNC_URL must not contain a path")
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil || !ip.IsLoopback() {
		return errors.New("PORT_SYNC_URL must name a loopback IP address (127.0.0.0/8 or [::1])")
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return errors.New("PORT_SYNC_URL has an invalid port")
		}
	}
	return nil
}

// ReadCredential reads one credential file: at most MaxCredentialBytes, one
// trailing newline removed, not empty. The error never carries the content.
func ReadCredential(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", errors.New("cannot be opened")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return "", errors.New("is not a regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(f, MaxCredentialBytes+1))
	if err != nil {
		return "", errors.New("cannot be read")
	}
	if len(raw) > MaxCredentialBytes {
		return "", errors.New("is larger than 1 KiB")
	}
	text := strings.TrimSuffix(string(raw), "\n")
	text = strings.TrimSuffix(text, "\r")
	if text == "" {
		return "", errors.New("is empty")
	}
	return text, nil
}
