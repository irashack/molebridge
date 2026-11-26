package proxy

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
)

// maxPasswordBytes is the longest password RFC 1929 can carry.
const maxPasswordBytes = 255

// ReadPassword reads the proxy's password from path. It refuses a missing
// file, anything but a regular file, a file anyone may read, an empty
// password and one longer than 255 bytes. Its group may read it: the proxy
// runs as a non-root user that is often given the file through a group, as
// Kubernetes' fsGroup does. One trailing newline ("\n" or "\r\n") is not
// part of the password.
func ReadPassword(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("proxy: no password file (PROXY_PASSWORD_FILE)")
	}
	// Opened without blocking, so a FIFO is refused below rather than
	// stalling the start.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("proxy: password file: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("proxy: password file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("proxy: the password file is not a regular file")
	}
	if info.Mode().Perm()&0o004 != 0 {
		return nil, fmt.Errorf("proxy: the password file is readable by others (mode %04o); make it 0600, 0640 or 0440",
			info.Mode().Perm())
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxPasswordBytes+3))
	if err != nil {
		return nil, fmt.Errorf("proxy: password file: %w", err)
	}
	s := string(raw)
	if strings.HasSuffix(s, "\r\n") {
		s = s[:len(s)-2]
	} else if strings.HasSuffix(s, "\n") {
		s = s[:len(s)-1]
	}
	if s == "" {
		return nil, errors.New("proxy: the password file is empty")
	}
	if len(s) > maxPasswordBytes {
		return nil, errors.New("proxy: the password is longer than 255 bytes")
	}
	return []byte(s), nil
}

// passwordMatches compares in constant time. Both sides are padded to the
// longest password allowed, so neither the length nor the first difference
// shows in the time taken.
func passwordMatches(want, got []byte) bool {
	var a, b [maxPasswordBytes]byte
	copy(a[:], want)
	copy(b[:], got)
	same := subtle.ConstantTimeCompare(a[:], b[:])
	same &= subtle.ConstantTimeEq(int32(len(want)), int32(len(got)))
	return same == 1 && len(got) <= maxPasswordBytes
}

// Bounds of the username's parts.
const (
	maxLocationLen = 63
	maxSessionLen  = 32
)

// ParseUsername reads `<location>` or `<location>.<session>`. A location is
// 1 to 63 of [a-z0-9_-], starting with a letter or digit (`any`, `se`,
// `se-got`, `se-got-wg-001`, a PIA region); a session is [a-z0-9_]{1,32}.
// Whether the location exists is the Upstream's to say.
func ParseUsername(username string) (location, session string, ok bool) {
	location, session, dotted := strings.Cut(username, ".")
	if !validLocation(location) {
		return "", "", false
	}
	if !dotted {
		return location, "", true
	}
	if !validSession(session) {
		return "", "", false
	}
	return location, session, true
}

func validLocation(s string) bool {
	if len(s) == 0 || len(s) > maxLocationLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case (c == '-' || c == '_') && i > 0:
		default:
			return false
		}
	}
	return true
}

func validSession(s string) bool {
	if len(s) == 0 || len(s) > maxSessionLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// authenticate checks a username and password; on success it returns the
// username's parts.
func (s *server) authenticate(username string, password []byte) (location, session string, ok bool) {
	match := passwordMatches(s.password, password)
	location, session, valid := ParseUsername(username)
	if !match || !valid {
		return "", "", false
	}
	return location, session, true
}

// validTarget checks "host:port" from a client: a port 1 to 65535 and a host
// that is an IP literal or a DNS name. The name is passed on as it is,
// never resolved here.
func validTarget(host string, port int) bool {
	if port < 1 || port > 65535 {
		return false
	}
	return validHost(host)
}

func validHost(host string) bool {
	if isIPLiteral(host) {
		return true
	}
	name := strings.TrimSuffix(host, ".")
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}
