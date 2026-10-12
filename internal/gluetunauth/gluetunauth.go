// Package gluetunauth holds the helpers around gluetun v3.41.3's control
// server role file and API key: the role file Molebridge generates, the check
// that a file is exactly that (the same structure routing/gluetun-preflight
// accepts before gluetun starts), the default-role rule, and the reader of the
// API key file. The gluetun-auth tool writes the files; the exit's gluetun
// client reads the key with ReadAPIKey. Port of applier/gluetun.py
// (read_api_key, gluetun_auth_config, gluetun_auth_file, default_role_allowed,
// valid_auth_file).
package gluetunauth

import (
	"io"
	"os"
	"regexp"
	"strings"
	"syscall"
	"unicode/utf8"
)

// MaxKeyBytes bounds the API key file.
const MaxKeyBytes = 1024

// Routes are the only routes the role grants. GET and PUT /v1/updater/status
// let the applier start one refresh of gluetun's server list
// (internal/server/updater.go at v3.41.3): gluetun's own updater first runs
// one period after start, never at start.
var Routes = []string{"PUT /v1/vpn/settings", "GET /v1/vpn/status", "GET /v1/publicip/ip",
	"GET /v1/updater/status", "PUT /v1/updater/status"}

// DefaultRoleName is the role the tool writes.
const DefaultRoleName = "molebridge"

var (
	roleNameRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)
	apiKeyRE   = regexp.MustCompile(`^[A-Za-z0-9_-]{32,128}$`)
	nameLineRE = regexp.MustCompile(`^name = "([^"]*)"$`)
	keyLineRE  = regexp.MustCompile(`^apikey = "([^"]*)"$`)
)

// routesLine is json.dumps(list(ROUTES)): a JSON array with ", " separators.
func routesLine() string {
	return `routes = ["` + strings.Join(Routes, `", "`) + `"]`
}

// Error is a refusal with a fixed message that carries no key.
type Error string

func (e Error) Error() string { return string(e) }

// ReadAPIKey reads one printable ASCII key (33 to 126), with an optional
// single trailing newline (LF or CRLF), from a regular file that is not a
// symbolic link, has no mode bits beyond 0600 (setuid, setgid and sticky
// count) and is at most MaxKeyBytes. Every failure is the same fixed error.
func ReadAPIKey(path string) (string, error) {
	fail := Error("cannot read gluetun API key")
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", fail
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", fail
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || uint32(st.Mode)&0o7777&^0o600 != 0 || info.Size() > MaxKeyBytes {
		return "", fail
	}
	raw, err := io.ReadAll(io.LimitReader(f, MaxKeyBytes+1))
	if err != nil || len(raw) > MaxKeyBytes {
		return "", fail
	}
	value := string(raw)
	if strings.HasSuffix(value, "\n") {
		value = value[:len(value)-1]
		value = strings.TrimSuffix(value, "\r")
	}
	if value == "" {
		return "", fail
	}
	for i := 0; i < len(value); i++ {
		if c := value[i]; c < 33 || c > 126 {
			return "", fail
		}
	}
	return value, nil
}

// AuthConfig is gluetun_auth_config: a single-role TOML template whose apikey
// is empty and so unusable until the caller fills it. The format is
// gluetun's internal/server/middlewares/auth/configfile_test.go:33-43;
// settings.go:116-132 defines auth = "apikey" and the apikey field.
func AuthConfig(roleName string) (string, error) {
	if !roleNameRE.MatchString(roleName) {
		return "", Error("invalid gluetun role name")
	}
	return "[[roles]]\nname = \"" + roleName + "\"\nauth = \"apikey\"\napikey = \"\"\n" + routesLine() + "\n", nil
}

// AuthFile is gluetun_auth_file: the complete role file, one role with apikey
// authentication and exactly Routes. With any role in the file gluetun
// answers no other route (internal/server/middlewares/auth/settings.go:72-90,
// middleware.go:67-72 at v3.41.3); with none it applies a public default role
// that includes PUT /v1/vpn/status, so the file must always be there. The key
// must be URL-safe base64 text, which needs no escaping in TOML.
func AuthFile(apiKey, roleName string) (string, error) {
	if !apiKeyRE.MatchString(apiKey) {
		return "", Error("invalid gluetun API key")
	}
	config, err := AuthConfig(roleName)
	if err != nil {
		return "", err
	}
	return strings.Replace(config, `apikey = ""`, `apikey = "`+apiKey+`"`, 1), nil
}

// DefaultRoleAllowed is default_role_allowed: gluetun's
// HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE as routing/gluetun-preflight accepts
// it. Unset, empty or "{}" (gluetun's image default, no default role) is fine,
// with surrounding spaces or tabs at most. An unset setting and an empty one
// are the same here.
func DefaultRoleAllowed(value string) bool {
	switch strings.Trim(value, " \t") {
	case "", "{}":
		return true
	}
	return false
}

// ValidAuthFile is valid_auth_file: true for exactly what AuthFile writes,
// the structure routing/gluetun-preflight accepts before gluetun starts. The
// last newline is optional.
func ValidAuthFile(text string) bool {
	if len(text) > 4096 || !utf8.ValidString(text) || strings.ContainsAny(text, "\r\x00") {
		return false
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) != 5 {
		return false
	}
	name := nameLineRE.FindStringSubmatch(lines[1])
	key := keyLineRE.FindStringSubmatch(lines[3])
	return lines[0] == "[[roles]]" && name != nil && roleNameRE.MatchString(name[1]) &&
		lines[2] == `auth = "apikey"` && key != nil && apiKeyRE.MatchString(key[1]) &&
		lines[4] == routesLine()
}
