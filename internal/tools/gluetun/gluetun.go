// Package gluetun holds the gluetun-auth and gluetun-post-rules roles:
// tools/molebridge.py's gluetun_auth and gluetun_post_rules as container
// tools. Neither calls a container engine. Paths in the messages are the
// directories the caller mounted, where the Python tool printed
// repository-relative paths.
package gluetun

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/gluetunauth"
	"github.com/irashack/molebridge/internal/tools/privfile"
)

// checkError is a refusal with a fixed message (host_tools.CheckError); the
// roles print it as "FAIL <message>".
type checkError string

func (e checkError) Error() string { return string(e) }

// Options are what the roles need from their surroundings.
type Options struct {
	// Env is the process environment as a map.
	Env    map[string]string
	Random io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// Defaults returns Options for the real process.
func Defaults(env map[string]string, stdout, stderr io.Writer) Options {
	return Options{Env: env, Random: rand.Reader, Stdout: stdout, Stderr: stderr}
}

// AuthHelp documents the mounts of gluetun-auth.
const AuthHelp = `Usage: molebridge gluetun-auth [--rotate] DIR

Writes gluetun's control-server role file (DIR/auth.toml) and the exit's copy
of its API key (DIR/api_key), both mode 0600, from one key generated here.
The key is never printed. DIR is the directory you mounted; the Compose files
read ./secrets/gluetun, so mount that. If both files exist nothing changes;
--rotate replaces both with a new key. If only one exists, --rotate is the
way to write both again. After a rotation recreate gluetun and the exit
container so both use the new key.

  docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/secrets/gluetun:/out" \
    ghcr.io/irashack/molebridge:<tag> gluetun-auth /out

  docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/secrets/gluetun:/out" \
    ghcr.io/irashack/molebridge:<tag> gluetun-auth --rotate /out

On rootless Podman drop --user and add --userns=keep-id.
`

// PostRulesHelp documents the mounts and settings of gluetun-post-rules.
const PostRulesHelp = `Usage: molebridge gluetun-post-rules [--ipv4-only] DIR

Writes gluetun's post-rules file (DIR/post-rules.txt, mode 0644) from the
routing settings in the environment, validated as the exit validates them:

  OVERLAY_CIDR (required)  OVERLAY6_CIDR (optional)  OVERLAY_IF (wt0)
  EXIT_IF (wg0)  EXIT_TABLE (51821)  HOST_IF (eth0)  HOST_TABLE (51822)
  CONTROL_MARK (0x1bd00)  NB_WIREGUARD_PORT (51820)

An unset or empty setting is its default, as in Compose's ${NAME:-default}.
Pass the settings with -e NAME=value; an --env-file works only when its lines
are plain NAME=value (docker does not strip quotes or an "export"). DIR is the
directory you mounted; the Compose files read ./tunnel/gluetun, so mount that.
--ipv4-only leaves out the ip6tables lines, for a host where gluetun finds no
ip6tables. Recreate gluetun afterwards to apply the file.

  docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/tunnel/gluetun:/out" \
    -e OVERLAY_CIDR=100.64.0.0/10 \
    ghcr.io/irashack/molebridge:<tag> gluetun-post-rules /out

On rootless Podman drop --user and add --userns=keep-id.
`

// parseArgs reads "[--flag ...] DIR". The flags may come before or after DIR.
func parseArgs(args []string, flags ...string) (dir string, set map[string]bool, help, ok bool) {
	set = map[string]bool{}
	for _, a := range args {
		switch {
		case a == "-h" || a == "--help":
			return "", nil, true, true
		case len(a) > 1 && a[0] == '-':
			known := false
			for _, f := range flags {
				if a == f {
					set[f] = true
					known = true
				}
			}
			if !known {
				return "", nil, false, false
			}
		case dir == "":
			dir = a
		default:
			return "", nil, false, false
		}
	}
	return dir, set, false, dir != ""
}

func report(o Options, err error) int {
	var ce checkError
	if errors.As(err, &ce) {
		fmt.Fprintf(o.Stderr, "FAIL %s\n", ce)
	} else {
		// Never show OS error text, which can carry paths and settings.
		fmt.Fprintln(o.Stderr, "FAIL unable to inspect local configuration.")
	}
	return 1
}

// -- gluetun-auth ------------------------------------------------------------

// AuthMain is the gluetun-auth role: 0 on success (written or already there),
// 1 on a refusal, 2 on a usage error.
func AuthMain(args []string, o Options) int {
	dir, set, help, ok := parseArgs(args, "--rotate")
	switch {
	case help:
		io.WriteString(o.Stdout, AuthHelp)
		return 0
	case !ok:
		fmt.Fprintln(o.Stderr, "usage: molebridge gluetun-auth [--rotate] DIR")
		return 2
	}
	wrote, err := writeAuth(dir, set["--rotate"], o.Random)
	if err != nil {
		return report(o, err)
	}
	if wrote {
		fmt.Fprintf(o.Stdout, "Wrote %s and %s (mode 0600, key not shown); recreate gluetun and the exit container to use them.\n",
			filepath.Join(dir, "auth.toml"), filepath.Join(dir, "api_key"))
	} else {
		fmt.Fprintf(o.Stdout, "%s and api_key already exist; --rotate replaces them.\n", filepath.Join(dir, "auth.toml"))
	}
	return 0
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func isSymlink(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode()&os.ModeSymlink != 0
}

// writeAuth is Host.gluetun_auth: write gluetun's role file and the exit's
// copy of its key, both mode 0600, from one key generated here.
func writeAuth(dir string, rotate bool, random io.Reader) (bool, error) {
	keyPath, authPath := filepath.Join(dir, "api_key"), filepath.Join(dir, "auth.toml")
	haveKey, haveAuth := exists(keyPath), exists(authPath)
	if haveKey && haveAuth && !rotate {
		return false, nil
	}
	if (haveKey || haveAuth) && !rotate {
		return false, checkError(fmt.Sprintf("Only one of %s and auth.toml exists; run gluetun-auth --rotate to write both again.", keyPath))
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o777); err != nil {
		return false, err
	}
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return false, err
	}
	if isSymlink(dir) || isSymlink(keyPath) || isSymlink(authPath) {
		return false, checkError(fmt.Sprintf("%s and its files must not be symlinks.", dir))
	}
	var raw [32]byte
	if _, err := io.ReadFull(random, raw[:]); err != nil {
		return false, err
	}
	key := base64.RawURLEncoding.EncodeToString(raw[:])
	auth, err := gluetunauth.AuthFile(key, gluetunauth.DefaultRoleName)
	if err != nil {
		return false, err
	}
	for _, f := range []struct{ path, text string }{{keyPath, key + "\n"}, {authPath, auth}} {
		if err := privfile.Write(f.path, []byte(f.text), 0o600); err != nil {
			return false, err
		}
	}
	return true, nil
}

// -- gluetun-post-rules ------------------------------------------------------

// settingDefaults are the gluetun backend's host-side settings with the defaults
// compose.gluetun.yaml gives them; OVERLAY_CIDR has none.
var settingDefaults = map[string]string{
	"OVERLAY_CIDR": "", "OVERLAY6_CIDR": "", "OVERLAY_IF": "wt0", "EXIT_IF": "wg0",
	"EXIT_TABLE": "51821", "HOST_IF": "eth0", "HOST_TABLE": "51822",
	"CONTROL_MARK": "0x1bd00", "NB_WIREGUARD_PORT": "51820",
}

var portRE = regexp.MustCompile(`^[1-9][0-9]{0,4}$`)

const invalidSettings = "Invalid gluetun routing settings; check OVERLAY_CIDR, CONTROL_MARK, HOST_IF, EXIT_IF, " +
	"EXIT_TABLE, HOST_TABLE and NB_WIREGUARD_PORT in the environment passed with -e or --env-file (docs/configuration.md)."

// RenderPostRules validates the settings as the exit does and renders the
// file (Host.gluetun_post_rules up to the write).
func RenderPostRules(env map[string]string, ipv6 bool) (string, error) {
	settings := map[string]string{}
	for name, def := range settingDefaults {
		if v := env[name]; v != "" {
			settings[name] = v
		} else {
			settings[name] = def
		}
	}
	settings["TUNNEL_BACKEND"] = "gluetun"
	config, err := contract.ConfigFromEnv(func(name string) string { return settings[name] })
	if err != nil {
		return "", checkError(invalidSettings)
	}
	port := settings["NB_WIREGUARD_PORT"]
	if !portRE.MatchString(port) {
		return "", checkError(invalidSettings)
	}
	n, _ := strconv.Atoi(port)
	text, err := contract.RenderPostRules(config, n, ipv6)
	if err != nil {
		return "", checkError(invalidSettings)
	}
	return text, nil
}

// PostRulesMain is the gluetun-post-rules role.
func PostRulesMain(args []string, o Options) int {
	dir, set, help, ok := parseArgs(args, "--ipv4-only")
	switch {
	case help:
		io.WriteString(o.Stdout, PostRulesHelp)
		return 0
	case !ok:
		fmt.Fprintln(o.Stderr, "usage: molebridge gluetun-post-rules [--ipv4-only] DIR")
		return 2
	}
	text, err := RenderPostRules(o.Env, !set["--ipv4-only"])
	if err != nil {
		return report(o, err)
	}
	path := filepath.Join(dir, "post-rules.txt")
	if err := os.MkdirAll(dir, 0o777); err != nil {
		return report(o, err)
	}
	if info, err := os.Lstat(path); isSymlink(path) || isSymlink(dir) || (err == nil && !info.Mode().IsRegular()) {
		return report(o, checkError(path+" must be a regular file; remove what is there."))
	}
	if err := privfile.Write(path, []byte(text), 0o644); err != nil {
		return report(o, err)
	}
	fmt.Fprintf(o.Stdout, "Wrote %s; recreate gluetun to apply it.\n", path)
	return 0
}
