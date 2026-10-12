package exit

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/nbprofile"
	"github.com/irashack/molebridge/internal/providers"
	"github.com/irashack/molebridge/internal/tunnelconf"
)

// Defaults of the paths.
const (
	DefaultStateDir = "/state"
	DefaultConfDir  = "/config/wg_confs"
	DefaultRunDir   = "/run"
	// DefaultNetBirdLog is the default of NB_LOG_FILE the image's NetBird
	// entrypoint set; /var/log/netbird is a tmpfs.
	DefaultNetBirdLog = "console,/var/log/netbird/client.log"
	// DefaultGrace is GUARD_GRACE and FWMARK_GRACE when unset.
	DefaultGrace = 30 * time.Second
)

// Refusal is a start-time refusal: Line is the whole line the program prints
// (to stderr, exit status 1) and carries nothing read from a secret file.
type Refusal struct{ Line string }

func (r *Refusal) Error() string { return r.Line }

// prefix is what molebridge-exit's fail() printed before its message.
const prefix = "molebridge-exit: "

func refuse(format string, a ...any) error {
	return &Refusal{Line: prefix + fmt.Sprintf(format, a...)}
}

// verbatim wraps a refusal that carries its own frame (the NetBird gate's).
func verbatim(err error) error {
	if err == nil {
		return nil
	}
	var r *Refusal
	if errors.As(err, &r) {
		return err
	}
	return &Refusal{Line: err.Error()}
}

// Settings is the exit's validated configuration.
type Settings struct {
	// Routing is the routing contract's configuration (internal/contract).
	Routing contract.Config
	// Provider is the PROVIDER setting.
	Provider string
	// Interval is ROUTING_RECONCILE_INTERVAL.
	Interval time.Duration
	// Grace is GUARD_GRACE: the lease length (5..30 seconds).
	Grace time.Duration
	// FwmarkGrace is FWMARK_GRACE, gluetun overlay exits only.
	FwmarkGrace time.Duration
	// StateDir is STATE_DIR; ConfDir the tunnel config directory; RunDir the
	// tmpfs for the supervisor's runtime files.
	StateDir, ConfDir, RunDir string
	// Server is the SERVER setting.
	Server string
	// Conf is the native backend's validated tunnel config.
	Conf *tunnelconf.Conf
	// NB are NetBird's validated settings (overlay kinds only).
	NB nbprofile.Settings
	// NBPaths locate the stored NetBird profile.
	NBPaths nbprofile.Paths
	// NoIdentity: no NetBird identity was found, so NetBird will enroll a new
	// peer (the worker says so before it asks for NetBird to start).
	NoIdentity bool
	// OtherConfs counts .conf files in the tunnel directory besides the exit's.
	OtherConfs int
	// WatchLog is the NetBird log file the gluetun log monitor reads.
	WatchLog string
	// Env is the environment the settings were read from. It holds secrets
	// (NB_SETUP_KEY and the pipeline's): it is never printed or logged.
	Env map[string]string
}

// Native reports a native-backend overlay exit.
func (s *Settings) Native() bool {
	return s.Routing.Kind == contract.Overlay && s.Routing.Backend == contract.Native
}

// Overlay reports an exit with an overlay (a NetBird child), natively or not.
func (s *Settings) Overlay() bool { return s.Routing.Kind == contract.Overlay }

// Kind is "overlay" or "sidecar" and BackendName "native" or "gluetun", as the
// status record and the cleanup argument name them.
func (s *Settings) Kind() string { return string(s.Routing.Kind) }

// BackendName is "native" or "gluetun".
func (s *Settings) BackendName() string {
	if s.Routing.IsGluetun() {
		return "gluetun"
	}
	return "native"
}

// PathHeartbeat is the worker's heartbeat file on the tmpfs.
func (s *Settings) PathHeartbeat() string { return filepath.Join(s.RunDir, "molebridge", "heartbeat") }

// PathLease is the small file the supervisor exposes its lease state in.
func (s *Settings) PathLease() string { return filepath.Join(s.RunDir, "molebridge", "lease.json") }

// PathResult is the status record the supervisor publishes.
func (s *Settings) PathResult() string { return filepath.Join(s.StateDir, "applier", "result.json") }

// EnvMap returns the process environment as a map.
func EnvMap(environ []string) map[string]string {
	env := make(map[string]string, len(environ))
	for _, kv := range environ {
		if k, v, ok := strings.Cut(kv, "="); ok {
			env[k] = v
		}
	}
	return env
}

// LoadOptions are the hooks tests and tools use.
type LoadOptions struct {
	// NBPaths overrides the NetBird profile locations (zero: the defaults for
	// NB_STATE_DIR).
	NBPaths nbprofile.Paths
	// WriteChecks creates the applier's state directory and probes that it can
	// be written. check-config leaves it false and changes nothing.
	WriteChecks bool
}

// aliasBackend accepts "native" for the contract's "wireguard".
func aliasBackend(get func(string) string) func(string) string {
	return func(name string) string {
		v := get(name)
		if name == "TUNNEL_BACKEND" && v == "native" {
			return string(contract.Native)
		}
		return v
	}
}

// parseGrace reads GUARD_GRACE and FWMARK_GRACE: whole seconds, 5 to 30,
// canonical decimal. The worker reports every 2 seconds, so 5 is the shortest
// grace a healthy exit always meets.
func parseGrace(name, text string) (time.Duration, error) {
	if text == "" {
		return DefaultGrace, nil
	}
	bad := refuse("%s must be 5..30 seconds", name)
	if text[0] == '0' || len(text) > 2 {
		return 0, bad
	}
	n := 0
	for i := 0; i < len(text); i++ {
		if text[i] < '0' || text[i] > '9' {
			return 0, bad
		}
		n = n*10 + int(text[i]-'0')
	}
	if n < 5 || n > 30 {
		return 0, bad
	}
	return time.Duration(n) * time.Second, nil
}

// LoadSettings validates the whole configuration, in the order the shell
// programs did (molebridge-exit, then the NetBird gate), and returns the first
// refusal. It changes nothing unless o.WriteChecks.
func LoadSettings(env map[string]string, o LoadOptions) (*Settings, error) {
	get := aliasBackend(func(name string) string { return env[name] })
	s := &Settings{Env: env}

	// TUNNEL_BACKEND is checked before the rest so the message names the
	// 0.8.0 spelling.
	if v := get("TUNNEL_BACKEND"); v != "" && v != string(contract.Native) && v != string(contract.Gluetun) {
		return nil, refuse("TUNNEL_BACKEND must be native or gluetun")
	}
	cfg, err := contract.ConfigFromEnv(get)
	if err != nil {
		return nil, refuse("%v", err)
	}
	s.Routing = cfg

	provider := get("PROVIDER")
	if provider == "" {
		provider = "mullvad"
	}
	s.Provider = provider
	spec, ok := providers.Lookup(provider)
	switch {
	case cfg.Backend == contract.Native && (!ok || spec.Backend != providers.BackendNative):
		return nil, refuse("PROVIDER must be mullvad, pia or nordvpn")
	case cfg.Backend == contract.Gluetun && !ok:
		return nil, refuse("PROVIDER must be one of: %s", strings.Join(providers.IDs(), ", "))
	case cfg.Backend == contract.Gluetun && spec.Backend != providers.BackendGluetun:
		return nil, refuse("TUNNEL_BACKEND=gluetun needs a gluetun provider (PROVIDER=gluetun-<name>)")
	}

	if s.Interval, err = contract.ReconcileInterval(get); err != nil {
		return nil, refuse("%v", err)
	}
	if s.Grace, err = parseGrace("GUARD_GRACE", get("GUARD_GRACE")); err != nil {
		return nil, err
	}
	s.StateDir = orDefault(get("STATE_DIR"), DefaultStateDir)
	s.ConfDir = orDefault(get("TUNNEL_CONF_DIR"), DefaultConfDir)
	s.RunDir = orDefault(get("MOLEBRIDGE_RUN_DIR"), DefaultRunDir)
	s.Server = get("SERVER")

	if s.Native() {
		pv := tunnelconf.Provider(provider)
		conf, err := tunnelconf.Load(s.ConfDir, cfg.ExitIf, pv, cfg.Table)
		if err != nil {
			return nil, refuse("%s", err.Error())
		}
		s.Conf = conf
		s.OtherConfs = tunnelconf.OtherConfs(s.ConfDir, cfg.ExitIf)
	}

	if cfg.Kind == contract.Overlay {
		// NetBird creates the interface the contract guards; the two names
		// are one setting in compose.yaml and must stay one.
		// (An empty NB_INTERFACE_NAME is NetBird settings' refusal below.)
		if name, set := env["NB_INTERFACE_NAME"]; !set || name != "" {
			if name == "" {
				name = contract.DefaultOverlayIf
			}
			if name != cfg.OverlayIf {
				return nil, refuse("NB_INTERFACE_NAME (%s) must equal OVERLAY_IF (%s), the interface the routing contract guards", name, cfg.OverlayIf)
			}
		}
		paths := o.NBPaths
		backend := nbprofile.BackendWireGuard
		if cfg.IsGluetun() {
			backend = nbprofile.BackendGluetun
		}
		// The environment the gate saw: the routing settings' defaults for the
		// interface names.
		nbEnv := withDefaults(env, map[string]string{"EXIT_IF": cfg.ExitIf})
		nb, err := nbprofile.CheckAll(nbEnv, backend, paths)
		if err != nil {
			return nil, verbatim(err)
		}
		s.NB = nb
		if paths.StateDir == "" {
			paths = nbprofile.DefaultPaths(nb.StateDir)
		}
		s.NBPaths = paths
		res, err := nbprofile.CheckBlacklist(paths, cfg.ExitIf)
		if err != nil {
			return nil, verbatim(err)
		}
		s.NoIdentity = res.NoIdentity
		if cfg.IsGluetun() {
			s.FwmarkGrace = nb.FwmarkGrace
			s.WatchLog = nb.WatchLog
		}
	}
	if err := checkStateDir(s.StateDir, o.WriteChecks); err != nil {
		return nil, err
	}
	return s, nil
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func withDefaults(env map[string]string, defaults map[string]string) map[string]string {
	out := make(map[string]string, len(env)+len(defaults))
	for k, v := range env {
		out[k] = v
	}
	for k, v := range defaults {
		if out[k] == "" {
			out[k] = v
		}
	}
	return out
}

// checkStateDir verifies the state directory the exit publishes into:
// <STATE_DIR>/applier must exist as a directory the process can write. With
// create, a missing directory is made and a file is created and removed as a
// probe; without it, access(2) alone answers and nothing changes.
func checkStateDir(stateDir string, create bool) error {
	dir := filepath.Join(stateDir, "applier")
	hint := " (on Docker the container needs DAC_OVERRIDE; see docs/setup.md)"
	fi, err := os.Stat(dir)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return refuse("the state directory %s can't be read%s", dir, hint)
		}
		if !create {
			return refuse("the state directory %s is missing; mount the state volume (docs/setup.md)", dir)
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return refuse("the state directory %s is missing and can't be created%s", dir, hint)
		}
	} else if !fi.IsDir() {
		return refuse("the state directory %s is not a directory", dir)
	}
	if !create {
		if err := syscall.Access(dir, 2); err != nil {
			return refuse("the state directory %s is not writable%s", dir, hint)
		}
		return nil
	}
	f, err := os.CreateTemp(dir, ".probe-*")
	if err != nil {
		return refuse("the state directory %s is not writable%s", dir, hint)
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return nil
}

// ChildEnvNetBird is the environment the NetBird processes get: NB_* and WT_*
// variables, PATH, HOME, TZ and TMPDIR, with NB_LOG_FILE's default filled in.
// Pipeline secrets (the Gatus token, PIA's files) never reach NetBird.
func ChildEnvNetBird(env map[string]string, tmpDir string) []string {
	out := map[string]string{}
	for k, v := range env {
		if strings.HasPrefix(k, "NB_") || strings.HasPrefix(k, "WT_") {
			out[k] = v
		}
	}
	for _, k := range []string{"PATH", "HOME", "TZ"} {
		if v, ok := env[k]; ok {
			out[k] = v
		}
	}
	if out["PATH"] == "" {
		out["PATH"] = "/usr/local/bin:/usr/bin:/bin"
	}
	if out["NB_LOG_FILE"] == "" {
		out["NB_LOG_FILE"] = DefaultNetBirdLog
	}
	out["TMPDIR"] = tmpDir
	return flatten(out)
}

// WorkerEnv is the supervisor's environment less NetBird's setup key, which
// only the NetBird children need.
func WorkerEnv(env map[string]string) []string {
	out := map[string]string{}
	for k, v := range env {
		switch k {
		case "NB_SETUP_KEY", "WT_SETUP_KEY":
			continue
		}
		out[k] = v
	}
	return flatten(out)
}

func flatten(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+m[k])
	}
	return out
}
