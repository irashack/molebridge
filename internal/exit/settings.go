package exit

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/irashack/molebridge/internal/applier"
	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/failover"
	"github.com/irashack/molebridge/internal/nbprofile"
	"github.com/irashack/molebridge/internal/providers"
	"github.com/irashack/molebridge/internal/state"
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
	// Provider is the PROVIDER setting: on a multi-provider exit, the
	// provider the tunnel starts on the first time.
	Provider string
	// Providers is the PROVIDERS setting: two or three native providers on a
	// multi-provider exit (docs/design/multi-provider.md), nil otherwise.
	Providers []string
	// StartProvider is the provider the tunnel starts on: Provider, or on a
	// multi-provider exit the active provider tunnel-provider.json names
	// when the settings were loaded (Provider when it names none).
	StartProvider string
	// Interval is ROUTING_RECONCILE_INTERVAL.
	Interval time.Duration
	// Grace is GUARD_GRACE: the lease length (5..30 seconds).
	Grace time.Duration
	// FwmarkGrace is FWMARK_GRACE, gluetun overlay exits only.
	FwmarkGrace time.Duration
	// StateDir is STATE_DIR; ConfDir the tunnel config directory; RunDir the
	// tmpfs for the supervisor's runtime files.
	StateDir, ConfDir, RunDir string
	// PrivateDir is PRIVATE_STATE_DIR: where the files only the exit reads
	// live. Empty means <STATE_DIR>/applier.
	PrivateDir string
	// StateGID is STATE_GID, -1 when unset: the group that may read the
	// published files in <STATE_DIR>/applier (the directory 0750, the files
	// 0640, both with that group), for readers that run as another user.
	StateGID int
	// Server is the SERVER setting.
	Server string
	// Failover is FAILOVER, FAILOVER_SERVERS, FAILOVER_AFTER and
	// FAILOVER_RETURN (docs/design/failover.md); off by default.
	Failover failover.Config
	// Conf is the native backend's validated tunnel config; nil on a
	// multi-provider exit, which has Confs.
	Conf *tunnelconf.Conf
	// Confs are a multi-provider exit's validated tunnel configs, one per
	// provider (<provider>.conf), nil otherwise.
	Confs map[string]*tunnelconf.Conf
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
	// Exchange is the network exchange's settings; nil means files only.
	Exchange *ExchangeSettings
	// Env is the environment the settings were read from. It holds secrets
	// (NB_SETUP_KEY and the pipeline's): it is never printed or logged.
	Env map[string]string
}

// MultiProvider reports a multi-provider exit (PROVIDERS set).
func (s *Settings) MultiProvider() bool { return len(s.Providers) > 1 }

// ConfOf is the tunnel config of a provider: a multi-provider exit's for
// that provider, a single-provider exit's own for its provider; nil for any
// other.
func (s *Settings) ConfOf(provider string) *tunnelconf.Conf {
	if s.MultiProvider() {
		return s.Confs[provider]
	}
	if provider == s.Provider {
		return s.Conf
	}
	return nil
}

// ConfNames are the tunnel config files the exit reads, in order.
func (s *Settings) ConfNames() []string {
	if s.MultiProvider() {
		names := make([]string, len(s.Providers))
		for i, id := range s.Providers {
			names[i] = id + ".conf"
		}
		return names
	}
	return []string{s.Routing.ExitIf + ".conf"}
}

// Native reports a native-backend overlay exit.
func (s *Settings) Native() bool {
	return s.Routing.Kind == contract.Overlay && s.Routing.Backend == contract.Native
}

// Overlay reports an exit with an overlay (a NetBird child), natively or not.
func (s *Settings) Overlay() bool { return s.Routing.Kind == contract.Overlay }

// NativeTunnel reports an exit that owns its tunnel: the native backend, as an
// overlay exit or as a native sidecar.
func (s *Settings) NativeTunnel() bool { return s.Routing.Backend == contract.Native }

// HasContract reports an exit that installs and repairs a routing contract:
// every overlay exit and the native sidecar. The gluetun sidecar has none.
func (s *Settings) HasContract() bool { return s.Overlay() || s.Routing.IsNativeSidecar() }

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

// RunDirOf is the runtime directory an environment names.
func RunDirOf(env map[string]string) string {
	return orDefault(env["MOLEBRIDGE_RUN_DIR"], DefaultRunDir)
}

// HeartbeatPathOf is the heartbeat file of an environment's runtime directory.
func HeartbeatPathOf(env map[string]string) string {
	return filepath.Join(RunDirOf(env), "molebridge", "heartbeat")
}

// GuardedPathOf is the native sidecar's guard heartbeat in an environment's
// runtime directory: written while its firewall and routing contract hold,
// whether or not the tunnel is up (`molebridge health --guarded`).
func GuardedPathOf(env map[string]string) string {
	return filepath.Join(RunDirOf(env), "molebridge", "guarded")
}

// LeasePathOf is the lease state file of an environment's runtime directory.
func LeasePathOf(env map[string]string) string {
	return filepath.Join(RunDirOf(env), "molebridge", "lease.json")
}

// PathHeartbeat is the worker's heartbeat file on the tmpfs.
func (s *Settings) PathHeartbeat() string { return filepath.Join(s.RunDir, "molebridge", "heartbeat") }

// PathGuarded is the native sidecar's guard heartbeat on the tmpfs.
func (s *Settings) PathGuarded() string { return filepath.Join(s.RunDir, "molebridge", "guarded") }

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
	// NeedNetBird refuses a NetBird exit when the image has no NetBird client
	// (molebridge-core), before anything changes. Tests leave it false.
	NeedNetBird bool
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
	if list := env["PROVIDERS"]; list != "" {
		ids, err := parseProviders(list, get)
		if err != nil {
			return nil, err
		}
		s.Providers = ids
		if env["EXIT_IF"] == "" {
			// The one interface name every provider's tunnel uses; the
			// single-provider default (mullvad) would mislead. Filled into
			// the environment itself, so the contract, NetBird's gate and
			// the cleanup child all see the same name.
			env = withDefaults(env, map[string]string{"EXIT_IF": DefaultMultiExitIf})
			s.Env = env
			get = aliasBackend(func(name string) string { return env[name] })
		}
	}
	// The image without NetBird says so before any other setting: EXIT_KIND
	// unset is a NetBird exit too.
	if kind := get("EXIT_KIND"); (kind == "" || kind == string(contract.Overlay)) && o.NeedNetBird {
		if err := needNetBird(env); err != nil {
			return nil, err
		}
	}
	cfg, err := contract.ConfigFromEnv(get)
	if err != nil {
		return nil, refuse("%v", err)
	}
	s.Routing = cfg

	provider := get("PROVIDER")
	if s.MultiProvider() {
		if provider == "" {
			return nil, refuse("PROVIDER is required with PROVIDERS: the provider the tunnel starts on the first time")
		}
		if !contains(s.Providers, provider) {
			return nil, refuse("PROVIDER must be one of PROVIDERS")
		}
	}
	if provider == "" {
		provider = "mullvad"
	}
	s.Provider = provider
	s.StartProvider = provider
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
	if s.StateGID, err = parseStateGID(get("STATE_GID")); err != nil {
		return nil, err
	}
	if dir := get("PRIVATE_STATE_DIR"); dir != "" {
		if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
			return nil, refuse("PRIVATE_STATE_DIR must be an absolute path without . or .. elements or a trailing slash")
		}
		if dir == filepath.Join(s.StateDir, "panel") || strings.HasPrefix(dir, filepath.Join(s.StateDir, "panel")+"/") {
			return nil, refuse("PRIVATE_STATE_DIR must not be under %s, the panel's directory", filepath.Join(s.StateDir, "panel"))
		}
		if applierDir := filepath.Join(s.StateDir, "applier"); strings.HasPrefix(dir, applierDir+"/") {
			return nil, refuse("PRIVATE_STATE_DIR must not be under %s, where the exit publishes", applierDir)
		} else if dir != applierDir {
			s.PrivateDir = dir
		}
	}

	if s.MultiProvider() {
		if mode, err := failover.ParseMode(get("FAILOVER")); err == nil && (failover.Config{Mode: mode}).On() {
			// Failover stays within one provider (the design's decision 7)
			// and is built for single-provider exits only.
			return nil, refuse("FAILOVER is for single-provider exits; a multi-provider exit (PROVIDERS) has none")
		}
	}
	if s.Failover, err = loadFailover(get, provider, s.Server, s.NativeTunnel()); err != nil {
		return nil, err
	}

	switch {
	case s.MultiProvider():
		// Each provider's own config, <provider>.conf, validated for its
		// provider; the interface is EXIT_IF whichever is active.
		s.Confs = map[string]*tunnelconf.Conf{}
		for _, id := range s.Providers {
			conf, err := tunnelconf.Load(s.ConfDir, id, tunnelconf.Provider(id), cfg.Table)
			if err != nil {
				return nil, refuse("%s", err.Error())
			}
			s.Confs[id] = conf
		}
		s.OtherConfs = tunnelconf.OtherConfs(s.ConfDir, s.Providers...)
		if id, ok := applier.ReadTunnelProvider(applier.TunnelProviderPath(s.StateDir, s.PrivateDir), s.Providers); ok {
			s.StartProvider = id
		}
	case s.NativeTunnel():
		pv := tunnelconf.Provider(provider)
		conf, err := tunnelconf.Load(s.ConfDir, cfg.ExitIf, pv, cfg.Table)
		if err != nil {
			return nil, refuse("%s", err.Error())
		}
		s.Conf = conf
		s.OtherConfs = tunnelconf.OtherConfs(s.ConfDir, cfg.ExitIf)
	}

	if cfg.Kind == contract.Overlay {
		if err := s.loadNetBird(env, cfg, o); err != nil {
			return nil, err
		}
	}
	if s.Exchange, err = loadExchange(env); err != nil {
		return nil, err
	}
	if s.Exchange != nil && s.MultiProvider() {
		// The exchange carries one provider's requests and catalogue; a
		// multi-provider exit's are not built yet.
		return nil, refuse("EXCHANGE_URL is not supported on a multi-provider exit (PROVIDERS) yet")
	}
	if err := checkStateDir(filepath.Join(s.StateDir, "applier"), 0o755, o.WriteChecks); err != nil {
		return nil, err
	}
	if s.StateGID >= 0 && o.WriteChecks {
		if err := shareStateDir(filepath.Join(s.StateDir, "applier"), s.StateGID); err != nil {
			return nil, err
		}
	}
	if s.PrivateDir != "" {
		if err := checkStateDir(s.PrivateDir, 0o700, o.WriteChecks); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// DefaultMultiExitIf is EXIT_IF's default on a multi-provider exit.
const DefaultMultiExitIf = "vpn"

// providersEnvMax bounds PROVIDERS: three ids, commas and some spaces.
const providersEnvMax = 64

// parseProviders reads PROVIDERS: two or three of mullvad, pia and nordvpn,
// comma-separated, no repeats, on the overlay exit with the native backend.
func parseProviders(list string, get func(string) string) ([]string, error) {
	bad := refuse("PROVIDERS must be two or three of mullvad, pia and nordvpn, comma-separated, each once")
	if get("TUNNEL_BACKEND") == string(contract.Gluetun) {
		return nil, refuse("PROVIDERS needs TUNNEL_BACKEND=native: a gluetun exit carries one provider")
	}
	if kind := get("EXIT_KIND"); kind != "" && kind != string(contract.Overlay) {
		return nil, refuse("PROVIDERS is for the overlay exit (EXIT_KIND=overlay); a sidecar carries one provider")
	}
	if len(list) > providersEnvMax {
		return nil, bad
	}
	var ids []string
	for _, part := range strings.Split(list, ",") {
		id := strings.TrimSpace(part)
		spec, ok := providers.Lookup(id)
		if ok && spec.Backend != providers.BackendNative {
			return nil, refuse("PROVIDERS takes native providers only (mullvad, pia, nordvpn), not %s", id)
		}
		if !ok || contains(ids, id) {
			return nil, bad
		}
		ids = append(ids, id)
	}
	if len(ids) < 2 || len(ids) > applier.MaxProviders {
		return nil, bad
	}
	return ids, nil
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// failoverEnvMax bounds FAILOVER_SERVERS: eight long names and commas.
const failoverEnvMax = 1024

// loadFailover reads the FAILOVER* settings. Failover is experimental and
// for the native backend only.
func loadFailover(get func(string) string, provider, server string, native bool) (failover.Config, error) {
	var c failover.Config
	var err error
	if c.Mode, err = failover.ParseMode(get("FAILOVER")); err != nil {
		return c, refuse("%v", err)
	}
	if list := get("FAILOVER_SERVERS"); list != "" {
		if len(list) > failoverEnvMax {
			return c, refuse("FAILOVER_SERVERS is too long")
		}
		for _, name := range strings.Split(list, ",") {
			c.Servers = append(c.Servers, strings.TrimSpace(name))
		}
	}
	c.After = failover.DefaultAfter
	if text := get("FAILOVER_AFTER"); text != "" {
		n, ok := seconds(text)
		if !ok {
			return c, refuse("FAILOVER_AFTER must be %d to %d seconds", int(failover.MinAfter.Seconds()), int(failover.MaxAfter.Seconds()))
		}
		c.After = time.Duration(n) * time.Second
	}
	c.Return = failover.DefaultReturn
	if v := get("FAILOVER_RETURN"); v != "" {
		c.Return = v
	}
	valid := func(name string) bool { return state.ValidServerName(name, provider) }
	if err := c.Validate(valid, server); err != nil {
		return c, refuse("%v", err)
	}
	if c.On() && !native {
		return c, refuse("FAILOVER needs TUNNEL_BACKEND=native: gluetun reconnects by itself")
	}
	return c, nil
}

// seconds parses a plain decimal of at most 4 digits, no sign or leading 0.
func seconds(text string) (int, bool) {
	if text == "" || len(text) > 4 || text[0] == '0' {
		return 0, false
	}
	n := 0
	for i := 0; i < len(text); i++ {
		if text[i] < '0' || text[i] > '9' {
			return 0, false
		}
		n = n*10 + int(text[i]-'0')
	}
	return n, true
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

// maxStateGID is the largest STATE_GID: a gid that fits a signed 32-bit int,
// as chown(2) takes it on every platform Go builds the exit for.
const maxStateGID = 1<<31 - 1

// parseStateGID is STATE_GID: empty is -1 (unset), otherwise a group id in
// canonical decimal, 0 to maxStateGID.
func parseStateGID(v string) (int, error) {
	if v == "" {
		return -1, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 || n > maxStateGID || strconv.Itoa(n) != v {
		return -1, refuse("STATE_GID must be a group id, a whole number from 0 to %d", maxStateGID)
	}
	return n, nil
}

// shareStateDir gives the published files in dir (<STATE_DIR>/applier) to
// group gid, for STATE_GID: the directory becomes mode 0750 with that group,
// and each regular file there that is mode 0644 or 0640 (a published file:
// result.json, relays.json, relay-error.json) becomes 0640 with that group.
// The private files (mode 0600) and anything that is not a regular file are
// left alone, and no link is followed. jsonfile.SetPublicGroup does the same
// for every file the exit publishes afterwards. Only the group gains: the
// directory stays writable by its owner alone, and the readers still only
// read.
func shareStateDir(dir string, gid int) error {
	hint := "; the exit must be a member of that group (Compose: group_add; Kubernetes: supplementalGroups) or hold CHOWN, and own the directory"
	d, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return refuse("STATE_GID %d: can't open the state directory %s: %v", gid, dir, unwrapPathError(err))
	}
	defer d.Close()
	if err := d.Chown(-1, gid); err != nil {
		return refuse("STATE_GID %d: can't give the state directory %s to group %d: %v%s", gid, dir, gid, unwrapPathError(err), hint)
	}
	if err := d.Chmod(0o750); err != nil {
		return refuse("STATE_GID %d: can't make the state directory %s mode 0750: %v%s", gid, dir, unwrapPathError(err), hint)
	}
	names, err := d.Readdirnames(-1)
	if err != nil {
		return refuse("STATE_GID %d: can't list the state directory %s: %v", gid, dir, unwrapPathError(err))
	}
	for _, name := range names {
		path := filepath.Join(dir, name)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if perm := info.Mode().Perm(); perm != 0o644 && perm != 0o640 {
			continue
		}
		f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue // replaced or removed meanwhile
			}
			return refuse("STATE_GID %d: can't open %s: %v", gid, path, unwrapPathError(err))
		}
		err = f.Chown(-1, gid)
		if err == nil {
			err = f.Chmod(0o640)
		}
		f.Close()
		if err != nil {
			return refuse("STATE_GID %d: can't give %s to group %d: %v%s", gid, path, gid, unwrapPathError(err), hint)
		}
	}
	return nil
}

// unwrapPathError is err without the *os.PathError frame, whose path the
// caller's message already names.
func unwrapPathError(err error) error {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

// checkStateDir verifies a state directory the exit writes into
// (<STATE_DIR>/applier, and PRIVATE_STATE_DIR when set): it must exist as a
// directory the process can write. With create, a missing directory is made
// with mode and a file is created and removed as a probe; without it,
// access(2) alone answers and nothing changes.
func checkStateDir(dir string, mode os.FileMode, create bool) error {
	hint := " (on Docker the container needs DAC_OVERRIDE; see docs/setup.md)"
	fi, err := os.Stat(dir)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return refuse("the state directory %s can't be read%s", dir, hint)
		}
		if !create {
			return refuse("the state directory %s is missing; mount the state volume (docs/setup.md)", dir)
		}
		if err := os.MkdirAll(dir, mode); err != nil {
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

// ChildEnvNetBird is the environment a NetBird command gets: NB_* and WT_*
// variables, PATH, HOME, TZ and TMPDIR, with NB_LOG_FILE's default filled in.
// Pipeline secrets (the Gatus token, PIA's files) never reach NetBird, and the
// enrollment secret (NB_SETUP_KEY, WT_SETUP_KEY) reaches only the command that
// enrolls: withSetupKey is true for `netbird up` alone, not for the daemon or
// the liveness probes.
func ChildEnvNetBird(env map[string]string, tmpDir string, withSetupKey bool) []string {
	out := map[string]string{}
	for k, v := range env {
		if strings.HasPrefix(k, "NB_") || strings.HasPrefix(k, "WT_") {
			if (k == "NB_SETUP_KEY" || k == "WT_SETUP_KEY") && !withSetupKey {
				continue
			}
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

// CleanupEnv is the cleanup child's environment: the names of the interfaces
// it removes and nothing else. It touches no secret and reads no file.
func CleanupEnv(env map[string]string) []string {
	out := map[string]string{}
	for _, k := range []string{"EXIT_IF", "OVERLAY_IF", "NB_INTERFACE_NAME", "TUNNEL_BACKEND", "EXIT_KIND", "TZ"} {
		if v, ok := env[k]; ok {
			out[k] = v
		}
	}
	out["PATH"] = "/usr/local/bin:/usr/bin:/bin"
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
