package nbprofile

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Backends. "native" is accepted for "wireguard": the plan's repair-tool
// command lines (D25) say TUNNEL_BACKEND=<native|gluetun>, the 0.7.x gate
// said wireguard.
const (
	BackendWireGuard = "wireguard"
	BackendGluetun   = "gluetun"
)

// Settings is what the gate parsed from the environment.
type Settings struct {
	// OverlayIF is NB_INTERFACE_NAME (default wt0).
	OverlayIF string
	// Backend is BackendWireGuard or BackendGluetun.
	Backend string
	// TunnelIF is EXIT_IF: default mullvad with the native backend, wg0 with
	// gluetun (the gate's defaults). The blacklist check (D25) wants it.
	TunnelIF string
	// StateDir is NB_STATE_DIR (default /var/lib/netbird).
	StateDir string
	// ControlMark is CONTROL_MARK, gluetun only.
	ControlMark uint32
	// FwmarkGrace is FWMARK_GRACE (5..30 seconds, default 30), gluetun only.
	FwmarkGrace time.Duration
	// GuardGrace is GUARD_GRACE (5..30 seconds, default 30), native only.
	GuardGrace time.Duration
	// WatchLog is the first absolute path in NB_LOG_FILE, gluetun only: the
	// log the gate reads.
	WatchLog string
}

// Go's strconv.ParseBool true values, used by the switches NetBird parses
// that way (client/firewall/create_linux.go:231-239,
// client/firewall/uspfilter/filter.go:512-519, and pflag for `netbird up`).
func truthy(s string) bool {
	switch s {
	case "1", "t", "T", "TRUE", "true", "True":
		return true
	}
	return false
}

type envView map[string]string

// get is `${NAME:-}`: unset and empty alike read as "".
func (e envView) get(name string) string { return e[name] }

// def is `${NAME:-fallback}`: unset or empty gives the fallback.
func (e envView) def(name, fallback string) string {
	if v := e[name]; v != "" {
		return v
	}
	return fallback
}

// isSet is `[ -n "${NAME+set}" ]`: set, even if empty.
func (e envView) isSet(name string) bool {
	_, ok := e[name]
	return ok
}

// ValidInterfaceName is the gate's and the guard's interface-name rule
// (routing/contract-rules, gr_valid_if): letters, digits and underscores to
// start, then also dots and hyphens, at most 15 bytes.
func ValidInterfaceName(name string) bool {
	if name == "" || len(name) > 15 {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		alnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
		if !alnum && (i == 0 || (c != '.' && c != '-')) {
			return false
		}
	}
	return true
}

func checkTunnelName(name string) error {
	if !ValidInterfaceName(name) {
		return refuse("the tunnel interface name is invalid (EXIT_IF)")
	}
	return nil
}

// checkCommon runs the gate's settings refusals that apply to both backends
// (routing/wait-for-guards:30-110), in the gate's order.
func checkCommon(e envView, backend string) (Settings, error) {
	var s Settings
	s.OverlayIF = e.def("NB_INTERFACE_NAME", "wt0")
	if !ValidInterfaceName(s.OverlayIF) {
		// The gate printed this line for a malformed name and exited silently
		// for one over 15 bytes; both now print it.
		return s, refuseBare("NetBird gate: invalid interface name")
	}
	if backend == "" {
		backend = e.def("TUNNEL_BACKEND", BackendWireGuard)
	}
	switch backend {
	case BackendWireGuard, "native":
		s.Backend = BackendWireGuard
	case BackendGluetun:
		s.Backend = BackendGluetun
	default:
		return s, refuseBare("NetBird gate: TUNNEL_BACKEND must be wireguard or gluetun")
	}
	s.StateDir = e.def("NB_STATE_DIR", DefaultStateDir)
	s.TunnelIF = e.def("EXIT_IF", map[string]string{BackendWireGuard: "mullvad", BackendGluetun: "wg0"}[s.Backend])

	// Supported runtime settings: kernel WireGuard and NetBird's kernel
	// firewall (client/iface/netstack/env.go:14,33-35;
	// client/iface/device/kernel_module_linux.go:37,89-92).
	kernelNeeded := "Molebridge needs kernel WireGuard and NetBird's kernel firewall"
	for _, name := range []string{"NB_FORCE_USERSPACE_FIREWALL", "NB_FORCE_USERSPACE_ROUTER"} {
		if err := mustBeOff(e, name, kernelNeeded); err != nil {
			return s, err
		}
	}
	// NetBird enables these two only on the exact value "true".
	for _, name := range []string{"NB_USE_NETSTACK_MODE", "NB_WG_KERNEL_DISABLED"} {
		if e.get(name) == "true" {
			return s, refuse(fmt.Sprintf("%s is set; %s", name, kernelNeeded))
		}
	}
	// compose.yaml sets this; it is part of the supported configuration.
	if !truthy(e.get("NB_DISABLE_USERSPACE_ROUTING")) {
		return s, refuse(`NB_DISABLE_USERSPACE_ROUTING must be "true" (compose.yaml sets it)`)
	}
	// Rosenpass is not supported on the exit: its key exchange needs local
	// delivery from the overlay. `netbird up` reads NB_ENABLE_ROSENPASS and
	// the older WT_ name (client/cmd/root.go:220,245-267;
	// client/cmd/up.go:99-100).
	for _, name := range []string{"NB_ENABLE_ROSENPASS", "WT_ENABLE_ROSENPASS"} {
		if err := mustBeOff(e, name, "Rosenpass cannot work on this exit"); err != nil {
			return s, err
		}
	}
	// Foreground mode runs NetBird inside `netbird up`, with the profile
	// chosen there instead of the daemon's (client/cmd/up.go:72,99-100,
	// 143-150,203-240).
	for _, name := range []string{"NB_FOREGROUND_MODE", "WT_FOREGROUND_MODE"} {
		if err := mustBeOff(e, name, "Molebridge supports only NetBird's daemon mode"); err != nil {
			return s, err
		}
	}
	// `netbird up` takes the interface name from NB_INTERFACE_NAME, and from
	// WT_INTERFACE_NAME when NB_ is unset (client/cmd/up.go:73,
	// client/cmd/root.go:245-267). Both must name the guarded interface.
	if e.isSet("NB_INTERFACE_NAME") && e.get("NB_INTERFACE_NAME") == "" {
		return s, refuse("NB_INTERFACE_NAME is empty")
	}
	if e.isSet("WT_INTERFACE_NAME") && e.get("WT_INTERFACE_NAME") != s.OverlayIF {
		return s, refuse(fmt.Sprintf("WT_INTERFACE_NAME is set and differs from the guarded interface %s", s.OverlayIF))
	}
	// Only NetBird's default profile, at its default location, is supported:
	// NB_CONFIG and WT_CONFIG move it (client/cmd/root.go:168,245-267);
	// NB_PROFILE and WT_PROFILE make `netbird up` switch to another
	// (client/cmd/up.go:93,99-100,136-141).
	for _, name := range []string{"NB_CONFIG", "WT_CONFIG", "NB_PROFILE", "WT_PROFILE"} {
		if e.isSet(name) {
			return s, refuse(name + " is set; Molebridge supports only NetBird's default profile")
		}
	}
	return s, nil
}

func mustBeOff(e envView, name, why string) error {
	if truthy(e.get(name)) {
		return refuse(fmt.Sprintf("%s is set; %s", name, why))
	}
	return nil
}

// checkBackend runs the refusals that follow the profile checks in the gate
// (routing/wait-for-guards:356-375 for gluetun, the grace for native).
func checkBackend(e envView, s *Settings) error {
	if s.Backend == BackendGluetun {
		return checkGluetun(e, s)
	}
	grace, err := parseGrace(e.def("GUARD_GRACE", "30"), "GUARD_GRACE")
	s.GuardGrace = grace
	return err
}

func checkGluetun(e envView, s *Settings) error {
	// Rules 88 and 89 send NetBird's control traffic to the host table by its
	// socket mark; an unmarked socket falls through to gluetun's rule 101 and
	// into the provider tunnel. NetBird marks its sockets only with advanced
	// routing, which these switch off (client/net/env_linux.go:34-73,
	// client/net/env.go:12-35; netstack mode is refused above).
	unmarked := "the gluetun backend needs NetBird to mark its control traffic"
	for _, name := range []string{"NB_USE_LEGACY_ROUTING", "NB_SKIP_SOCKET_MARK", "NB_DISABLE_CUSTOM_ROUTING"} {
		if err := mustBeOff(e, name, unmarked); err != nil {
			return err
		}
	}
	mark := e.def("CONTROL_MARK", "0x1bd00")
	mask, err := parseControlMark(mark)
	if err != nil {
		return err
	}
	s.ControlMark = mask
	// NetBird moves its whole mark range with NB_FWMARK_BASE and treats an
	// empty value as unset (client/net/fwmark.go:17-21,75-110). Require the
	// exact text, so no parsing difference can separate the two.
	if e.def("NB_FWMARK_BASE", "0x1bd00") != mark {
		return refuse(fmt.Sprintf("NB_FWMARK_BASE must equal CONTROL_MARK (%s)", mark))
	}
	// NetBird writes its log to the files in NB_LOG_FILE as well as the
	// console (the image's entrypoint sets this default). The gate reads the
	// first absolute path.
	for _, entry := range strings.Split(e.def("NB_LOG_FILE", "console,/var/log/netbird/client.log"), ",") {
		if strings.HasPrefix(entry, "/") {
			s.WatchLog = entry
			break
		}
	}
	if s.WatchLog == "" {
		return refuse("NB_LOG_FILE must name a log file; the gate reads it")
	}
	grace, err := parseGrace(e.def("FWMARK_GRACE", "30"), "FWMARK_GRACE")
	s.FwmarkGrace = grace
	return err
}

// parseControlMark is the gate's `case` on CONTROL_MARK: lowercase hexadecimal
// with the 0x prefix, a non-zero first digit, low byte zero, 32 bits.
func parseControlMark(mark string) (uint32, error) {
	const hexOnly = "CONTROL_MARK must be lowercase hexadecimal like 0x1bd00"
	if strings.HasPrefix(mark, "0x") {
		digits := mark[2:]
		for i := 0; i < len(digits); i++ {
			if c := digits[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return 0, refuse(hexOnly)
			}
		}
		if len(digits) >= 3 && digits[0] != '0' && strings.HasSuffix(digits, "00") {
			if len(mark) > 10 {
				return 0, refuse("CONTROL_MARK must fit in 32 bits")
			}
			v, err := strconv.ParseUint(digits, 16, 32)
			if err != nil {
				return 0, refuse("CONTROL_MARK must fit in 32 bits")
			}
			return uint32(v), nil
		}
	}
	return 0, refuse(hexOnly + ", low byte zero")
}

// parseGrace reads a grace period in whole seconds, 5 to 30, canonical
// decimal: the guard rewrites its record every 2 seconds and the gate reads
// it every 2, so 5 is the shortest grace a healthy exit always meets.
func parseGrace(text, name string) (time.Duration, error) {
	bad := refuse(name + " must be 5..30 seconds")
	if text == "" || text[0] == '0' || len(text) > 2 {
		return 0, bad
	}
	for i := 0; i < len(text); i++ {
		if text[i] < '0' || text[i] > '9' {
			return 0, bad
		}
	}
	n, _ := strconv.Atoi(text)
	if n < 5 || n > 30 {
		return 0, bad
	}
	return time.Duration(n) * time.Second, nil
}

// CheckEnv applies every settings refusal of the gate to env, for backend
// "wireguard" (or "native") or "gluetun"; an empty backend reads
// TUNNEL_BACKEND, default wireguard. It reads no file. Switches NetBird parses
// with Go's strconv.ParseBool refuse on that truth set; NB_USE_NETSTACK_MODE
// and NB_WG_KERNEL_DISABLED refuse only on the exact text "true", as NetBird
// enables them. The routing contract's own settings (overlay and exit
// tables, CIDRs, HOST_IF and the rest of gr_validate) belong to the routing
// code, not here.
func CheckEnv(env map[string]string, backend string) (Settings, error) {
	e := envView(env)
	s, err := checkCommon(e, backend)
	if err != nil {
		return s, err
	}
	return s, checkBackend(e, &s)
}

// CheckAll is the gate's whole configuration check, in its order: the common
// settings, the stored profiles (the active-profile state, the default
// profile and the legacy files), then the backend's settings. paths names the
// state directory and legacy files; the zero Paths means DefaultPaths of
// NB_STATE_DIR.
func CheckAll(env map[string]string, backend string, paths Paths) (Settings, error) {
	e := envView(env)
	s, err := checkCommon(e, backend)
	if err != nil {
		return s, err
	}
	if paths.StateDir == "" {
		paths = DefaultPaths(s.StateDir)
	}
	if err := CheckProfiles(paths, s.OverlayIF); err != nil {
		return s, err
	}
	return s, checkBackend(e, &s)
}

// TunnelFromEnv reads the three settings the repair tool needs to resolve the
// profile the daemon will load and the tunnel interface it must exclude:
// TUNNEL_BACKEND (wireguard or native; gluetun), EXIT_IF (default mullvad, or
// wg0 with gluetun) and NB_STATE_DIR. It applies none of the other refusals:
// the repair container does not carry NetBird's own environment.
func TunnelFromEnv(env map[string]string) (backend, tunnelIF, stateDir string, err error) {
	e := envView(env)
	switch b := e.def("TUNNEL_BACKEND", BackendWireGuard); b {
	case BackendWireGuard, "native":
		backend = BackendWireGuard
	case BackendGluetun:
		backend = BackendGluetun
	default:
		return "", "", "", refuseBare("NetBird gate: TUNNEL_BACKEND must be wireguard or gluetun")
	}
	def := "mullvad"
	if backend == BackendGluetun {
		def = "wg0"
	}
	tunnelIF = e.def("EXIT_IF", def)
	if err := checkTunnelName(tunnelIF); err != nil {
		return "", "", "", err
	}
	return backend, tunnelIF, e.def("NB_STATE_DIR", DefaultStateDir), nil
}
