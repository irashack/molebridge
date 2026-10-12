//go:build linux

package exit

import (
	"fmt"
	"io"

	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/tunnel"
)

// RunCleanup is `molebridge exit --cleanup --backend <native|gluetun> --kind
// <overlay|sidecar>`: the executor the supervisor runs, independent of the
// failed worker, after the worker is gone. Native cleanup deletes Molebridge's
// tunnel link and NetBird's overlay link (a kernel WireGuard interface can
// keep forwarding in a namespace another container holds); gluetun cleanup
// deletes only the overlay link and never gluetun's tunnel, which is not ours.
// Every rule and the unreachable fallback stay in place in both. A sidecar
// owns neither link and does nothing. It changes nothing else and is bounded
// by the supervisor, which kills it past its time.
func RunCleanup(args []string, env map[string]string, stderr io.Writer) int {
	var backend, kind string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--backend", "--kind":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, prefix+"usage: exit --cleanup --backend <native|gluetun> --kind <overlay|sidecar>")
				return 2
			}
			if args[i] == "--backend" {
				backend = args[i+1]
			} else {
				kind = args[i+1]
			}
			i++
		default:
			fmt.Fprintln(stderr, prefix+"usage: exit --cleanup --backend <native|gluetun> --kind <overlay|sidecar>")
			return 2
		}
	}
	if (backend != "native" && backend != "gluetun") || (kind != "overlay" && kind != "sidecar") {
		fmt.Fprintln(stderr, prefix+"usage: exit --cleanup --backend <native|gluetun> --kind <overlay|sidecar>")
		return 2
	}
	if kind == "sidecar" {
		fmt.Fprintln(stderr, prefix+"cleanup: a sidecar owns no interface; nothing to remove")
		return 0
	}
	exitDefault := contract.DefaultExitIf
	b := contract.Native
	if backend == "gluetun" {
		exitDefault, b = "wg0", contract.Gluetun
	}
	exitIf, overlayIf := orDefault(env["EXIT_IF"], exitDefault), orDefault(env["OVERLAY_IF"], orDefault(env["NB_INTERFACE_NAME"], contract.DefaultOverlayIf))
	if !contract.ValidInterfaceName(exitIf) || !contract.ValidInterfaceName(overlayIf) || exitIf == overlayIf {
		fmt.Fprintln(stderr, prefix+"cleanup: invalid interface names")
		return 1
	}
	m, err := tunnel.Open(tunnel.Options{})
	if err != nil {
		fmt.Fprintf(stderr, prefix+"cleanup: %v\n", err)
		return 1
	}
	defer m.Close()
	if err := m.Cleanup(b, exitIf, overlayIf); err != nil {
		fmt.Fprintf(stderr, prefix+"cleanup: %v\n", err)
		return 1
	}
	fmt.Fprintf(stderr, prefix+"cleanup: the interfaces this exit owns are removed; the routing guards stay in place\n")
	return 0
}
