//go:build linux

// Command fakenetbird stands in for the netbird client in the exit's drills:
// no NetBird code runs and nothing leaves the machine. It implements the three
// commands the supervisor runs:
//
//	netbird service run        creates a kernel WireGuard interface (and an
//	                           nftables table named netbird), marks the daemon
//	                           live and waits for TERM
//	netbird status --check live  exits 0 once the daemon is live
//	netbird up                 writes a stored profile that excludes the
//	                           tunnel interface, as NetBird does on first use
//
// Behavior is steered by NB_FAKE_* variables (the supervisor passes only NB_*
// and WT_* to NetBird): NB_FAKE_DIR (marker and trace directory), NB_FAKE_MODE
// (die: exit 9 after a second; deaf: ignore TERM; existing: do not create or
// delete the interface), NB_FAKE_FWMARK (the WireGuard fwmark to set, 0x...),
// NB_FAKE_NOBLACKLIST (write a profile without the tunnel exclusion),
// NB_FAKE_LOG_AFTER and NB_FAKE_LOG_LINE (append a line to the client log
// after that many seconds). The trace file records every call with a
// timestamp, and for `service run` the rules and links at that moment.
package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/nftables"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/irashack/molebridge/internal/nbprofile"
)

func dir() string {
	d := os.Getenv("NB_FAKE_DIR")
	if d == "" {
		d = "/tmp/fakenetbird"
	}
	_ = os.MkdirAll(d, 0o755)
	return d
}

func iface() string {
	if v := os.Getenv("NB_INTERFACE_NAME"); v != "" {
		return v
	}
	return "wt0"
}

func trace(format string, a ...any) {
	f, err := os.OpenFile(filepath.Join(dir(), "trace"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%d %s\n", time.Now().UnixNano(), fmt.Sprintf(format, a...))
}

func run(name string, args ...string) string {
	out, _ := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(out))
}

func main() {
	if len(os.Args) < 2 {
		os.Exit(2)
	}
	switch os.Args[1] {
	case "service":
		service()
	case "status":
		trace("status %s", strings.Join(os.Args[2:], " "))
		if _, err := os.Stat(filepath.Join(dir(), "live")); err != nil {
			os.Exit(1)
		}
	case "up":
		up()
	default:
		os.Exit(2)
	}
}

func service() {
	mode := os.Getenv("NB_FAKE_MODE")
	trace("service run")
	// What the contract looked like when the daemon started.
	for _, f := range []string{"-4", "-6"} {
		for _, line := range strings.Split(run("ip", f, "rule", "show"), "\n") {
			trace("rule%s %s", f, strings.Join(strings.Fields(line), " "))
		}
	}
	trace("links %s", strings.Join(strings.Fields(strings.ReplaceAll(run("ip", "-o", "link", "show"), "\n", " ; ")), " "))
	name := iface()
	if mode != "existing" {
		l := &netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: name}}
		if err := netlink.LinkAdd(l); err != nil {
			trace("link add failed: %v", err)
			fmt.Fprintf(os.Stderr, "fake netbird: cannot create %s: %v\n", name, err)
			os.Exit(1)
		}
		if v := os.Getenv("NB_FAKE_FWMARK"); v != "" {
			n, err := strconv.ParseUint(strings.TrimPrefix(v, "0x"), 16, 32)
			if err == nil {
				c, err := wgctrl.New()
				if err == nil {
					key, _ := wgtypes.GeneratePrivateKey()
					mark := int(n)
					_ = c.ConfigureDevice(name, wgtypes.Config{PrivateKey: &key, FirewallMark: &mark})
					c.Close()
				}
			}
		}
		if link, err := netlink.LinkByName(name); err == nil {
			_ = netlink.LinkSetUp(link)
		}
		nc, err := nftables.New()
		if err == nil {
			t := nc.AddTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: "netbird"})
			// ListChains finds NetBird's table through its chains.
			nc.AddChain(&nftables.Chain{Name: "netbird-rt-fwd", Table: t})
			_ = nc.Flush()
		}
	}
	if err := os.WriteFile(filepath.Join(dir(), "live"), []byte("live\n"), 0o644); err != nil {
		os.Exit(1)
	}
	if mode == "die" {
		time.Sleep(time.Second)
		trace("died")
		os.Exit(9)
	}
	if after, err := strconv.Atoi(os.Getenv("NB_FAKE_LOG_AFTER")); err == nil {
		go func() {
			time.Sleep(time.Duration(after) * time.Second)
			for _, entry := range strings.Split(os.Getenv("NB_LOG_FILE"), ",") {
				if strings.HasPrefix(entry, "/") {
					f, err := os.OpenFile(entry, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
					if err == nil {
						fmt.Fprintln(f, os.Getenv("NB_FAKE_LOG_LINE"))
						f.Close()
					}
					return
				}
			}
		}()
	}
	sig := make(chan os.Signal, 1)
	if mode == "deaf" {
		signal.Ignore(syscall.SIGTERM)
	}
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	<-sig
	trace("terminated")
	if mode != "existing" {
		if link, err := netlink.LinkByName(name); err == nil {
			_ = netlink.LinkDel(link)
		}
		if nc, err := nftables.New(); err == nil {
			nc.DelTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: "netbird"})
			_ = nc.Flush()
		}
	}
	_ = os.Remove(filepath.Join(dir(), "live"))
}

func up() {
	trace("up")
	state := os.Getenv("NB_STATE_DIR")
	if state == "" {
		state = "/var/lib/netbird"
	}
	path := filepath.Join(state, "default.json")
	if _, err := os.Stat(path); err != nil {
		list := nbprofile.DefaultInterfaceBlacklist()
		if extra := os.Getenv("NB_EXTRA_IFACE_BLACKLIST"); extra != "" && os.Getenv("NB_FAKE_NOBLACKLIST") == "" {
			list = append(list, extra)
		}
		b, _ := json.Marshal(map[string]any{"WgIface": iface(), "IFaceBlackList": list})
		_ = os.MkdirAll(state, 0o700)
		if err := os.WriteFile(path, b, 0o600); err != nil {
			os.Exit(1)
		}
	}
	var key [8]byte
	_, _ = rand.Read(key[:])
}
