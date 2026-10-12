package applier

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/irashack/molebridge/internal/egress"
	"github.com/irashack/molebridge/internal/netx"
	"github.com/irashack/molebridge/internal/providers"
	"github.com/irashack/molebridge/internal/validate"
)

const mullvadCheckBytes = 16384

// mullvadFamily is Mullvad's answer for one family. am.i.mullvad.net has no
// AAAA record; Mullvad publishes per-family names.
type mullvadProbe struct {
	ip, city, country string
	exit              bool
}

func (a *Applier) mullvadFamily(ctx context.Context, family int) (mullvadProbe, error) {
	response, err := a.sys.Fetch(ctx, netx.Request{
		URL: "https://ipv" + strconv.Itoa(family) + ".am.i.mullvad.net/json", Family: family,
		BindInterface: a.exit.ExitIf, MaxBytes: mullvadCheckBytes, Timeout: 10 * time.Second})
	if err != nil {
		return mullvadProbe{}, err
	}
	decoded, err := validate.DecodeJSON(response.Body)
	if err != nil {
		return mullvadProbe{}, err
	}
	data, ok := decoded.(map[string]any)
	if !ok {
		return mullvadProbe{}, errors.New("invalid egress response")
	}
	exit, isBool := data["mullvad_exit_ip"].(bool)
	if !isBool {
		return mullvadProbe{}, errors.New("invalid egress response")
	}
	text, isString := data["ip"].(string)
	if !isString {
		return mullvadProbe{}, errors.New("invalid egress address")
	}
	ip, err := netip.ParseAddr(text)
	if err != nil {
		return mullvadProbe{}, errors.New("invalid egress address")
	}
	if (family == 4) != ip.Is4() {
		return mullvadProbe{}, errors.New("wrong egress address family")
	}
	var labels [2]string
	for i, key := range []string{"city", "country"} {
		label, isString := data[key].(string)
		if !isString || validate.RuneCount(label) > 256 {
			return mullvadProbe{}, errors.New("invalid egress location")
		}
		for _, r := range validate.Runes(label) {
			if r < 32 {
				return mullvadProbe{}, errors.New("invalid egress location")
			}
		}
		labels[i] = label
	}
	return mullvadProbe{ip: ip.String(), city: labels[0], country: labels[1], exit: exit}, nil
}

// MullvadEgress is Mullvad's check for every family the tunnel carries. The
// first family that Mullvad says is not its exit ends the check, so no later
// request can turn that answer into a retryable failure.
func (a *Applier) MullvadEgress(ctx context.Context) (EgressResult, error) {
	addresses, err := a.tunnelAddresses(ctx, true)
	if err != nil {
		return EgressResult{}, err
	}
	probes := map[int]mullvadProbe{}
	order := []int{}
	for _, family := range sortedFamilies(addresses) {
		if err := a.withinRetryBudget(); err != nil {
			return EgressResult{}, err
		}
		probe, err := a.mullvadFamily(ctx, family)
		if err != nil {
			return EgressResult{}, err
		}
		probes[family] = probe
		order = append(order, family)
		if !probe.exit {
			break
		}
	}
	confirmed := true
	for _, probe := range probes {
		confirmed = confirmed && probe.exit
	}
	first, ok := probes[4]
	if !ok {
		first = probes[order[0]]
	}
	result := EgressResult{EgressIP: first.ip, EgressCity: strPtr(first.city), EgressCountry: strPtr(first.country),
		ExitConfirmed: confirmed}
	for _, family := range order {
		name := strconv.Itoa(family)
		result.EgressIPs = append(result.EgressIPs, validate.Pair{Key: name, Value: probes[family].ip})
		state := "fail"
		if probes[family].exit {
			state = "pass"
		}
		result.Families = append(result.Families, validate.Pair{Key: name, Value: state})
	}
	return result, nil
}

// DefaultEcho is the caller's address from an IP echo service, through the
// tunnel interface or, with tunnel false, over the host's own route.
func (a *Applier) DefaultEcho(ctx context.Context, url string, family int, tunnel bool) (string, error) {
	request := netx.Request{URL: url, Family: family, MaxBytes: egress.EchoMaxBytes, Timeout: 10 * time.Second}
	if tunnel {
		request.BindInterface = a.exit.ExitIf
	}
	response, err := a.sys.Fetch(ctx, request)
	if err != nil {
		return "", err
	}
	if !utf8.Valid(response.Body) {
		return "", errors.New("invalid echo response")
	}
	return egress.ParseEcho(string(response.Body), family)
}

func (a *Applier) echo(ctx context.Context, url string, family int, tunnel bool) (string, error) {
	return a.hooks.Echo(ctx, a, url, family, tunnel)
}

// hostAddress is the host's own public address, measured off the tunnel. When
// that fails: egress.HostLacksFamily for IPv6 only if the namespace provably
// has no IPv6 of its own, otherwise "": no usable answer, which TunnelEgress
// raises.
func (a *Applier) hostAddress(ctx context.Context, family int) string {
	address, err := a.echo(ctx, egress.EchoURLs[family][0], family, false)
	if err == nil {
		return address
	}
	if family == 6 && a.hostLacksIPv6(ctx) {
		return egress.HostLacksFamily
	}
	return ""
}

func (a *Applier) hostLacksIPv6(ctx context.Context) bool {
	routes, links, err := a.sys.IPv6Evidence(ctx)
	if err != nil {
		return false
	}
	ignore := map[string]bool{a.exit.ExitIf: true}
	if a.kind() == "overlay" {
		ignore[a.exit.OverlayIf] = true
	}
	return egress.HostLacksIPv6(routes, links, ignore)
}

// exitAddresses are the selected server's exit addresses in one family, nil
// when the catalogue lists none.
func (a *Applier) exitAddresses(server string, family int) map[string]bool {
	if server == "" {
		return nil
	}
	listed := a.catalog.ExitIPs(server)
	if len(listed) == 0 {
		return nil
	}
	values := make([]any, len(listed))
	for i, s := range listed {
		values[i] = s
	}
	return egress.ExitAddresses(map[string]any{"exit_ips": values}, family)
}

// TunnelEgress is the "tunnel" tier (internal/egress), for every family the
// tunnel carries. exit_confirmed stays false: that field means the provider
// itself confirmed the egress. The first family that fails the checks ends
// them, and echo answers that disagree, or that the catalogue does not list as
// the server's exit, fail before the host's own address is measured, so no
// later request can turn a failed check into a retryable one.
func (a *Applier) TunnelEgress(ctx context.Context, server string, age *int) (EgressResult, error) {
	var relay *providers.Relay
	if server != "" {
		relay, _ = a.catalog.Relays().Get(server)
	}
	verified := relay != nil
	var result EgressResult
	addresses := map[string]string{}
	tunnel, err := a.tunnelAddresses(ctx, true)
	if err != nil {
		return EgressResult{}, err
	}
	for _, family := range sortedFamilies(tunnel) {
		name := strconv.Itoa(family)
		var echoes []string
		for _, url := range egress.EchoURLs[family] {
			if err := a.withinRetryBudget(); err != nil {
				return EgressResult{}, err
			}
			answer, err := a.echo(ctx, url, family, true)
			if err != nil {
				return EgressResult{}, err
			}
			echoes = append(echoes, answer)
		}
		addresses[name] = echoes[0]
		result.EgressIPs = append(result.EgressIPs, validate.Pair{Key: name, Value: echoes[0]})
		expected := a.exitAddresses(server, family)
		same := true
		for _, e := range echoes {
			same = same && e == echoes[0]
		}
		if !same || (expected != nil && !expected[echoes[0]]) {
			verified = false
			result.Families = append(result.Families, validate.Pair{Key: name, Value: "fail"})
			break
		}
		if err := a.withinRetryBudget(); err != nil {
			return EgressResult{}, err
		}
		host := a.hostAddress(ctx, family)
		if host == "" {
			return EgressResult{}, errors.New("host address measurement failed")
		}
		verified = egress.TunnelVerdict(echoes, host, expected, age, HandshakeFreshSec) && verified
		state := "fail"
		if verified {
			state = "pass"
		}
		result.Families = append(result.Families, validate.Pair{Key: name, Value: state})
		if !verified {
			break
		}
	}
	result.EgressIP = addresses["4"]
	if verified {
		result.EgressTier = providers.TierTunnel
	}
	return result, nil
}
