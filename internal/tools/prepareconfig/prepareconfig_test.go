package prepareconfig

// Ported from tools/test_prepare_tunnel_config.py. The parser-side parts of
// that file (the generated configs are accepted, the rewrite for policy
// routing) are also in internal/tunnelconf's tests; here they run against the
// real generator, and its output is passed through the exit's validator.
// test_unsupported_host_refuses_before_creating_key_file is not ported: the
// binary is Linux-only in the image and has no fchmod gate.

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/irashack/molebridge/internal/tunnelconf"
)

// Fictitious values: all-zero keys and documentation addresses.
const (
	private = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	public  = private
)

const downloaded = `
[Interface]
# Device: Example Device
PrivateKey = ` + private + `
Address = 192.0.2.2/32,2001:db8:4::2/128
DNS = 192.0.2.1

[Peer]
PublicKey = ` + public + `
AllowedIPs = 0.0.0.0/0,::0/0
Endpoint = 198.51.100.10:51820
`

func build(t *testing.T, text, table string) string {
	t.Helper()
	out, err := BuildTunnelConf(text, table)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestRewritesForPolicyRouting(t *testing.T) { // test_rewrites_for_policy_routing
	out := build(t, downloaded, "51821")
	for _, want := range []string{"Table = off", "MTU = 1420",
		"ip route replace default dev %i table 51821; ip -6 route replace default dev %i table 51821",
		"Endpoint = 198.51.100.10:51820", "AllowedIPs = 0.0.0.0/0, ::/0",
		"Address = 192.0.2.2/32, 2001:db8:4::2/128", "PersistentKeepalive = 25"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "DNS") {
		t.Error("the DNS line must be dropped")
	}
}

func TestIPv4OnlyConfigOmitsIPv6Routes(t *testing.T) { // test_ipv4_only_config_omits_ipv6_routes
	out := build(t, strings.Replace(downloaded, ",2001:db8:4::2/128", "", 1), DefaultTable)
	if strings.Contains(out, "ip -6") {
		t.Error("ip -6 route in an IPv4-only config")
	}
	if !strings.Contains(out, "AllowedIPs = 0.0.0.0/0\n") {
		t.Error("AllowedIPs is not IPv4 only")
	}
}

func TestRejectsBadKeyAndEndpoint(t *testing.T) { // test_rejects_bad_key_and_endpoint
	for name, c := range map[string]struct{ text, msg string }{
		"bad private key": {strings.Replace(downloaded, private, "not-a-key", 1), "Interface PrivateKey is missing or is not a WireGuard key"},
		"bad public key":  {strings.Replace(downloaded, "PublicKey = "+public, "PublicKey = short", 1), "Peer PublicKey is missing or is not a WireGuard key"},
		"hostname":        {strings.Replace(downloaded, "198.51.100.10:51820", "se-sto-wg-001:51820", 1), "Peer Endpoint must be an IPv4 address and port"},
		"no port":         {strings.Replace(downloaded, "198.51.100.10:51820", "198.51.100.10", 1), "Peer Endpoint must be an IPv4 address and port"},
		"ipv6 endpoint":   {strings.Replace(downloaded, "198.51.100.10:51820", "[2001:db8::1]:51820", 1), "Peer Endpoint must be an IPv4 address and port"},
		"no endpoint":     {strings.Replace(downloaded, "Endpoint = 198.51.100.10:51820", "", 1), "Peer Endpoint must be an IPv4 address and port"},
	} {
		_, err := BuildTunnelConf(c.text, DefaultTable)
		if err == nil || err.Error() != c.msg {
			t.Errorf("%s: %v, want %q", name, err, c.msg)
		}
	}
}

func TestRejectsReservedTableAndInvalidPort(t *testing.T) { // test_rejects_reserved_table_and_invalid_port
	for _, table := range []string{"0", "254", "255", "000256", "4294967296", "51821; echo bad", "", "-1", "256 "} {
		_, err := BuildTunnelConf(downloaded, table)
		if err == nil || err.Error() != "EXIT_TABLE must be an unreserved table number (256..2147483647)" {
			t.Errorf("table %q: %v", table, err)
		}
	}
	for _, table := range []string{"256", "51821", "2147483647"} {
		build(t, downloaded, table)
	}
	for _, port := range []string{"0", "65536", "-1", "x", "123456", ""} {
		_, err := BuildTunnelConf(strings.Replace(downloaded, ":51820", ":"+port, 1), DefaultTable)
		if err == nil || err.Error() != "Peer Endpoint port must be 1..65535" && !strings.Contains(err.Error(), "Endpoint") {
			t.Errorf("port %q: %v", port, err)
		}
	}
}

func TestAddressRefusals(t *testing.T) {
	for name, c := range map[string]struct{ address, msg string }{
		"none":          {"", "Interface Address has no IPv4 tunnel address"},
		"only v6":       {"2001:db8::2/128", "Interface Address has no IPv4 tunnel address"},
		"garbage":       {"nonsense", "Interface Address is not valid"},
		"bad prefix":    {"192.0.2.2/33", "Interface Address is not valid"},
		"two v4":        {"192.0.2.2/32, 192.0.2.3/32", "Interface Address has more than one address in a family"},
		"two v6":        {"192.0.2.2/32, 2001:db8::2/128, 2001:db8::3/128", "Interface Address has more than one address in a family"},
		"subnet":        {"192.0.2.2/24", "Interface Address must be host addresses (/32 and /128)"},
		"v6 subnet":     {"192.0.2.2/32, 2001:db8::2/64", "Interface Address must be host addresses (/32 and /128)"},
		"leading zeros": {"192.0.02.2/32", "Interface Address is not valid"},
		"v6 zone":       {"192.0.2.2/32, fe80::2%eth0/128", "Interface Address is not valid"},
	} {
		text := strings.Replace(downloaded, "Address = 192.0.2.2/32,2001:db8:4::2/128", "Address = "+c.address, 1)
		_, err := BuildTunnelConf(text, DefaultTable)
		if err == nil || err.Error() != c.msg {
			t.Errorf("%s: %v, want %q", name, err, c.msg)
		}
	}
	// Spellings ipaddress.ip_interface reads as host addresses.
	for address, want := range map[string]string{
		"192.0.2.2":                       "192.0.2.2/32",
		"192.0.2.2/255.255.255.255":       "192.0.2.2/32",
		"192.0.2.2/0.0.0.0":               "", // a /0 netmask: refused as a subnet
		"192.0.2.2/32,2001:DB8:0:0::2":    "192.0.2.2/32, 2001:db8::2/128",
		" 192.0.2.2/32 , 2001:db8::2/128": "192.0.2.2/32, 2001:db8::2/128",
	} {
		text := strings.Replace(downloaded, "Address = 192.0.2.2/32,2001:db8:4::2/128", "Address = "+address, 1)
		out, err := BuildTunnelConf(text, DefaultTable)
		if want == "" {
			if err == nil {
				t.Errorf("%q accepted", address)
			}
			continue
		}
		if err != nil || !strings.Contains(out, "Address = "+want+"\n") {
			t.Errorf("%q: %v\n%s", address, err, out)
		}
	}
}

func TestParserFollowsTheIniReaderOfTheOriginal(t *testing.T) {
	// The first value of a key wins, only the first peer is read, comments and
	// other sections are ignored, and Python's str.splitlines separators end
	// lines.
	text := "[Interface]\nPrivateKey = " + private + "\nPrivateKey = bad\nAddress = 192.0.2.2/32 # comment\n" +
		"[Other]\nEndpoint = 203.0.113.9:1\n[Peer]\nPublicKey = " + public + "\nEndpoint = 198.51.100.10:51820\n" +
		"[Peer]\nEndpoint = 203.0.113.99:9\n[ Interface ]\nMTU = 1\x0cNote = x\r\nFoo\n"
	out := build(t, text, DefaultTable)
	if !strings.Contains(out, "PrivateKey = "+private+"\n") || !strings.Contains(out, "Endpoint = 198.51.100.10:51820\n") ||
		strings.Contains(out, "203.0.113") || strings.Contains(out, "bad") {
		t.Errorf("unexpected output:\n%s", out)
	}
	got := splitLines("a\rb\r\nc\nd\x0be\x1cf\u2028g\u0085h\n\n")
	if strings.Join(got, "|") != "a|b|c|d|e|f|g|h|" {
		t.Errorf("splitLines: %q", got)
	}
	if len(splitLines("")) != 0 || len(splitLines("x\n")) != 1 {
		t.Error("splitLines edge cases")
	}
}

func TestOutputIsAcceptedByTheExitsValidator(t *testing.T) { // test_whatever_the_generator_accepts_the_image_accepts
	for name, text := range map[string]string{
		"dual stack": downloaded,
		"ipv4":       strings.Replace(downloaded, ",2001:db8:4::2/128", "", 1),
	} {
		out := build(t, text, "51821")
		conf, err := tunnelconf.Parse(out, tunnelconf.Mullvad, 51821)
		if err != nil {
			t.Fatalf("%s: %v\n%s", name, err, out)
		}
		if conf.Peer == nil || conf.Peer.Endpoint.String() != "198.51.100.10:51820" {
			t.Errorf("%s: peer %+v", name, conf.Peer)
		}
	}
	// Another exit table goes through to the hooks the validator reads.
	out := build(t, downloaded, "40000")
	if _, err := tunnelconf.Parse(out, tunnelconf.Mullvad, 40000); err != nil {
		t.Errorf("table 40000: %v", err)
	}
	if _, err := tunnelconf.Parse(out, tunnelconf.Mullvad, 51821); err == nil {
		t.Error("a config for table 40000 passed for table 51821")
	}
	pia, err := BuildPIAConf(private, "51821")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tunnelconf.Parse(pia, tunnelconf.PIA, 51821); err != nil {
		t.Errorf("pia: %v\n%s", err, pia)
	}
}

type fixedRandom byte

func (f fixedRandom) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(f)
	}
	return len(p), nil
}

func opts(env map[string]string) (Options, *bytes.Buffer, *bytes.Buffer) {
	var out, errb bytes.Buffer
	return Options{Env: env, Random: fixedRandom(0xff), Stdout: &out, Stderr: &errb}, &out, &errb
}

func TestWritesMode0600WithoutPrintingKeys(t *testing.T) { // test_writes_mode_0600_without_printing_keys
	old := syscall.Umask(0)
	defer syscall.Umask(old)
	dir := t.TempDir()
	src := filepath.Join(dir, "download.conf")
	if err := os.WriteFile(src, []byte(downloaded), 0o644); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(dir, "wg_confs", "mullvad.conf")
	o, stdout, stderr := opts(nil)
	if code := Main([]string{src, dest}, o); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	info, err := os.Stat(dest)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode: %v %v", info, err)
	}
	got, _ := os.ReadFile(dest)
	if !strings.Contains(string(got), private) {
		t.Error("the key is not in the output file")
	}
	if want := "wrote " + dest + " (mode 0600); delete " + src + " now\n"; stdout.String() != want {
		t.Errorf("stdout %q, want %q", stdout, want)
	}
	if strings.Contains(stdout.String()+stderr.String(), private) || stderr.Len() != 0 {
		t.Error("key material or noise in the output")
	}
	// The directory holds only the result: no temporary file is left.
	entries, _ := os.ReadDir(filepath.Dir(dest))
	if len(entries) != 1 {
		t.Errorf("leftovers: %v", entries)
	}
	// Run again: the file is replaced atomically, with the same mode.
	if code := Main([]string{src, dest}, o); code != 0 {
		t.Fatal("second run failed")
	}
}

func TestMullvadRefusalsWriteNothingAndPrintOnlyFixedText(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "out", "mullvad.conf")
	bad := filepath.Join(dir, "bad.conf")
	os.WriteFile(bad, []byte(strings.Replace(downloaded, private, "SECRETSECRETSECRET", 1)), 0o600)
	for name, c := range map[string]struct {
		src, want string
		env       map[string]string
	}{
		"bad key":   {bad, "error: Interface PrivateKey is missing or is not a WireGuard key\n", nil},
		"bad table": {bad, "error: Interface PrivateKey is missing or is not a WireGuard key\n", map[string]string{"EXIT_TABLE": "1"}},
		"missing":   {filepath.Join(dir, "absent"), "error: open " + filepath.Join(dir, "absent") + ": no such file or directory\n", nil},
		"huge":      {mk(t, dir, "huge", strings.Repeat("#", MaxInput+1)), "error: the downloaded config is larger than 64 KiB\n", nil},
		"not utf-8": {mk(t, dir, "latin", "[Interface]\n# \xe9\xff\n"), "error: the downloaded config is not valid UTF-8\n", nil},
	} {
		o, stdout, stderr := opts(c.env)
		if code := Main([]string{c.src, dest}, o); code != 1 || stdout.Len() != 0 || stderr.String() != c.want {
			t.Errorf("%s: code %d stdout %q stderr %q", name, code, stdout, stderr)
		}
		if _, err := os.Stat(dest); err == nil {
			t.Errorf("%s: wrote the output", name)
		}
	}
	// A table from the environment decides the hooks.
	good := mk(t, dir, "good", downloaded)
	o, _, _ := opts(map[string]string{"EXIT_TABLE": "40000"})
	if code := Main([]string{good, dest}, o); code != 0 {
		t.Fatal("EXIT_TABLE=40000 refused")
	}
	if got, _ := os.ReadFile(dest); !strings.Contains(string(got), "table 40000") {
		t.Error("EXIT_TABLE ignored")
	}
}

func mk(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"one"}, {"a", "b", "c"}, {"--pia"}, {"--pia", "a", "b"},
		{"--nordvpn"}, {"--nordvpn", "a"}, {"--nordvpn", "a", "b", "c"}} {
		o, stdout, stderr := opts(nil)
		if code := Main(args, o); code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "usage: molebridge prepare-config") {
			t.Errorf("%q: %d %q %q", args, code, stdout, stderr)
		}
	}
	o, stdout, _ := opts(nil)
	if code := Main([]string{"--help"}, o); code != 0 || !strings.Contains(stdout.String(), "--user") || !strings.Contains(stdout.String(), "prepare-config --pia /out/pia.conf") ||
		!strings.Contains(stdout.String(), "prepare-config --nordvpn /in.conf /out/nordvpn.conf") {
		t.Errorf("help: %d %q", code, stdout)
	}
}

func TestNewPrivateKeyIsClampedAndUsable(t *testing.T) {
	for _, b := range []byte{0x00, 0xff, 0x5a} {
		key, err := NewPrivateKey(fixedRandom(b))
		if err != nil {
			t.Fatal(err)
		}
		raw, err := base64.StdEncoding.DecodeString(key)
		if err != nil || len(raw) != 32 {
			t.Fatalf("%q: %v", key, err)
		}
		if raw[0]&7 != 0 || raw[31]&0x80 != 0 || raw[31]&0x40 == 0 {
			t.Errorf("byte %#x: not clamped: % x", b, raw)
		}
		// A real X25519 private key: the public half derives.
		priv, err := ecdh.X25519().NewPrivateKey(raw)
		if err != nil || len(priv.PublicKey().Bytes()) != 32 {
			t.Errorf("byte %#x: %v", b, err)
		}
		if _, err := requireKey(key, "k"); err != nil {
			t.Errorf("own key refused: %v", err)
		}
	}
	// Different draws differ.
	a, _ := NewPrivateKey(fixedRandom(1))
	b, _ := NewPrivateKey(fixedRandom(2))
	if a == b {
		t.Error("same key")
	}
	if _, err := NewPrivateKey(strings.NewReader("short")); err == nil {
		t.Error("short random source accepted")
	}
}

func TestPIACreatesANewConfigAndNeverOverwrites(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "wg_confs", "pia.conf")
	o, stdout, stderr := opts(nil)
	if code := Main([]string{"--pia", dest}, o); code != 0 || stderr.Len() != 0 {
		t.Fatalf("%d %s", code, stderr)
	}
	if want := "wrote " + dest + " (mode 0600)\n"; stdout.String() != want {
		t.Errorf("stdout %q", stdout)
	}
	info, _ := os.Stat(dest)
	if info == nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", info)
	}
	got, _ := os.ReadFile(dest)
	want, _ := BuildPIAConf(func() string { k, _ := NewPrivateKey(fixedRandom(0xff)); return k }(), DefaultTable)
	if string(got) != want {
		t.Errorf("content:\n%s", got)
	}
	if strings.Contains(string(got), "Address") || strings.Contains(string(got), "[Peer]") {
		t.Error("a PIA config has no address or peer")
	}
	if _, err := tunnelconf.Parse(string(got), tunnelconf.PIA, 51821); err != nil {
		t.Errorf("not accepted by the exit's validator: %v", err)
	}
	if strings.Contains(stdout.String(), "PrivateKey") {
		t.Error("key printed")
	}
	// Second run: the file is kept.
	o2, stdout2, stderr2 := opts(nil)
	o2.Random = fixedRandom(7)
	if code := Main([]string{"--pia", dest}, o2); code != 1 || stdout2.Len() != 0 ||
		stderr2.String() != "error: "+dest+" exists; keep it, or remove it deliberately to make a new key\n" {
		t.Errorf("%d %q %q", code, stdout2, stderr2)
	}
	if again, _ := os.ReadFile(dest); string(again) != string(got) {
		t.Error("existing PIA config overwritten")
	}
	// A bad EXIT_TABLE writes nothing.
	o3, _, stderr3 := opts(map[string]string{"EXIT_TABLE": "7"})
	other := filepath.Join(dir, "other.conf")
	if code := Main([]string{"--pia", other}, o3); code != 1 || !strings.Contains(stderr3.String(), "EXIT_TABLE") {
		t.Errorf("%d %q", code, stderr3)
	}
	if _, err := os.Stat(other); err == nil {
		t.Error("wrote with a bad table")
	}
}

// A config as NordVPN's Nord Account download writes it (fictitious values):
// NordLynx's address at /16, a DNS line and a peer named by hostname.
const nordDownloaded = `[Interface]
PrivateKey = ` + private + `
Address = 10.5.0.2/16
DNS = 192.0.2.53
[Peer]
PublicKey = ` + public + `
AllowedIPs = 0.0.0.0/0
Endpoint = city.example.test:51820
PersistentKeepalive = 25
`

func TestNordVPNDownloadBecomesTheNordConfig(t *testing.T) {
	want, err := BuildNordConf(private, "51821", "prepare-config --nordvpn")
	if err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{
		"as downloaded": nordDownloaded,
		"crlf":          strings.ReplaceAll(nordDownloaded, "\n", "\r\n"),
		"host address":  strings.Replace(nordDownloaded, "10.5.0.2/16", "10.5.0.2/32", 1),
		"no peer":       nordDownloaded[:strings.Index(nordDownloaded, "[Peer]")],
	} {
		out, err := BuildNordVPNTunnelConf(text, "51821")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if out != want {
			t.Errorf("%s:\n%s", name, out)
		}
	}
	for _, not := range []string{"[Peer]", "DNS", "Endpoint", "example.test", "/16"} {
		if strings.Contains(want, not) {
			t.Errorf("config has %q", not)
		}
	}
	conf, err := tunnelconf.Parse(want, tunnelconf.NordVPN, 51821)
	if err != nil {
		t.Fatalf("not accepted by the exit's validator: %v\n%s", err, want)
	}
	if conf.Addr4 != nordHost || conf.Peer != nil {
		t.Errorf("address %v peer %+v", conf.Addr4, conf.Peer)
	}
}

func TestNordVPNRefusals(t *testing.T) {
	only := "Interface Address must be NordLynx's 10.5.0.2 and nothing else"
	for name, c := range map[string]struct{ text, table, msg string }{
		"bad key":        {strings.Replace(nordDownloaded, private, "not-a-key", 1), "51821", "Interface PrivateKey is missing or is not a WireGuard key"},
		"no address":     {strings.Replace(nordDownloaded, "Address = 10.5.0.2/16\n", "", 1), "51821", only},
		"other address":  {strings.Replace(nordDownloaded, "10.5.0.2/16", "192.0.2.2/32", 1), "51821", only},
		"ipv6 too":       {strings.Replace(nordDownloaded, "10.5.0.2/16", "10.5.0.2/16, 2001:db8::2/128", 1), "51821", only},
		"bad address":    {strings.Replace(nordDownloaded, "10.5.0.2/16", "10.5.0.2/40", 1), "51821", only},
		"mullvad file":   {downloaded, "51821", only},
		"reserved table": {nordDownloaded, "255", "EXIT_TABLE must be an unreserved table number (256..2147483647)"},
	} {
		_, err := BuildNordVPNTunnelConf(c.text, c.table)
		if err == nil || err.Error() != c.msg {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The Mullvad path names the right flag rather than refusing the /16.
	if _, err := BuildTunnelConf(nordDownloaded, "51821"); err == nil ||
		err.Error() != "this is a NordVPN config; use prepare-config --nordvpn" {
		t.Errorf("mullvad path: %v", err)
	}
}

func TestNordVPNWritesMode0600WithoutPrintingKeys(t *testing.T) {
	dir := t.TempDir()
	src := mk(t, dir, "download.conf", nordDownloaded)
	dest := filepath.Join(dir, "wg_confs", "nordvpn.conf")
	o, stdout, stderr := opts(map[string]string{"EXIT_TABLE": "40000"})
	if code := Main([]string{"--nordvpn", src, dest}, o); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	info, err := os.Stat(dest)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode: %v %v", info, err)
	}
	got, _ := os.ReadFile(dest)
	if _, err := tunnelconf.Parse(string(got), tunnelconf.NordVPN, 40000); err != nil {
		t.Errorf("EXIT_TABLE=40000 not applied: %v\n%s", err, got)
	}
	if want := "wrote " + dest + " (mode 0600); delete " + src + " now\n"; stdout.String() != want {
		t.Errorf("stdout %q, want %q", stdout, want)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr %q", stderr)
	}
	// Without the flag the same file is refused with a pointer to it, and
	// nothing is written.
	other := filepath.Join(dir, "other.conf")
	o2, stdout2, stderr2 := opts(nil)
	if code := Main([]string{src, other}, o2); code != 1 || stdout2.Len() != 0 ||
		stderr2.String() != "error: this is a NordVPN config; use prepare-config --nordvpn\n" {
		t.Errorf("%d %q %q", code, stdout2, stderr2)
	}
	if _, err := os.Stat(other); err == nil {
		t.Error("wrote the output")
	}
}
