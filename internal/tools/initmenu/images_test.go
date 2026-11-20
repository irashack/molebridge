package initmenu

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Fictitious references of one release, as the release notes would give them.
var (
	zeroDigest = "sha256:" + strings.Repeat("0", 64)
	oneDigest  = "sha256:" + strings.Repeat("1", 64)
	goodImage  = MolebridgeRepo + ":v9.9.9@" + zeroDigest
	goodCore   = CoreRepo + ":v9.9.9@" + oneDigest
)

func ptr(s string) *string { return &s }

func TestParseImages(t *testing.T) {
	img, err := ParseImages("--image", ptr(goodImage), "--core-image", ptr(goodCore))
	if err != nil || img != (Images{Molebridge: goodImage, Core: goodCore, Tag: "v9.9.9"}) {
		t.Fatalf("good references: %+v %v", img, err)
	}
	rc, err := ParseImages("--image", ptr(MolebridgeRepo+":v9.9.9-rc.2@"+zeroDigest), "--core-image", ptr(CoreRepo+":v9.9.9-rc.2@"+oneDigest))
	if err != nil || rc.Tag != "v9.9.9-rc.2" {
		t.Fatalf("candidate references: %+v %v", rc, err)
	}
	if img, err := ParseImages("--image", nil, "--core-image", nil); err != nil || img != (Images{}) {
		t.Fatalf("neither: %+v %v", img, err)
	}
	for name, c := range map[string]struct {
		image, core *string
		want        string
	}{
		"image only": {ptr(goodImage), nil, "--image and --core-image go together: give both, the two images of one release."},
		"core only":  {nil, ptr(goodCore), "--image and --core-image go together"},
		"empty":      {ptr(""), ptr(goodCore), "--image is empty: give ghcr.io/irashack/molebridge:<tag>@sha256:<digest>."},
		"wrong repo": {ptr("ghcr.io/example/molebridge:v9.9.9@" + zeroDigest), ptr(goodCore),
			`--image "ghcr.io/example/molebridge:v9.9.9@` + zeroDigest + `" is not ghcr.io/irashack/molebridge:<tag>@sha256:<digest>: the repository is ghcr.io/example/molebridge, not ghcr.io/irashack/molebridge.`},
		"core as image": {ptr(goodCore), ptr(goodCore), "the repository is ghcr.io/irashack/molebridge-core, not ghcr.io/irashack/molebridge."},
		"image as core": {ptr(goodImage), ptr(goodImage), "--core-image " + `"` + goodImage + `"` + " is not ghcr.io/irashack/molebridge-core:<tag>@sha256:<digest>: the repository is ghcr.io/irashack/molebridge, not ghcr.io/irashack/molebridge-core."},
		"no registry":   {ptr("irashack/molebridge:v9.9.9@" + zeroDigest), ptr(goodCore), "the repository is irashack/molebridge, not"},
		"no digest":     {ptr(MolebridgeRepo + ":v9.9.9"), ptr(goodCore), "it has no digest; init needs the index digest from the release notes, not a tag alone."},
		"no tag":        {ptr(MolebridgeRepo + "@" + zeroDigest), ptr(goodCore), "it has no tag; give the release's tag, such as v0.14.1, before the digest."},
		"empty tag":     {ptr(MolebridgeRepo + ":@" + zeroDigest), ptr(goodCore), "it has no tag"},
		"floating tag":  {ptr(MolebridgeRepo + ":0.14@" + zeroDigest), ptr(goodCore), "the tag 0.14 is not a release tag such as v0.14.1 or a candidate tag such as v0.14.1-rc.1."},
		"latest":        {ptr(MolebridgeRepo + ":latest@" + zeroDigest), ptr(goodCore), "the tag latest is not a release tag"},
		"uppercase hex": {ptr(MolebridgeRepo + ":v9.9.9@sha256:" + strings.Repeat("A", 64)), ptr(goodCore), "the digest must be sha256: and 64 lowercase hexadecimal digits."},
		"short digest":  {ptr(MolebridgeRepo + ":v9.9.9@sha256:" + strings.Repeat("0", 63)), ptr(goodCore), "the digest must be sha256: and 64 lowercase"},
		"long digest":   {ptr(MolebridgeRepo + ":v9.9.9@sha256:" + strings.Repeat("0", 65)), ptr(goodCore), "the digest must be sha256: and 64 lowercase"},
		"sha512":        {ptr(MolebridgeRepo + ":v9.9.9@sha512:" + strings.Repeat("0", 64)), ptr(goodCore), "the digest must be sha256:"},
		"two digests":   {ptr(goodImage + "@" + zeroDigest), ptr(goodCore), "the digest must be sha256:"},
		"leading space": {ptr(" " + goodImage), ptr(goodCore), "it holds a space, a control character or a non-ASCII character."},
		"trailing nl":   {ptr(goodImage), ptr(goodCore + "\n"), `--core-image "` + goodCore + `\n" is not ghcr.io/irashack/molebridge-core:<tag>@sha256:<digest>: it holds a space`},
		"inner tab":     {ptr(MolebridgeRepo + ":v9.9.9\t@" + zeroDigest), ptr(goodCore), "it holds a space"},
		"non-ASCII":     {ptr(MolebridgeRepo + ":v9.9.9@sha256:" + strings.Repeat("０", 64)), ptr(goodCore), "non-ASCII"},
		"mismatched tags": {ptr(goodImage), ptr(CoreRepo + ":v9.9.8@" + oneDigest),
			"--image has tag v9.9.9 but --core-image has tag v9.9.8: give the two images of one release."},
		"rc and release": {ptr(goodImage), ptr(CoreRepo + ":v9.9.9-rc.1@" + oneDigest), "--image has tag v9.9.9 but --core-image has tag v9.9.9-rc.1"},
	} {
		_, err := ParseImages("--image", c.image, "--core-image", c.core)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if _, ok := err.(Refusal); !ok {
			t.Errorf("%s: %T, not a Refusal", name, err)
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %q, want %q", name, err, c.want)
		}
	}
}

// TestRenderWithImages: with images, every combination writes exactly what
// it writes without them, but for the given images in place of each
// Molebridge pin and two header lines saying so.
func TestRenderWithImages(t *testing.T) {
	images := Images{Molebridge: goodImage, Core: goodCore, Tag: "v9.9.9"}
	pinned := PinnedTag()
	if !releaseTagRE.MatchString(pinned) {
		t.Fatalf("compose.tmpl's pinned tag is %q", pinned)
	}
	raw, _ := templateFS.ReadFile("compose.tmpl")
	var tmplImage, tmplCore string
	for _, m := range molebridgePinRE.FindAllSubmatch(raw, -1) {
		ref := strings.TrimPrefix(string(m[0]), string(m[1]))
		if len(m[2]) > 0 {
			tmplCore = ref
		} else {
			tmplImage = ref
		}
	}
	if tmplImage == "" || tmplCore == "" {
		t.Fatal("compose.tmpl pins neither image")
	}
	header := "# The Molebridge images are not that file's pins: they are the v9.9.9\n" +
		"# images init was given (--image and --core-image, or the answers file).\n"
	imageLine := regexp.MustCompile(`(?m)^ +image: (.*)$`)
	n := 0
	for _, a := range everyAnswers() {
		p, err := a.Plan()
		if err != nil {
			continue
		}
		n++
		plain, err := Render(p)
		if err != nil {
			t.Fatal(err)
		}
		p.Images = images
		files, err := Render(p)
		if err != nil {
			t.Fatal(err)
		}
		got := string(files[ComposeFile])
		want := strings.ReplaceAll(string(plain[ComposeFile]), tmplImage, goodImage)
		want = strings.ReplaceAll(want, tmplCore, goodCore)
		want = strings.Replace(want, "# Your settings are in .env", header+"# Your settings are in .env", 1)
		if got != want {
			t.Errorf("%+v: with images:\n%s", a, lineDiff(strings.Split(want, "\n"), strings.Split(got, "\n")))
		}
		if strings.Contains(got, ":"+pinned+"@") {
			t.Errorf("%+v: a %s pin is left", a, pinned)
		}
		for _, m := range imageLine.FindAllStringSubmatch(got, -1) {
			if strings.HasPrefix(m[1], "ghcr.io/irashack/") && m[1] != goodImage && m[1] != goodCore {
				t.Errorf("%+v: image %s", a, m[1])
			}
		}
		for name, body := range plain {
			if name != ComposeFile && !bytes.Equal(body, files[name]) {
				t.Errorf("%+v: %s differs with images", a, name)
			}
		}
	}
	if n == 0 {
		t.Fatal("no combination rendered")
	}
}

// everyAnswers lists the answers TestEveryCombination tries, accepted or not.
func everyAnswers() []Answers {
	var out []Answers
	provs := append([]string{"mullvad", "pia", "nordvpn", "mullvad,pia,nordvpn"}, gluetunIDs()...)
	ways := [][]string{{WayNetBird}, {WaySidecar}, {WayNetBird, WayProxy}, {WaySidecar, WayProxy}}
	extras := [][]string{nil, {ExtraSwitchyard}, {ExtraPortSync}, {ExtraSwitchyard, ExtraPortSync}}
	for _, prov := range provs {
		for _, w := range ways {
			for _, e := range extras {
				out = append(out, Answers{prov, w, e})
			}
		}
	}
	return out
}

func TestPinsNotice(t *testing.T) {
	tail := " To pin the release you verified, pass --image and --core-image (docs/setup.md#molebridge-init)."
	generic := "molebridge init: compose.yaml pins the Molebridge images at v0.14.0, the pins of the source this binary was built from, possibly an older release." + tail
	for version, want := range map[string]string{
		"dev":          generic,
		"":             generic,
		"v0.14.0":      generic,
		"v0.14.0-rc.1": generic,
		"v0.14":        generic,
		"v0.14.1": "molebridge init: compose.yaml pins the Molebridge images at v0.14.0, the pins of the source this binary was built from: " +
			"this is v0.14.1; the pins are v0.14.0's." + tail,
		"v0.14.1-rc.2": "molebridge init: compose.yaml pins the Molebridge images at v0.14.0, the pins of the source this binary was built from: " +
			"this is v0.14.1 (built as v0.14.1-rc.2); the pins are v0.14.0's." + tail,
	} {
		if got := pinsNotice(version, "v0.14.0"); got != want {
			t.Errorf("%q:\n got %s\nwant %s", version, got, want)
		}
	}
}

func runVersion(t *testing.T, version string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Main(args, Options{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb,
		Terminal: func() bool { return false }, Version: version})
	return code, out.String(), errb.String()
}

func TestMainImages(t *testing.T) {
	answers := writeAnswers(t, `{"schema":1,"provider":"pia","ways_in":["netbird-exit","proxy"]}`)
	pinned := PinnedTag()

	// Without images: compose.tmpl's pins, and the line about them last on stderr.
	out := t.TempDir()
	code, _, stderr := runVersion(t, "v99.0.0-rc.1", "--out", out, "--answers", answers)
	want := "molebridge init: compose.yaml pins the Molebridge images at " + pinned +
		", the pins of the source this binary was built from: this is v99.0.0 (built as v99.0.0-rc.1); the pins are " +
		pinned + "'s. To pin the release you verified, pass --image and --core-image (docs/setup.md#molebridge-init).\n"
	if code != 0 || stderr != want {
		t.Fatalf("no images: exit %d, %q", code, stderr)
	}
	compose, _ := os.ReadFile(filepath.Join(out, ComposeFile))
	if !strings.Contains(string(compose), ":"+pinned+"@") {
		t.Error("no images: the pins are not compose.tmpl's")
	}
	code, _, stderr = runVersion(t, "dev", "--out", t.TempDir(), "--answers", answers)
	if code != 0 || !strings.HasSuffix(stderr, ", possibly an older release. To pin the release you verified, pass --image and --core-image (docs/setup.md#molebridge-init).\n") {
		t.Errorf("dev: exit %d, %q", code, stderr)
	}

	// With the flags: their images, and nothing on stderr.
	out = t.TempDir()
	code, stdout, stderr := runVersion(t, "v99.0.0-rc.1", "--out", out, "--answers", answers, "--image", goodImage, "--core-image", goodCore)
	if code != 0 || stderr != "" || !strings.Contains(stdout, "Wrote ") {
		t.Fatalf("flags: exit %d, %q %q", code, stdout, stderr)
	}
	compose, _ = os.ReadFile(filepath.Join(out, ComposeFile))
	if !strings.Contains(string(compose), "    image: "+goodImage+"\n") || !strings.Contains(string(compose), "    image: "+goodCore+"\n") ||
		strings.Contains(string(compose), ":"+pinned+"@") {
		t.Errorf("flags: compose.yaml:\n%s", compose)
	}

	// In the answers file: the same output.
	inFile := writeAnswers(t, `{"schema":1,"provider":"pia","ways_in":["netbird-exit","proxy"],"image":"`+goodImage+`","core_image":"`+goodCore+`"}`)
	out2 := t.TempDir()
	code, _, stderr = runVersion(t, "v99.0.0-rc.1", "--out", out2, "--answers", inFile)
	fromFile, _ := os.ReadFile(filepath.Join(out2, ComposeFile))
	if code != 0 || stderr != "" || !bytes.Equal(fromFile, compose) {
		t.Errorf("answers file: exit %d, %q", code, stderr)
	}
	// Both, the same: accepted. Both, different: refused.
	code, _, stderr = runVersion(t, "", "--out", t.TempDir(), "--answers", inFile, "--image", goodImage, "--core-image", goodCore)
	if code != 0 || stderr != "" {
		t.Errorf("same in both: exit %d, %q", code, stderr)
	}

	dir := t.TempDir()
	for _, c := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"--answers", answers, "--image", goodImage}, 2,
			"molebridge init: --image and --core-image go together: give both, the two images of one release.\n"},
		{[]string{"--answers", answers, "--image", goodImage, "--core-image", ""}, 2,
			"molebridge init: --core-image is empty: give ghcr.io/irashack/molebridge-core:<tag>@sha256:<digest>.\n"},
		{[]string{"--answers", answers, "--image", MolebridgeRepo + ":v9.9.9", "--core-image", goodCore}, 2,
			`molebridge init: --image "ghcr.io/irashack/molebridge:v9.9.9" is not ghcr.io/irashack/molebridge:<tag>@sha256:<digest>: it has no digest; init needs the index digest from the release notes, not a tag alone.` + "\n"},
		{[]string{"--answers", answers, "--image", goodImage, "--core-image", CoreRepo + ":v9.9.8@" + oneDigest}, 2,
			"molebridge init: --image has tag v9.9.9 but --core-image has tag v9.9.8: give the two images of one release.\n"},
		{[]string{"--answers", inFile, "--image", MolebridgeRepo + ":v9.9.8@" + zeroDigest, "--core-image", CoreRepo + ":v9.9.8@" + oneDigest}, 1,
			"molebridge init: --image and --core-image name other images than the answers file's image and core_image: give them in one place.\n"},
		{[]string{"--answers", writeAnswers(t, `{"schema":1,"provider":"pia","ways_in":["sidecar"],"image":"`+goodImage+`"}`)}, 1,
			"molebridge init: the answers file's image and the answers file's core_image go together: give both, the two images of one release.\n"},
		{[]string{"--answers", writeAnswers(t, `{"schema":1,"provider":"pia","ways_in":["sidecar"],"image":"`+goodImage+`","core_image":7}`)}, 1,
			"molebridge init: the answers file's core_image must be a string.\n"},
		{[]string{"--answers", writeAnswers(t, `{"schema":1,"provider":"pia","ways_in":["sidecar"],"image":"`+goodImage+` ","core_image":"`+goodCore+`"}`)}, 1,
			`molebridge init: the answers file's image "` + goodImage + ` " is not ghcr.io/irashack/molebridge:<tag>@sha256:<digest>: it holds a space, a control character or a non-ASCII character.` + "\n"},
	} {
		code, _, stderr := runVersion(t, "v99.0.0", append([]string{"--out", dir}, c.args...)...)
		if code != c.code || stderr != c.want {
			t.Errorf("%v: exit %d, %q; want %d, %q", c.args, code, stderr, c.code, c.want)
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("refusals wrote %v", entries)
	}
	if code, stdout, _ := run(t, "", false, "--help"); code != 0 || !strings.Contains(stdout, "--core-image REF  ghcr.io/irashack/molebridge-core:<tag>@sha256:<digest>") {
		t.Errorf("--help: %d %s", code, stdout)
	}
}
