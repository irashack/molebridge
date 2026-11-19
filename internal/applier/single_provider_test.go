// A single-provider exit keeps its files byte for byte as they were before
// the multi-provider exit (docs/design/multi-provider.md, rule 2): the
// attempt record, the location memory, PIA's tunnel.json and the names of
// every file the applier writes, for fixed scenarios. The status records are
// locked by golden_test.go; this locks the rest. The golden
// (testdata/single_provider_files_golden.json) was generated from the applier
// before the provider set existed and is never regenerated to make a change
// pass: a difference is a change to single-provider exits.
package applier

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var updateSingle = flag.Bool("update-single-provider", false, "rewrite testdata/single_provider_files_golden.json")

var attemptIDRE = regexp.MustCompile(`"attempt_id": "[0-9a-f]+"`)

// stateFiles is every file under the state directory, by path relative to
// it, with its content normalized: timestamps and attempt ids replaced.
func stateFiles(t *testing.T, dir string) map[string]string {
	t.Helper()
	files := map[string]string{}
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		if strings.HasPrefix(rel, "secrets"+string(filepath.Separator)) || rel == filepath.Join("panel", "desired.json") {
			return nil
		}
		content := ""
		// The catalogue and the error record are the providers package's,
		// locked by its own tests: their names are what matters here.
		if filepath.Base(rel) != "relays.json" {
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			content = attemptIDRE.ReplaceAllString(normalized(string(raw)), `"attempt_id": "<id>"`)
		}
		files[filepath.ToSlash(rel)] = content
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func TestSingleProviderFilesStayByteForByte(t *testing.T) {
	scenarios := map[string]func(t *testing.T) string{
		"mullvad_switch": func(t *testing.T) string {
			a, _, dir := mullvadSetup(t)
			a.switchTo(t, requestAt(testHost, nil))
			return dir
		},
		"mullvad_rejected": func(t *testing.T) string {
			a, _, dir := mullvadSetup(t)
			desire(t, a, requestAt("xx-xxx-wg-999", nil))
			mustTick(t, a)
			return dir
		},
		"mullvad_mutation_failed": func(t *testing.T) string {
			a, k, dir := mullvadSetup(t)
			addRelay(a, otherHost, otherKey)
			k.keys = []string{otherKey}
			k.failSet = true
			desire(t, a, requestAt(testHost, nil))
			mustTick(t, a)
			return dir
		},
		"mullvad_configured": func(t *testing.T) string {
			dir := t.TempDir()
			writeSnapshot(t, dir, "", map[string]any{testHost: mullvadEntry(testHost, testKey)})
			a := newApplier(t, newKernel(t), dir, NewMullvad(), testHost)
			mustTick(t, a)
			return dir
		},
		"nord_switch": func(t *testing.T) string {
			a, _, dir := nordSetup(t)
			a.switchTo(t, nordRequest(nordUS, nil))
			return dir
		},
		"pia_switch": func(t *testing.T) string {
			a, _, _, dir, _ := piaSetup(t, false)
			a.switchTo(t, piaRequest(nil))
			return dir
		},
		"pia_forward_bound": func(t *testing.T) string {
			a, _, _, dir, _ := piaSetup(t, true)
			piaDesire(t, a)
			mustTick(t, a)
			mustTick(t, a)
			return dir
		},
	}
	got := map[string]map[string]string{}
	for name, run := range scenarios {
		got[name] = stateFiles(t, run(t))
	}
	path := filepath.Join("testdata", "single_provider_files_golden.json")
	if *updateSingle {
		raw, err := json.MarshalIndent(got, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(raw, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var golden map[string]map[string]string
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatal(err)
	}
	if len(golden) != len(scenarios) {
		t.Errorf("%d scenarios, %d golden", len(scenarios), len(golden))
	}
	for name, files := range got {
		want := golden[name]
		var names, wantNames []string
		for f := range files {
			names = append(names, f)
		}
		for f := range want {
			wantNames = append(wantNames, f)
		}
		sort.Strings(names)
		sort.Strings(wantNames)
		if strings.Join(names, " ") != strings.Join(wantNames, " ") {
			t.Errorf("%s: files %v, want %v", name, names, wantNames)
		}
		for f, content := range want {
			if files[f] != content {
				t.Errorf("%s: %s differs:\n got: %s\nwant: %s", name, f, files[f], content)
			}
		}
	}
}
