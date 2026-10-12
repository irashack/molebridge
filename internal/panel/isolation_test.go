package panel

// New in 0.8.0 (no Python counterpart): the panel's start-time isolation
// self-check from the plan's "Upgrade from 0.7.x". The decision function is
// tested with injected inputs.

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func okInputs() IsolationInputs {
	return IsolationInputs{UID: 1000, CapKnown: true, PanelUser: "1000:1000",
		Applier: []MountState{{Label: "a", Known: true, ReadOnly: true}, {Label: "b", Known: true, ReadOnly: true}}}
}

func TestCheckIsolation(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*IsolationInputs)
		want   []string
	}{
		{"a locked-down panel starts", func(*IsolationInputs) {}, nil},
		{"capabilities refuse", func(in *IsolationInputs) { in.CapEff = 0x1 }, []string{refuseCapabilities}},
		{"the full set refuses", func(in *IsolationInputs) { in.CapEff = 0x1ffffffffff }, []string{refuseCapabilities}},
		{"an unreadable set refuses", func(in *IsolationInputs) { in.CapKnown = false }, []string{refuseCapUnknown}},
		{"root without PANEL_USER refuses", func(in *IsolationInputs) { in.UID = 0; in.PanelUser = "" }, []string{refuseRoot}},
		{"root with a non-root PANEL_USER refuses", func(in *IsolationInputs) { in.UID = 0 }, []string{refuseRoot}},
		{"root with PANEL_USER=0:0 starts", func(in *IsolationInputs) { in.UID = 0; in.PanelUser = "0:0" }, nil},
		{"root with PANEL_USER=0 starts", func(in *IsolationInputs) { in.UID = 0; in.PanelUser = "0" }, nil},
		{"root with PANEL_USER=00:0 starts", func(in *IsolationInputs) { in.UID = 0; in.PanelUser = "00:0" }, nil},
		{"root with PANEL_USER=10:0 refuses", func(in *IsolationInputs) { in.UID = 0; in.PanelUser = "10:0" }, []string{refuseRoot}},
		{"root with PANEL_USER=root refuses", func(in *IsolationInputs) { in.UID = 0; in.PanelUser = "root" }, []string{refuseRoot}},
		{"PANEL_USER=0:0 does not excuse capabilities", func(in *IsolationInputs) { in.UID = 0; in.PanelUser = "0:0"; in.CapEff = 1 }, []string{refuseCapabilities}},
		{"a writable applier mount refuses", func(in *IsolationInputs) { in.Applier[1].ReadOnly = false }, []string{refuseMounts}},
		{"an unknown mount refuses", func(in *IsolationInputs) { in.Applier[0].Known = false }, []string{refuseMountUnknown}},
		{"everything wrong says everything", func(in *IsolationInputs) {
			in.UID, in.PanelUser, in.CapEff = 0, "", 1
			in.Applier[0].ReadOnly = false
		}, []string{refuseCapabilities, refuseRoot, refuseMounts}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := okInputs()
			tc.mutate(&in)
			got := CheckIsolation(in)
			if strings.Join(got, "|") != strings.Join(tc.want, "|") {
				t.Fatalf("CheckIsolation = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRefusalsNameNothingFromTheEnvironment(t *testing.T) {
	in := okInputs()
	in.UID, in.PanelUser, in.CapEff = 0, "secret-looking-value", 1
	in.Applier[0] = MountState{Label: "/srv/private/path", Known: true}
	for _, refusal := range CheckIsolation(in) {
		for _, leaked := range []string{"secret-looking-value", "/srv/private/path"} {
			if strings.Contains(refusal, leaked) {
				t.Errorf("refusal %q repeats %q", refusal, leaked)
			}
		}
	}
}

func TestParseCapEff(t *testing.T) {
	status := "Name:\tpanel\nUmask:\t0022\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t000001ffffffffff\n"
	if n, ok := ParseCapEff(strings.NewReader(status)); !ok || n != 0 {
		t.Fatalf("ParseCapEff = %d, %v", n, ok)
	}
	if n, ok := ParseCapEff(strings.NewReader("CapEff:\t00000000a80425fb\n")); !ok || n != 0xa80425fb {
		t.Fatalf("ParseCapEff = %x, %v", n, ok)
	}
	for _, bad := range []string{"", "Name:\tx\n", "CapEff:\tzz\n", "CapEff:\n"} {
		if _, ok := ParseCapEff(strings.NewReader(bad)); ok {
			t.Errorf("ParseCapEff(%q) succeeded", bad)
		}
	}
}

func fakeProbe(t *testing.T, status string, uid int, readOnly map[string]bool) IsolationProbe {
	t.Helper()
	path := filepath.Join(t.TempDir(), "status")
	if status != "" {
		if err := os.WriteFile(path, []byte(status), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return IsolationProbe{
		StatusPath: path,
		UID:        func() int { return uid },
		ReadOnly: func(dir string) (bool, error) {
			ro, ok := readOnly[dir]
			if !ok {
				return false, fs.ErrNotExist
			}
			return ro, nil
		},
	}
}

func TestVerifyIsolationGathersEveryExit(t *testing.T) {
	exits := []Exit{{ID: "mine"}, {ID: "a"}}
	probe := fakeProbe(t, "CapEff:\t0000000000000000\n", 1000, map[string]bool{
		"/state/mine/applier": true, "/state/a/applier": true})
	var warn bytes.Buffer
	if err := VerifyIsolation(map[string]string{"PANEL_USER": "1000:1000"}, exits, "/state", probe, &warn); err != nil {
		t.Fatalf("VerifyIsolation = %v", err)
	}
	probe.ReadOnly = func(dir string) (bool, error) { return dir != "/state/a/applier", nil }
	err := VerifyIsolation(map[string]string{"PANEL_USER": "1000:1000"}, exits, "/state", probe, &warn)
	var refused *ErrIsolation
	if !errors.As(err, &refused) || len(refused.Refusals) != 1 || refused.Refusals[0] != refuseMounts {
		t.Fatalf("VerifyIsolation = %v", err)
	}
}

func TestVerifyIsolationSingleExitChecksStateApplier(t *testing.T) {
	probe := fakeProbe(t, "CapEff:\t0000000000000000\n", 1000, map[string]bool{"/state/applier": true})
	if err := VerifyIsolation(map[string]string{}, nil, "/state", probe, os.Stderr); err != nil {
		t.Fatal(err)
	}
	probe = fakeProbe(t, "CapEff:\t0000000000000000\n", 1000, map[string]bool{"/state/applier": false})
	if err := VerifyIsolation(map[string]string{}, nil, "/state", probe, os.Stderr); err == nil {
		t.Fatal("a writable applier mount was accepted")
	}
}

func TestVerifyIsolationAbsentDirectoryIsNothingToProtect(t *testing.T) {
	probe := fakeProbe(t, "CapEff:\t0000000000000000\n", 1000, map[string]bool{})
	if err := VerifyIsolation(map[string]string{}, nil, "/state", probe, os.Stderr); err != nil {
		t.Fatalf("an unmounted applier directory refused the start: %v", err)
	}
}

func TestVerifyIsolationNoProcStatusRefuses(t *testing.T) {
	probe := fakeProbe(t, "", 1000, map[string]bool{"/state/applier": true})
	err := VerifyIsolation(map[string]string{}, nil, "/state", probe, os.Stderr)
	var refused *ErrIsolation
	if !errors.As(err, &refused) || refused.Refusals[0] != refuseCapUnknown {
		t.Fatalf("VerifyIsolation = %v", err)
	}
}

func TestIsolationCheckCanBeSwitchedOffAndSaysSo(t *testing.T) {
	probe := fakeProbe(t, "CapEff:\t0000000000000fff\n", 0, nil)
	var warn bytes.Buffer
	if err := VerifyIsolation(map[string]string{IsolationOffEnv: "off"}, nil, "/state", probe, &warn); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(warn.String(), "switched off") {
		t.Fatalf("no warning: %q", warn.String())
	}
	// Only the exact value switches it off.
	if err := VerifyIsolation(map[string]string{IsolationOffEnv: "0"}, nil, "/state", probe, &warn); err == nil {
		t.Fatal("the check was skipped")
	}
}

func TestReadOnlyMountOnARealDirectory(t *testing.T) {
	dir := t.TempDir()
	if ro, err := readOnlyMount(dir); err != nil || ro {
		t.Fatalf("readOnlyMount(%q) = %v, %v", dir, ro, err)
	}
	if _, err := readOnlyMount(filepath.Join(dir, "missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing directory: %v", err)
	}
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readOnlyMount(file); err == nil {
		t.Fatal("a file counted as a directory")
	}
}
