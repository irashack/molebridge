package main

import (
	"bytes"
	"testing"
)

func TestVersionRolePrintsTheBuildVersion(t *testing.T) {
	if version != "dev" {
		t.Errorf("a build without -X main.version says %q, want dev", version)
	}
	saved := version
	t.Cleanup(func() { version = saved })
	version = "v0.0.0-rc.0"
	var stdout, stderr bytes.Buffer
	if code := versionMain(nil, &stdout, &stderr); code != 0 || stdout.String() != "molebridge v0.0.0-rc.0\n" || stderr.Len() != 0 {
		t.Fatalf("%d %q %q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	if code := versionMain([]string{"x"}, &stdout, &stderr); code != 2 || stdout.Len() != 0 || stderr.String() != "usage: molebridge version\n" {
		t.Fatalf("%d %q %q", code, stdout.String(), stderr.String())
	}
}
