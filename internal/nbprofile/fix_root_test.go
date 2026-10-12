package nbprofile

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// Ownership under real privilege, run where the tests run as root (the
// throwaway container): the replacement keeps a foreign owner, group and mode,
// and an unprivileged process that cannot chown refuses. Skipped elsewhere.

func rootFixture(t *testing.T, uid, gid int, mode os.FileMode, text string) (Paths, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "nbroot")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "state")
	if err := os.Mkdir(state, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(state, 0o777); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(state, "default.json")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, uid, gid); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return Paths{StateDir: state}, path
}

func TestFixBlacklistKeepsAForeignOwnerAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create a file owned by another user")
	}
	p, path := rootFixture(t, 4242, 4343, 0o640, listProfile(`["wt0"]`))
	if _, err := FixBlacklistWith(p, "mullvad", FixOptions{SocketAnswers: noSocket}); err != nil {
		t.Fatal(err)
	}
	st := mustStat(t, path)
	uid, gid, _ := ownerOf(st)
	if uid != 4242 || gid != 4343 || st.Mode().Perm() != 0o640 {
		t.Fatalf("owner %d:%d mode %v", uid, gid, st.Mode())
	}
	if data, _ := os.ReadFile(path); !strings.Contains(string(data), `"mullvad"`) {
		t.Fatal("not repaired")
	}
}

func TestFixBlacklistRefusesAForeignOwnerWithoutPrivilege(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to set up and drop privilege in a child")
	}
	text := listProfile(`["wt0"]`)
	p, path := rootFixture(t, 4242, 4343, 0o666, text)
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperForeignOwner$")
	cmd.Env = append(os.Environ(), "NBP_HELPER_STATE="+p.StateDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper failed: %v\n%s", err, out)
	}
	if data, _ := os.ReadFile(path); string(data) != text {
		t.Fatal("the original changed")
	}
	if entries := dirEntries(t, p.StateDir); len(entries) != 1 {
		t.Fatalf("a temporary file was left: %v", entries)
	}
}

// TestHelperForeignOwner runs in a child as an unprivileged user.
func TestHelperForeignOwner(t *testing.T) {
	state := os.Getenv("NBP_HELPER_STATE")
	if state == "" {
		t.Skip("child of TestFixBlacklistRefusesAForeignOwnerWithoutPrivilege")
	}
	if err := syscall.Setgid(1000); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Setuid(1000); err != nil {
		t.Fatal(err)
	}
	_, err := FixBlacklistWith(Paths{StateDir: state}, "mullvad", FixOptions{SocketAnswers: noSocket})
	if err == nil || !strings.Contains(err.Error(), "cannot give the replacement the owner and group") {
		t.Fatalf("error = %v (uid %s)", err, strconv.Itoa(os.Geteuid()))
	}
}
