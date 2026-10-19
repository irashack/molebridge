package privfile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func names(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

func expectFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.Mode().IsRegular() {
		t.Fatalf("%s is %v, not a regular file", path, fi.Mode())
	}
	if fi.Mode().Perm() != mode {
		t.Errorf("%s has mode %v, want %v", path, fi.Mode().Perm(), mode)
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != content {
		t.Errorf("%s holds %q (%v), want %q", path, b, err, content)
	}
}

func TestWriteCreatesTheFileAndItsDirectoriesWithTheMode(t *testing.T) {
	for _, mode := range []os.FileMode{0o600, 0o644, 0o755} {
		dir := t.TempDir()
		path := filepath.Join(dir, "a", "b", "out")
		if err := Write(path, []byte("content\n"), mode); err != nil {
			t.Fatal(err)
		}
		// The mode is set on the file, not left to the umask.
		expectFile(t, path, "content\n", mode)
		if got := names(t, filepath.Dir(path)); len(got) != 1 {
			t.Errorf("mode %v: the directory holds %v", mode, got)
		}
	}
}

func TestWriteReplacesTheFileWhole(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out")
	if err := os.WriteFile(path, []byte("old content, longer than the new\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A reader that has the old file open keeps reading the old file: the new
	// one is a different file renamed over it, not the old one rewritten.
	old, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	if err := Write(path, []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	expectFile(t, path, "new\n", 0o600)
	b := make([]byte, 64)
	n, _ := old.Read(b)
	if string(b[:n]) != "old content, longer than the new\n" {
		t.Errorf("the open file now reads %q", b[:n])
	}
	if got := names(t, dir); len(got) != 1 {
		t.Errorf("the directory holds %v", got)
	}
}

func TestWriteReplacesALinkAndNotItsTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("target\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "out")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	expectFile(t, path, "new\n", 0o600)
	expectFile(t, target, "target\n", 0o644)
}

func TestAFailedWriteLeavesNoTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	// A non-empty directory where the file should go: the rename fails.
	path := filepath.Join(dir, "out")
	if err := os.MkdirAll(filepath.Join(path, "inside"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, []byte("new\n"), 0o600); err == nil {
		t.Fatal("a file was written over a non-empty directory")
	}
	if got := names(t, dir); len(got) != 1 || got[0] != "out" {
		t.Errorf("the directory holds %v", got)
	}
	// A parent that is a file: nothing can be created.
	parent := filepath.Join(dir, "file")
	if err := os.WriteFile(parent, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Write(filepath.Join(parent, "out"), []byte("new\n"), 0o600); err == nil {
		t.Fatal("a file was written under a file")
	}
}

func TestWriteNewCreatesAPrivateFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a", "out")
	if err := WriteNew(path, []byte("secret\n")); err != nil {
		t.Fatal(err)
	}
	expectFile(t, path, "secret\n", 0o600)
}

func TestWriteNewNeverReplacesAnything(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "existing")
	if err := os.WriteFile(existing, []byte("keep\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(existing, link); err != nil {
		t.Fatal(err)
	}
	dangling := filepath.Join(dir, "dangling")
	missing := filepath.Join(dir, "missing")
	if err := os.Symlink(missing, dangling); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(dir, "directory")
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{existing, link, dangling, directory} {
		if err := WriteNew(path, []byte("new\n")); !errors.Is(err, ErrExists) {
			t.Errorf("%s: %v, want ErrExists", filepath.Base(path), err)
		}
	}
	expectFile(t, existing, "keep\n", 0o644)
	if _, err := os.Lstat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the dangling link's target was created: %v", err)
	}
	if fi, err := os.Lstat(dangling); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the dangling link changed: %v %v", fi, err)
	}
}

func TestWriteNewThatCannotCreateSaysSo(t *testing.T) {
	dir := t.TempDir()
	parent := filepath.Join(dir, "file")
	if err := os.WriteFile(parent, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(parent, "out"), filepath.Join(parent, "sub", "out")} {
		err := WriteNew(path, []byte("new\n"))
		if !errors.Is(err, ErrCreate) || errors.Is(err, ErrExists) {
			t.Errorf("%s: %v, want ErrCreate", path, err)
		}
	}
}
