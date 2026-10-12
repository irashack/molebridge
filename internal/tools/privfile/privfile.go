// Package privfile writes the files the file tools produce: private files
// (mode 0600) written atomically or created exclusively, and public files
// (mode 0644) written atomically. The tools run as the invoking user, so
// nothing here changes an owner.
package privfile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// Write puts content into path with the given mode: a temporary file in the
// same directory is written, synced, set to mode and renamed over path, so a
// reader sees the old file or the new one and a failure leaves no temporary
// file behind. (tempfile.mkstemp, fchmod and os.replace in the Python tools.)
// The parent directories are created first with the default mode.
func Write(path string, content []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o777); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".tmp-")
	if err != nil {
		return err
	}
	name := f.Name()
	cleanup := func(err error) error {
		f.Close()
		os.Remove(name)
		return err
	}
	if err := f.Chmod(mode); err != nil {
		return cleanup(err)
	}
	if _, err := f.Write(content); err != nil {
		return cleanup(err)
	}
	if err := f.Sync(); err != nil {
		return cleanup(err)
	}
	if err := f.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}

// ErrExists is returned by WriteNew when the path is already taken, and
// ErrCreate (wrapped, so errors.Is finds it) when it cannot be created.
var (
	ErrExists = errors.New("the output file exists")
	ErrCreate = errors.New("the output file could not be created")
)

// WriteNew creates path with mode 0600 and never replaces what is there: the
// file is opened with O_EXCL and O_NOFOLLOW, so an existing file, a symbolic
// link (dangling or not) and a race all refuse. The parent directories are
// created first. A partial file is removed on failure.
func WriteNew(path string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o777); err != nil {
		return fmt.Errorf("%w: %v", ErrCreate, err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrExists
		}
		return fmt.Errorf("%w: %v", ErrCreate, err)
	}
	fail := func(err error) error {
		f.Close()
		os.Remove(path)
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		return fail(err)
	}
	if _, err := f.Write(content); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return err
	}
	return nil
}
