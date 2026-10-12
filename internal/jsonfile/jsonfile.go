// Package jsonfile reads and writes the JSON state files: bounded, strict on
// the way in, atomic on the way out. internal/state re-exports it under the
// names the Python module (state.read_json, state.write_json_atomic) had; the
// relay catalogue in internal/providers uses it directly, because state
// imports providers and the reverse would be a cycle.
//
// It offers Read, ReadObject, Write (atomic, 0600 or 0644, size-bounded) and
// ErrSizeLimit.
package jsonfile

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/irashack/molebridge/internal/validate"
)

// ErrSizeLimit is returned when a document would pass its size bound.
var ErrSizeLimit = errors.New("state file exceeds its size limit")

// Read returns the decoded JSON document in the file at path, or nil when
// anything is wrong with it: the path is a symlink or not a regular file, the
// file is larger than limit bytes, it is not strictly valid JSON (duplicate
// keys, bad UTF-8, NaN, too deep), or it cannot be read. (A file holding the
// JSON null reads as nil too, as in Python.) A FIFO or a device is never
// opened for reading.
func Read(path string, limit int64) any {
	value, _ := ReadOK(path, limit)
	return value
}

// ReadOK is Read, with a second result that is false when the file could not
// be read or decoded, and true for a document that is the JSON null.
func ReadOK(path string, limit int64) (any, bool) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, false
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, false
	}
	value, err := validate.DecodeJSON(raw)
	if err != nil {
		return nil, false
	}
	return value, true
}

// ReadObject is Read for a document that must be a JSON object.
func ReadObject(path string, limit int64) (map[string]any, bool) {
	object, ok := Read(path, limit).(map[string]any)
	return object, ok
}

// Options are the optional parts of Write.
type Options struct {
	// Public makes the file 0644 so a non-root reader can open the applier's
	// state; otherwise it is 0600.
	Public bool
	// MaxBytes, when positive, stops the encoder with ErrSizeLimit as soon as
	// the output passes it. Zero means no bound.
	MaxBytes int64
}

type limitWriter struct {
	w       io.Writer
	max     int64
	written int64
}

func (l *limitWriter) Write(p []byte) (int, error) {
	if l.max > 0 && l.written+int64(len(p)) > l.max {
		return 0, ErrSizeLimit
	}
	n, err := l.w.Write(p)
	l.written += int64(n)
	return n, err
}

// Write replaces the file at path atomically with the JSON encoding of v
// (validate.EncodeJSON: the bytes Python's json.dump writes). The document is
// encoded in small chunks into a temporary file in the same directory, so
// memory stays bounded by the chunk size whatever the document's size; the
// file is synced and renamed over path. On any error the temporary file is
// removed and the old file stays in place. The directory is created if needed.
func Write(path string, v any, opts Options) (err error) {
	dir := filepath.Dir(path)
	if err = os.MkdirAll(dir, 0o777); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	temporary := f.Name()
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(temporary)
		}
	}()
	mode := os.FileMode(0o600)
	if opts.Public {
		mode = 0o644
	}
	if err = f.Chmod(mode); err != nil {
		return err
	}
	if err = validate.EncodeJSON(&limitWriter{w: f, max: opts.MaxBytes}, v); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}
