// Package jsonfile reads and writes the JSON state files: bounded, strict on
// the way in, atomic on the way out. internal/state re-exports it under the
// names the Python module (state.read_json, state.write_json_atomic) had; the
// relay catalogue in internal/providers uses it directly, because state
// imports providers and the reverse would be a cycle.
//
// It offers Read, ReadObject, ReadBytes, ReadBytesErr, Write and WriteBytes
// (atomic, 0600 or 0644, or 0640 for a group after SetPublicGroup;
// size-bounded), ErrSizeLimit and ErrNotRegular.
package jsonfile

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
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
	raw, ok := ReadBytes(path, limit)
	if !ok {
		return nil, false
	}
	value, err := validate.DecodeJSON(raw)
	if err != nil {
		return nil, false
	}
	return value, true
}

// ReadBytes is the file at path, undecoded, under Read's rules: false when
// the path is a symlink or not a regular file, the file is larger than limit
// bytes or it cannot be read. A caller that decodes only part of a large
// document (validate.DecodeJSONMembers) reads it with this.
func ReadBytes(path string, limit int64) ([]byte, bool) {
	raw, err := ReadBytesErr(path, limit)
	return raw, err == nil
}

// ReadBytesErr is ReadBytes with the reason it failed: the open or read
// error (an *os.PathError, which names the path), ErrNotRegular or
// ErrSizeLimit. The reason holds no part of the file's content.
func ReadBytesErr(path string, limit int64) ([]byte, error) {
	return readBytes(path, limit, syscall.O_NOFOLLOW)
}

// ReadMountedErr is ReadBytesErr for a file you mount, a secret or a
// certificate: it follows a symbolic link, as a Kubernetes secret volume
// presents each file as one, but what the link names must still be a regular
// file of at most limit bytes, and it is opened without blocking, so a FIFO
// is refused rather than stalling the start.
func ReadMountedErr(path string, limit int64) ([]byte, error) {
	return readBytes(path, limit, 0)
}

func readBytes(path string, limit int64, flags int) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|flags, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, ErrNotRegular
	}
	if info.Size() > limit {
		return nil, ErrSizeLimit
	}
	raw, err := readSized(io.LimitReader(f, limit+1), info.Size())
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, ErrSizeLimit
	}
	return raw, nil
}

// ErrNotRegular is ReadBytesErr's reason for a path that is not a regular
// file.
var ErrNotRegular = errors.New("not a regular file")

// readSized reads r to its end into a buffer of size plus one byte, so the
// read that finds the end needs no larger one (io.ReadAll would allocate
// about twice the file as its buffer grows); a file that grew since its size
// was taken is read on by io.ReadAll.
func readSized(r io.Reader, size int64) ([]byte, error) {
	buf := make([]byte, 0, size+1)
	for {
		n, err := r.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		if err == io.EOF {
			return buf, nil
		}
		if err != nil {
			return buf, err
		}
		if len(buf) == cap(buf) {
			rest, err := io.ReadAll(r)
			return append(buf, rest...), err
		}
	}
}

// ReadObject is Read for a document that must be a JSON object.
func ReadObject(path string, limit int64) (map[string]any, bool) {
	object, ok := Read(path, limit).(map[string]any)
	return object, ok
}

// publicGroup is SetPublicGroup's gid, -1 when unset.
var publicGroup atomic.Int64

func init() { publicGroup.Store(-1) }

// SetPublicGroup makes every Public file this process writes from now on
// mode 0640 with group gid, instead of 0644 with the process's own group: the
// exit's STATE_GID, for readers (the panel, the proxy) that run as another
// user in that group. A negative gid restores 0644. The process must be able
// to give a file that group (it is a member of it, or holds CAP_CHOWN), or
// Write fails. Private (0600) files are not affected.
func SetPublicGroup(gid int) {
	if gid < 0 {
		gid = -1
	}
	publicGroup.Store(int64(gid))
}

// Options are the optional parts of Write.
type Options struct {
	// Public makes the file 0644 so a non-root reader can open the applier's
	// state (0640 with the group SetPublicGroup names, when it named one);
	// otherwise it is 0600.
	Public bool
	// MaxBytes, when positive, stops the encoder with ErrSizeLimit as soon as
	// the output passes it. Zero means no bound.
	MaxBytes int64
	// NoSync skips the fsync before the rename. For a record its writer
	// rewrites within seconds and that nothing restores from (result.json):
	// the rename stays atomic, and after a crash the file is the previous
	// version or the new one, never a torn one, but a few seconds may be lost.
	// On a copy-on-write filesystem each fsync costs a log-tree commit; a
	// 2-second rewrite with one wrote about 1.8 MB a minute on btrfs.
	NoSync bool
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
// file is synced (unless opts.NoSync) and renamed over path. On any error the temporary file is
// removed and the old file stays in place. The directory is created if needed.
func Write(path string, v any, opts Options) error {
	return writeFile(path, opts, func(w io.Writer) error {
		return validate.EncodeJSON(&limitWriter{w: w, max: opts.MaxBytes}, v)
	})
}

// WriteBytes is Write for a document already encoded: data is written as it
// is, under the same rules (atomic, 0600 or 0644, MaxBytes, NoSync). The
// network exchange stores the bytes it received, so their hash is the
// sender's.
func WriteBytes(path string, data []byte, opts Options) error {
	if opts.MaxBytes > 0 && int64(len(data)) > opts.MaxBytes {
		return ErrSizeLimit
	}
	return writeFile(path, opts, func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	})
}

func writeFile(path string, opts Options, fill func(io.Writer) error) (err error) {
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
		if gid := publicGroup.Load(); gid >= 0 {
			// SetPublicGroup: the group reads it, others don't.
			if err = f.Chown(-1, int(gid)); err != nil {
				return err
			}
			mode = 0o640
		}
	}
	if err = f.Chmod(mode); err != nil {
		return err
	}
	if err = fill(f); err != nil {
		return err
	}
	if !opts.NoSync {
		if err = f.Sync(); err != nil {
			return err
		}
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}
