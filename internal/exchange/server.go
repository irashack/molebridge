package exchange

import (
	"crypto/subtle"
	"errors"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/irashack/molebridge/internal/jsonfile"
	"github.com/irashack/molebridge/internal/validate"
)

// Exit is one exit the exchange serves: its id, its provider (for the
// catalog's size limit) and its directory on the panel's side, which holds
// panel/desired.json (the panel's, read here), applier/ (the copies, written
// here and read-only for the panel) and exchange.json (the link state).
type Exit struct {
	ID       string
	Provider string
	Dir      string
}

// DesiredPath, CopyPath and LinkPath are the exit's files on the panel's side.
func (e Exit) DesiredPath() string { return filepath.Join(e.Dir, "panel", "desired.json") }

// CopyPath is the panel's copy of a published file.
func (e Exit) CopyPath(name string) string { return filepath.Join(e.Dir, "applier", name) }

// LinkPath is the link state, state/<id>/exchange.json.
func (e Exit) LinkPath() string { return filepath.Join(e.Dir, LinkFile) }

// LinkFile is the link state's file name in the exit's directory.
const LinkFile = "exchange.json"

// Server is the exchange: an http.Handler for every exit in Exits. Each
// request carries the exit's own token, read from TokensDir/<id> on every
// request, so a rotated token takes effect without a restart.
type Server struct {
	Exits     map[string]Exit
	TokensDir string
	// Now is the clock (time.Now when nil); Logf logs one line (never a token,
	// a header or a body).
	Now  func() time.Time
	Logf func(format string, a ...any)

	mu    sync.Mutex
	links map[string]*link
	// hashes caches each copy's hash by its size and modification time, so the
	// catalog isn't hashed again every round.
	hashes map[string]cachedHash
}

type link struct {
	contact time.Time
	offset  *float64
	files   map[string]received
}

type received struct {
	at   time.Time
	hash string
}

type cachedHash struct {
	size  int64
	mtime time.Time
	hash  string
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Server) logf(format string, a ...any) {
	if s.Logf != nil {
		s.Logf(format, a...)
	}
}

// ServeHTTP answers GET /v1/exits/<id> and PUT /v1/exits/<id>/files/<name>.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rest, ok := strings.CutPrefix(r.URL.Path, "/v1/exits/")
	if !ok {
		reply(w, http.StatusNotFound, "not found")
		return
	}
	parts := strings.Split(rest, "/")
	id := parts[0]
	// An unknown exit and a wrong token answer the same, so the answer doesn't
	// tell which ids exist.
	// The token file's path is built from the configured exit's id, never
	// from the URL's.
	ex, known := s.Exits[id]
	if !ValidExitID(id) || !known || !s.authorized(ex, r.Header.Get("Authorization")) {
		reply(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	switch {
	case len(parts) == 1:
		if r.Method != http.MethodGet {
			reply(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.serveGet(w, r, ex)
	case len(parts) == 3 && parts[1] == "files":
		if r.Method != http.MethodPut {
			reply(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.servePut(w, r, ex, parts[2])
	default:
		reply(w, http.StatusNotFound, "not found")
	}
}

func reply(w http.ResponseWriter, status int, message string) {
	body, _ := validate.MarshalJSON(validate.Members("error", message))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// authorized compares the bearer token with the exit's token file in
// constant time. A missing, unsafe, short or unreadable file refuses every
// request for that exit.
func (s *Server) authorized(ex Exit, header string) bool {
	given, ok := strings.CutPrefix(header, "Bearer ")
	if !ok || given == "" {
		return false
	}
	if !ValidExitID(ex.ID) {
		return false
	}
	want, ok := ReadToken(filepath.Join(s.TokensDir, ex.ID))
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(given), []byte(want)) == 1
}

// ReadToken reads a token file: a regular file, not a symlink, at most
// TokenLimit bytes, one line of at least MinTokenBytes printable ASCII
// characters with no spaces, and an optional final newline.
func ReadToken(path string) (string, bool) {
	raw, ok := jsonfile.ReadBytes(path, TokenLimit)
	if !ok {
		return "", false
	}
	token := strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r")
	if len(token) < MinTokenBytes {
		return "", false
	}
	for i := 0; i < len(token); i++ {
		if token[i] <= ' ' || token[i] > '~' {
			return "", false
		}
	}
	return token, true
}

func (s *Server) serveGet(w http.ResponseWriter, r *http.Request, ex Exit) {
	now := s.now()
	var desired any
	if value, ok := jsonfile.ReadOK(ex.DesiredPath(), DesiredLimit); ok {
		if object, isObject := value.(map[string]any); isObject {
			desired = object
		}
	}
	have := validate.Obj{}
	for _, name := range Files {
		if h := s.copyHash(ex.CopyPath(name)); h != "" {
			have = append(have, validate.Pair{Key: name, Value: h})
		}
	}
	body, err := validate.MarshalJSON(validate.Members("schema", Schema, "desired", desired, "have", have))
	if err != nil {
		reply(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.contact(ex, r, now, "", "")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}

func (s *Server) servePut(w http.ResponseWriter, r *http.Request, ex Exit, name string) {
	limit, ok := FileLimit(name, ex.Provider)
	if !ok {
		reply(w, http.StatusNotFound, "not found")
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		reply(w, http.StatusRequestEntityTooLarge, "file exceeds its size limit")
		return
	case err != nil:
		reply(w, http.StatusBadRequest, "cannot read the body")
		return
	}
	value, err := validate.DecodeJSON(data)
	if _, isObject := value.(map[string]any); err != nil || !isObject {
		reply(w, http.StatusBadRequest, "not a strict JSON object")
		return
	}
	hash := Hash(data)
	if given := r.Header.Get(SHA256Header); given != "" && given != hash {
		reply(w, http.StatusBadRequest, "hash mismatch")
		return
	}
	// The status record changes every 2 seconds and is rebuilt by the exit,
	// so it isn't synced; the others are.
	opts := jsonfile.Options{Public: true, MaxBytes: limit, NoSync: name == FileResult}
	if err := jsonfile.WriteBytes(ex.CopyPath(name), data, opts); err != nil {
		s.logf("cannot write the copy of %s for exit %s: %v", name, ex.ID, pathless(err))
		reply(w, http.StatusInternalServerError, "cannot store the file")
		return
	}
	s.contact(ex, r, s.now(), name, hash)
	w.WriteHeader(http.StatusNoContent)
}

// pathless drops the path from a file-system error, keeping its cause.
func pathless(err error) error {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	var le *os.LinkError
	if errors.As(err, &le) {
		return le.Err
	}
	return err
}

// copyHash is the hash of the copy at path, or "" when there is none.
func (s *Server) copyHash(path string) string {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return ""
	}
	s.mu.Lock()
	cached, ok := s.hashes[path]
	s.mu.Unlock()
	if ok && cached.size == info.Size() && cached.mtime.Equal(info.ModTime()) {
		return cached.hash
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return ""
	}
	defer f.Close()
	// No copy is larger than the largest catalog limit; one that is can't
	// match anything the exit holds.
	data, err := io.ReadAll(io.LimitReader(f, maxCopy+1))
	if err != nil || int64(len(data)) > maxCopy {
		return ""
	}
	h := Hash(data)
	s.mu.Lock()
	if s.hashes == nil {
		s.hashes = map[string]cachedHash{}
	}
	s.hashes[path] = cachedHash{size: info.Size(), mtime: info.ModTime(), hash: h}
	s.mu.Unlock()
	return h
}

// contact records a request from the exit, and the file it delivered when
// name is set, and writes the link state.
func (s *Server) contact(ex Exit, r *http.Request, now time.Time, name, hash string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.links == nil {
		s.links = map[string]*link{}
	}
	l := s.links[ex.ID]
	if l == nil {
		l = &link{files: map[string]received{}}
		s.links[ex.ID] = l
	}
	l.contact = now
	l.offset = nil
	if sent, err := time.Parse(time.RFC3339Nano, r.Header.Get(SentAtHeader)); err == nil {
		offset := math.Round(sent.Sub(now).Seconds()*10) / 10
		l.offset = &offset
	}
	if name != "" {
		l.files[name] = received{at: now, hash: hash}
	}
	files := validate.Obj{}
	for _, n := range Files {
		if f, ok := l.files[n]; ok {
			files = append(files, validate.Pair{Key: n, Value: validate.Members("received_at", validate.FormatTime(f.at), "sha256", f.hash)})
		}
	}
	var offset any
	if l.offset != nil {
		offset = *l.offset
	}
	state := validate.Members("schema", Schema, "exit", ex.ID, "last_contact_at", validate.FormatTime(now),
		"clock_offset_s", offset, "files", files)
	if err := jsonfile.Write(ex.LinkPath(), state, jsonfile.Options{Public: true, NoSync: true, MaxBytes: LinkLimit}); err != nil {
		s.logf("cannot write the link state for exit %s: %v", ex.ID, pathless(err))
	}
}

// maxCopy bounds the copy copyHash reads.
const maxCopy = 64 << 20

// LinkLimit bounds exchange.json.
const LinkLimit = 4096
