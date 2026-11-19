package proxy

import (
	"sync"
	"time"
)

// maxSessions bounds the session table; past it, a new session is served
// without a pin until expired ones are dropped.
const maxSessions = 10000

type pin struct {
	server   string
	lastUsed time.Time
}

// sessions are the pinned servers by location and session name. A session
// keeps its server while the Upstream keeps returning it (it chooses again
// once the server is benched) and the session has been used within
// SessionTTL.
type sessions struct {
	now func() time.Time
	mu  sync.Mutex
	m   map[string]pin
}

func newSessions(now func() time.Time) *sessions {
	return &sessions{now: now, m: map[string]pin{}}
}

func sessionKey(location, session string) string { return location + "." + session }

// pinned is the session's server, or "" for none (no session, a new one or
// an expired one).
func (s *sessions) pinned(location, session string) string {
	if session == "" {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.m[sessionKey(location, session)]
	if !ok || s.now().Sub(p.lastUsed) > SessionTTL {
		return ""
	}
	return p.server
}

// update records a connection of the session through server ("" when the
// Upstream returned none: the pin, if any, stays, and only its use counts).
func (s *sessions) update(location, session, server string) {
	if session == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := sessionKey(location, session)
	now := s.now()
	p, ok := s.m[key]
	if ok && now.Sub(p.lastUsed) > SessionTTL {
		p, ok = pin{}, false
	}
	if !ok && len(s.m) >= maxSessions {
		s.expireLocked(now)
		if len(s.m) >= maxSessions {
			return
		}
	}
	if server != "" {
		p.server = server
	}
	p.lastUsed = now
	s.m[key] = p
}

// active drops expired sessions and counts the rest.
func (s *sessions) active() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked(s.now())
	return len(s.m)
}

func (s *sessions) expireLocked(now time.Time) {
	for k, p := range s.m {
		if now.Sub(p.lastUsed) > SessionTTL {
			delete(s.m, k)
		}
	}
}
