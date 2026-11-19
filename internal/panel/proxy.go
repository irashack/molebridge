package panel

import (
	"strconv"
	"strings"

	"github.com/irashack/molebridge/internal/validate"
	"github.com/irashack/molebridge/internal/verdict"
)

// The proxy view (docs/switchyard.md, "The proxy view"): an exit's proxy,
// shown beside it when PANEL_PROXY_STATUS names the proxy's status file. It
// is read-only and separate from the exit: nothing here reads or changes the
// exit's record, verdict, label or switching, and the exit's verdict is
// never computed from proxy.json.

// proxyBenchShown is how many benched servers the page lists; panel.js
// describeProxy lists as many.
const proxyBenchShown = 50

// proxyStates are the states the proxy view shows.
var proxyStates = []string{"ok", "refusing", "failed", "unknown"}

// proxyPayload is /api/status's `proxy`: the proxy's verdict and, only once
// AssessProxy has validated the record, the record's details. Nothing of an
// unvalidated record is passed on.
func (s *Server) proxyPayload(ex Exit) validate.Obj {
	record := verdict.ReadProxy(ex.ProxyPath)
	v := verdict.AssessProxy(record, ex.Provider, s.now())
	reasons := []any{}
	for _, r := range v.Reasons {
		reasons = append(reasons, r)
	}
	var message, tunnel any
	if v.Message != nil {
		message = *v.Message
	}
	if v.Tunnel != "" {
		tunnel = v.Tunnel
	}
	var checkedAt, listen, sessions, connections, servers any
	if r, ok := record.(map[string]any); ok && v.State != "unknown" {
		checkedAt, listen = r["checked_at"], r["listen"]
		sessions = proxyCount(r["sessions"])
		conn, _ := r["connections"].(map[string]any)
		connections = validate.Members("open", proxyCount(conn["open"]), "total", proxyCount(conn["total"]),
			"failed", proxyCount(conn["failed"]))
		known, _ := r["servers"].(map[string]any)
		list, _ := known["benched"].([]any)
		benched := make([]any, 0, len(list))
		for _, entry := range list {
			b, _ := entry.(map[string]any)
			benched = append(benched, validate.Members("server", b["server"], "until", b["until"], "reason", b["reason"]))
		}
		servers = validate.Members("known", proxyCount(known["known"]), "benched", benched)
	}
	// The guarantee is the proxy role's, not the file's: it holds whatever
	// the file says, and is stated even while the status is unknown.
	return validate.Members("guarantee", "opt-in", "state", v.State, "label", v.Label, "reasons", reasons,
		"message", message, "tunnel", tunnel, "checked_at", checkedAt, "listen", listen, "sessions", sessions,
		"connections", connections, "servers", servers)
}

// proxyCount is a validated record's count.
func proxyCount(v any) int64 {
	n, _ := validate.IsInt(v)
	return n
}

// BenchedView is one benched server as the page lists it.
type BenchedView struct {
	Server string
	Until  string
	Reason string
}

// ProxyView is everything the page says about the proxy: plain text,
// unescaped. panel.js describeProxy is the same function, and the JS tests
// check that they agree.
type ProxyView struct {
	State     string
	Label     string
	Guarantee string
	Note      string

	Listen      string
	Sessions    string
	Connections string
	Servers     string
	Message     string
	CheckedAt   string

	Benched []BenchedView
	More    string
}

// JSONObject is the view as the browser tests compare it.
func (v ProxyView) JSONObject() validate.Obj {
	benched := make([]any, len(v.Benched))
	for i, b := range v.Benched {
		benched[i] = validate.Members("server", b.Server, "until", b.Until, "reason", b.Reason)
	}
	return validate.Members("state", v.State, "label", v.Label, "guarantee", v.Guarantee, "note", v.Note,
		"fields", validate.Members("listen", v.Listen, "sessions", v.Sessions, "connections", v.Connections,
			"servers", v.Servers, "message", v.Message, "checked_at", v.CheckedAt),
		"benched", benched, "more", v.More)
}

// describeProxy builds the ProxyView from /api/status's `proxy`, decoded.
func describeProxy(p map[string]any) ProxyView {
	w := text.Proxy
	state, _ := p["state"].(string)
	if !contains(proxyStates, state) {
		state = "unknown"
	}
	var notes []string
	reasons, _ := p["reasons"].([]any)
	for _, r := range reasons {
		if code, ok := r.(string); ok {
			if phrase, known := w.Reason[code]; known {
				notes = append(notes, phrase)
			}
		}
	}
	view := ProxyView{
		State: state, Label: textOr(p["label"], ""), Guarantee: w.Guarantee, Note: strings.Join(notes, " "),
		Listen: textOr(p["listen"], w.None), Sessions: w.None, Connections: w.None, Servers: w.None,
		Message: textOr(p["message"], w.None), CheckedAt: textOr(p["checked_at"], w.None),
		Benched: []BenchedView{},
	}
	if n, ok := validate.IsInt(p["sessions"]); ok {
		view.Sessions = strconv.FormatInt(n, 10)
	}
	if c, ok := p["connections"].(map[string]any); ok {
		open, ok1 := validate.IsInt(c["open"])
		total, ok2 := validate.IsInt(c["total"])
		failed, ok3 := validate.IsInt(c["failed"])
		if ok1 && ok2 && ok3 {
			view.Connections = strings.NewReplacer("{open}", strconv.FormatInt(open, 10),
				"{total}", strconv.FormatInt(total, 10), "{failed}", strconv.FormatInt(failed, 10)).Replace(w.Connections)
		}
	}
	if s, ok := p["servers"].(map[string]any); ok {
		known, okKnown := validate.IsInt(s["known"])
		list, okList := s["benched"].([]any)
		if okKnown && okList {
			view.Servers = strings.NewReplacer("{known}", strconv.FormatInt(known, 10),
				"{benched}", strconv.Itoa(len(list))).Replace(w.Servers)
			for i, entry := range list {
				if i == proxyBenchShown {
					view.More = strings.ReplaceAll(w.More, "{n}", strconv.Itoa(len(list)-proxyBenchShown))
					break
				}
				b, _ := entry.(map[string]any)
				view.Benched = append(view.Benched, BenchedView{
					Server: textOr(b["server"], w.None),
					Until:  strings.ReplaceAll(w.Until, "{at}", runeSlice(textOr(b["until"], ""), 11, 19)),
					Reason: textOr(b["reason"], ""),
				})
			}
		}
	}
	return view
}

// contains reports whether list holds value.
func contains(list []string, value string) bool {
	for _, v := range list {
		if v == value {
			return true
		}
	}
	return false
}

// proxyView is the proxy view for an exit: its payload, decoded as the
// browser decodes it, and described.
func (s *Server) proxyView(ex Exit) ProxyView {
	raw, err := validate.MarshalJSON(s.proxyPayload(ex))
	if err != nil {
		return describeProxy(map[string]any{"state": "unknown", "label": text.Proxy.Unavailable})
	}
	decoded, _ := validate.DecodeJSON(raw)
	m, _ := decoded.(map[string]any)
	return describeProxy(m)
}

// proxyNoteClass: a refusal is the proxy keeping its guarantee, shown as a
// caution; a failed or unknown proxy as a problem.
func proxyNoteClass(state string) string {
	if state == "refusing" {
		return "note"
	}
	return "note note-negative"
}

// renderProxy is the proxy view's section of the page. Read-only: no
// controls. The guarantee comes first.
func renderProxy(v ProxyView) string {
	noteHidden := ""
	if v.Note == "" {
		noteHidden = " hidden"
	}
	var rows strings.Builder
	for _, b := range v.Benched {
		rows.WriteString(`<li><span class="bench-server">` + esc(b.Server) + `</span>` +
			`<span class="bench-until subdue">` + esc(b.Until) + `</span>` +
			`<span class="bench-reason">` + esc(b.Reason) + `</span></li>`)
	}
	benchedHidden, moreHidden := "", ""
	if len(v.Benched) == 0 {
		benchedHidden = " hidden"
	}
	if v.More == "" {
		moreHidden = " hidden"
	}
	return fill(proxyTemplate, "state", esc(v.State), "label", esc(v.Label), "guarantee", esc(v.Guarantee),
		"noteClass", proxyNoteClass(v.State), "noteHidden", noteHidden, "note", esc(v.Note),
		"listen", esc(v.Listen), "sessions", esc(v.Sessions), "connections", esc(v.Connections),
		"servers", esc(v.Servers), "message", esc(v.Message), "checked", esc(v.CheckedAt),
		"benchedHidden", benchedHidden, "rows", rows.String(), "moreHidden", moreHidden, "more", esc(v.More))
}

const proxyTemplate = `<section class="widget proxy-widget" data-proxy aria-label="Proxy">
  <div class="widget-header"><h2>Proxy</h2><span class="pill pill-«state»" data-proxy-pill>«label»</span></div>
  <div class="widget-content proxy" data-proxy-state="«state»">
    <p class="proxy-guarantee">«guarantee»</p>
    <p class="«noteClass»" data-proxy-note«noteHidden»>«note»</p>
    <dl>
      <dt>Listening on</dt><dd data-proxy-f="listen">«listen»</dd>
      <dt>Sessions</dt><dd data-proxy-f="sessions">«sessions»</dd>
      <dt>Connections</dt><dd data-proxy-f="connections">«connections»</dd>
      <dt>Servers</dt><dd data-proxy-f="servers">«servers»</dd>
      <dt>Message</dt><dd data-proxy-f="message">«message»</dd>
      <dt>Checked</dt><dd data-proxy-f="checked_at">«checked»</dd>
    </dl>
    <div class="proxy-benched" data-proxy-benched-block«benchedHidden»>
      <h3>Benched</h3>
      <ul class="bench-list" data-proxy-benched>«rows»</ul>
      <p class="subdue small" data-proxy-more«moreHidden»>«more»</p>
    </div>
  </div>
</section>
`
