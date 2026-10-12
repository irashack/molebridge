package panel

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/irashack/molebridge/internal/validate"
	"github.com/irashack/molebridge/internal/verdict"
)

// textJSON is every word the page shows about an exit's status (app.py's
// TEXT), for the HTML here and for the page script, which receives this
// table in the page (data-text) and has no wording of its own. Only fixed
// text: nothing from a record. The bytes are what json.dumps(TEXT,
// separators=(',', ':')) wrote, and are embedded in the page as they are.
const textJSON = `{"connection":{"overlay":{"ok":"Secure connection","applying":"Switching route","failed":"Connection needs attention","unknown":"Connection unverified"},"sidecar":{"ok":"Secure connection","applying":"Switching server","failed":"Connection needs attention","unknown":"Connection unverified"}},"tier":{"provider":"provider-confirmed","tunnel":"tunnel checks only","none":"not confirmed"},"failed":"Tunnel verification failed.","stale":"Status is stale or unavailable. Details are from the last check.","unverified":"The connection can't be confirmed. Details are from the last check.","unreachable":"Cannot reach the panel. Connection status is unknown.","drop":{"overlay":"Open connections through the exit will drop.","sidecar":"Open connections through the tunnel will drop."},"gives_up":"Verification gives up after {s} seconds.","next":{"recheck":"Re-checking at {at} UTC.","reapply":"Retrying at {at} UTC."},"checks":{"routing":"Routing protection","netbird":"NetBird kernel mode","owner_record":"Owner record","peer":"Tunnel peer","handshake":"Handshake","egress":"Egress check","traffic_protection":"Traffic protection","app_attachment":"App attachment"},"check_state":{"pass":"passed","fail":"failed","unknown":"unknown","n/a":"not applicable","legacy":"not reported individually"},"not_checked":"not checked by Molebridge ({by})","handshake_age":", {age} s old","reason":{"no-peer":"no tunnel peer","multiple-peers":"more than one tunnel peer","catalogue-stale":"no fresh server list","unidentified":"peer not in the server list","not-target":"not the selected server","unanswered":"the check got no answer","not-confirmed":"not confirmed by the provider","tunnel-checks-failed":"tunnel checks failed","host-address-not-measurable":"this host's address can't be measured","reconnecting":"gluetun is reconnecting"},"reason_format":"{text}: {reason}"}`

// wording is textJSON, read once.
type wording struct {
	Connection   map[string]map[string]string `json:"connection"`
	Tier         map[string]string            `json:"tier"`
	Failed       string                       `json:"failed"`
	Stale        string                       `json:"stale"`
	Unverified   string                       `json:"unverified"`
	Unreachable  string                       `json:"unreachable"`
	Drop         map[string]string            `json:"drop"`
	GivesUp      string                       `json:"gives_up"`
	Next         map[string]string            `json:"next"`
	Checks       map[string]string            `json:"checks"`
	CheckState   map[string]string            `json:"check_state"`
	NotChecked   string                       `json:"not_checked"`
	HandshakeAge string                       `json:"handshake_age"`
	Reason       map[string]string            `json:"reason"`
	ReasonFormat string                       `json:"reason_format"`
}

// text is the parsed wording table; it never changes after start.
var text = func() wording {
	var w wording
	if err := json.Unmarshal([]byte(textJSON), &w); err != nil {
		panic("panel: wording table: " + err.Error())
	}
	return w
}()

// exitView is the part of /api/status's `verdict` that describe reads.
type exitView struct {
	State        string
	Label        string
	Kind         string
	Tier         string
	Message      *string
	Reasons      []string
	NextAction   string
	NextActionAt string
	NotCheckedBy map[string]string
	Checks       map[string]string
}

// CheckView is one line of Diagnostics.
type CheckView struct {
	Name  string
	Label string
	State string
	Text  string
}

// View is everything the page says about an exit's status: plain text,
// unescaped. panel.js describe is the same function; the JS tests check that
// they agree.
type View struct {
	State      string
	Label      string
	Kind       string
	Connection string
	Tier       string // "" for none
	TunnelOnly bool
	IP         string
	Note       string
	Next       string
	Status     string
	Message    string
	Egress     string
	EgressTier string
	Forwarded  string
	CheckedAt  string
	Checks     []CheckView
}

// JSONObject is the view as the browser tests and the server's own tests
// compare it: Python describe()'s dict, in its member order.
func (v View) JSONObject() validate.Obj {
	checks := make([]any, len(v.Checks))
	for i, c := range v.Checks {
		checks[i] = validate.Members("name", c.Name, "label", c.Label, "state", c.State, "text", c.Text)
	}
	var tier any
	if v.Tier != "" {
		tier = v.Tier
	}
	return validate.Members(
		"state", v.State, "label", v.Label, "kind", v.Kind, "connection", v.Connection,
		"tier", tier, "tunnel_only", v.TunnelOnly, "ip", v.IP, "note", v.Note, "next", v.Next,
		"fields", validate.Members("status", v.Status, "message", v.Message, "egress", v.Egress,
			"egress_tier", v.EgressTier, "forwarded_port", v.Forwarded, "checked_at", v.CheckedAt),
		"checks", checks)
}

func textOr(value any, fallback string) string {
	if s, ok := value.(string); ok {
		return s
	}
	return fallback
}

// checkText is how Diagnostics shows one check. panel.js checkText says the
// same.
func checkText(name, state string, result map[string]any, by map[string]string) string {
	if state == "not-checked" {
		who := by[name]
		if who == "" {
			who = "another component"
		}
		return strings.ReplaceAll(text.NotChecked, "{by}", who)
	}
	out, known := text.CheckState[state]
	if !known {
		out = text.CheckState["unknown"]
	}
	checks, _ := result["checks"].(map[string]any)
	check, _ := checks[name].(map[string]any)
	if name == "handshake" && (state == "pass" || state == "fail") {
		if age, ok := validate.IsInt(check["age_s"]); ok {
			out += strings.ReplaceAll(text.HandshakeAge, "{age}", strconv.FormatInt(age, 10))
		}
	}
	if reason, ok := check["reason"].(string); ok && state == "fail" {
		if phrase, known := text.Reason[reason]; known {
			out = strings.ReplaceAll(strings.ReplaceAll(text.ReasonFormat, "{text}", out), "{reason}", phrase)
		}
	}
	return out
}

// describe builds the View from /api/status's verdict and result.
func describe(v exitView, result map[string]any) View {
	state := v.State
	kind := v.Kind
	if kind != "overlay" && kind != "sidecar" {
		kind = "overlay"
	}
	tier := ""
	if state == "ok" && (v.Tier == "provider" || v.Tier == "tunnel") {
		tier = v.Tier
	}
	message := ""
	if v.Message != nil {
		message = *v.Message
	}
	note := ""
	switch state {
	case "failed":
		note = message
		if note == "" {
			note = text.Failed
		}
	case "unknown":
		note = message
		if note == "" {
			stale := false
			for _, r := range v.Reasons {
				if r == "status-stale" || r == "no-status" {
					stale = true
				}
			}
			if stale {
				note = text.Stale
			} else {
				note = text.Unverified
			}
		}
	}
	upcoming := ""
	if state == "failed" || state == "unknown" {
		if pattern, ok := text.Next[v.NextAction]; ok && v.NextActionAt != "" {
			upcoming = strings.ReplaceAll(pattern, "{at}", runeSlice(v.NextActionAt, 11, 19))
		}
	}
	forwarded := "none"
	if port, ok := validate.IsInt(result["forwarded_port"]); ok {
		forwarded = strconv.FormatInt(port, 10)
	}
	ip := "—"
	if egressIP, ok := result["egress_ip"].(string); ok && state == "ok" && egressIP != "" {
		ip = egressIP
	}
	tierKey := tier
	if tierKey == "" {
		tierKey = "none"
	}
	view := View{
		State: state, Label: v.Label, Kind: kind, Connection: text.Connection[kind][state],
		Tier: tier, TunnelOnly: tier == "tunnel",
		IP: ip, Note: note, Next: upcoming,
		Status:     textOr(result["status"], "(unknown)"),
		Message:    textOr(result["message"], ""),
		Egress:     textOr(result["egress_city"], "(unknown)") + ", " + textOr(result["egress_country"], "(unknown)"),
		EgressTier: text.Tier[tierKey],
		Forwarded:  forwarded,
		CheckedAt:  textOr(result["checked_at"], "(unknown)"),
	}
	for _, name := range verdict.CheckNames {
		checkState := v.Checks[name]
		if checkState == "" {
			checkState = "unknown"
		}
		view.Checks = append(view.Checks, CheckView{
			Name: name, Label: text.Checks[name], State: checkState,
			Text: checkText(name, checkState, result, v.NotCheckedBy),
		})
	}
	return view
}

// runeSlice is s[from:to] on characters.
func runeSlice(s string, from, to int) string {
	runes := []rune(s)
	if from > len(runes) {
		return ""
	}
	if to > len(runes) {
		to = len(runes)
	}
	return string(runes[from:to])
}
