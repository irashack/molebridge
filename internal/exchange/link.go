package exchange

import (
	"math"
	"time"

	"github.com/irashack/molebridge/internal/jsonfile"
	"github.com/irashack/molebridge/internal/validate"
)

// Link is the link state the exchange writes for an exit (exchange.json):
// when it last heard from the exit, on the exchange's own clock, and the
// offset between the two clocks when the exit sent one.
type Link struct {
	LastContact time.Time
	// Offset is the exit's clock minus the exchange's, in seconds; nil when
	// the exit sent no time.
	Offset *float64
}

// ReadLink reads exchange.json strictly; false when it is missing, unsafe or
// not a schema 1 link state.
func ReadLink(path string) (Link, bool) {
	m, ok := jsonfile.ReadObject(path, LinkLimit)
	if !ok {
		return Link{}, false
	}
	if schema, ok := m["schema"].(int64); !ok || schema != Schema {
		return Link{}, false
	}
	at, ok := validate.ParseTime(m["last_contact_at"])
	if !ok {
		return Link{}, false
	}
	l := Link{LastContact: at}
	switch v := m["clock_offset_s"].(type) {
	case nil:
	case float64:
		l.Offset = &v
	case int64:
		f := float64(v)
		l.Offset = &f
	default:
		return Link{}, false
	}
	return l, true
}

// Judge is the link's verdict for an exit reached over the network: "" when
// the panel may judge the copy of its record, else the reason code and label
// that replace the verdict. No link state, or none for UnreachableAfter, is
// exit-unreachable; a clock offset past SkewLimit is clock-skew.
func Judge(l Link, ok bool, now time.Time) (reason, label string) {
	switch {
	case !ok || now.Sub(l.LastContact) > UnreachableAfter:
		return "exit-unreachable", "exit unreachable"
	case l.Offset != nil && math.Abs(*l.Offset) > SkewLimit.Seconds():
		return "clock-skew", "clocks differ"
	}
	return "", ""
}
