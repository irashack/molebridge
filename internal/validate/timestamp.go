package validate

import (
	"regexp"
	"strconv"
	"time"
)

// TimeLayout is the timestamp format of every state file.
const TimeLayout = "2006-01-02T15:04:05Z"

// FormatTime is Python's now_iso() for the instant t: UTC, whole seconds,
// "%Y-%m-%dT%H:%M:%SZ".
func FormatTime(t time.Time) string { return t.UTC().Format(TimeLayout) }

// ParseTime reads exactly "YYYY-MM-DDTHH:MM:SSZ" with a valid calendar date
// and time (no leap seconds), and nothing else: the strict reading the
// verdict uses. The second result is false for anything but a string of that
// form. (The Python reader's \d also matches non-ASCII digits; this does not.)
func ParseTime(value any) (time.Time, bool) {
	s, ok := value.(string)
	if !ok || len(s) != 20 || s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' || s[16] != ':' || s[19] != 'Z' {
		return time.Time{}, false
	}
	num := func(from, to int) (int, bool) {
		n := 0
		for i := from; i < to; i++ {
			if s[i] < '0' || s[i] > '9' {
				return 0, false
			}
			n = n*10 + int(s[i]-'0')
		}
		return n, true
	}
	year, ok1 := num(0, 4)
	month, ok2 := num(5, 7)
	day, ok3 := num(8, 10)
	hour, ok4 := num(11, 13)
	minute, ok5 := num(14, 16)
	second, ok6 := num(17, 19)
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6) {
		return time.Time{}, false
	}
	return buildTime(year, month, day, hour, minute, second)
}

func buildTime(year, month, day, hour, minute, second int) (time.Time, bool) {
	if year < 1 || month < 1 || month > 12 || day < 1 || hour > 23 || minute > 59 || second > 59 {
		return time.Time{}, false
	}
	if day > daysIn(year, month) {
		return time.Time{}, false
	}
	return time.Date(year, time.Month(month), day, hour, minute, second, 0, time.UTC), true
}

func daysIn(year, month int) int {
	switch month {
	case 2:
		if year%4 == 0 && (year%100 != 0 || year%400 == 0) {
			return 29
		}
		return 28
	case 4, 6, 9, 11:
		return 30
	}
	return 31
}

// lenient is what Python's datetime.strptime accepts for
// '%Y-%m-%dT%H:%M:%SZ': one or two digits for the month, day, hour, minute
// and second (a day may be space padded), literals matched without regard to
// case.
var lenient = regexp.MustCompile(`(?i)^(\d{4})-(1[0-2]|0[1-9]|[1-9])-(3[0-1]|[1-2]\d|0[1-9]|[1-9]| [1-9])T` +
	`(2[0-3]|[0-1]\d|\d):([0-5]\d|\d):(6[0-1]|[0-5]\d|\d)Z$`)

func parseLenient(value any) (time.Time, bool) {
	s, ok := value.(string)
	if !ok {
		return time.Time{}, false
	}
	m := lenient.FindStringSubmatch(s)
	if m == nil {
		return time.Time{}, false
	}
	var n [6]int
	for i := range n {
		field := m[i+1]
		if field[0] == ' ' {
			field = field[1:]
		}
		n[i], _ = strconv.Atoi(field)
	}
	return buildTime(n[0], n[1], n[2], n[3], n[4], n[5])
}

// AgeSeconds is the Python state.age_seconds: the seconds from the timestamp
// to now, or false when value is not a string strptime would read. It is more
// lenient than ParseTime on purpose (it is what the readers of desired.json and
// the catalogue snapshot always used). A zero now means time.Now().
func AgeSeconds(value any, now time.Time) (float64, bool) {
	when, ok := parseLenient(value)
	if !ok {
		return 0, false
	}
	if now.IsZero() {
		now = time.Now()
	}
	return secondsBetween(now, when), true
}

// Recent reports whether value is a timestamp no newer than now and at most
// maxAge seconds old. It reads value leniently, as AgeSeconds does (one-digit
// fields, any case), and a zero now means time.Now(). Fresh takes the same
// arguments in the same order and is the strict reading.
func Recent(value any, maxAge float64, now time.Time) bool {
	age, ok := AgeSeconds(value, now)
	return ok && 0 <= age && age <= maxAge
}

// Fresh is the verdict's reading: a strictly formed timestamp (ParseTime),
// not in the future, at most maxAge seconds old. Unlike Recent it refuses any
// other spelling of the time, and now is used as given: a zero now is the
// year 1, not time.Now().
func Fresh(value any, maxAge float64, now time.Time) bool {
	when, ok := ParseTime(value)
	if !ok {
		return false
	}
	age := secondsBetween(now, when)
	return 0 <= age && age <= maxAge
}

// secondsBetween is a - b in seconds, without time.Duration's limit of about
// 292 years (a timestamp may be from the year 1 or 9999).
func secondsBetween(a, b time.Time) float64 {
	return float64(a.Unix()-b.Unix()) + float64(a.Nanosecond()-b.Nanosecond())/1e9
}
