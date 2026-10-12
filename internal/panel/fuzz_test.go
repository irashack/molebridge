package panel

// Fuzz targets for what a browser or a proxy controls: form posts, query
// strings, request targets, cookie headers and Host/Origin values. None may
// panic, and the host checks never allow what they cannot parse.

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func FuzzParseSelectForm(f *testing.F) {
	for _, seed := range []string{"server=se-sto-wg-001&csrf_token=abc", "a=%zz&b=%e2%82&c", "&&&=&=", "exit=a+b%20c", "x=\xff\xfe"} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		fields := parseSelectForm(body)
		for name, value := range fields {
			if !utf8.ValidString(name) || !utf8.ValidString(value) {
				t.Fatalf("invalid UTF-8 field %q=%q", name, value)
			}
		}
		parseQS(string(body), false)
	})
}

func FuzzSplitTarget(f *testing.F) {
	for _, seed := range []string{"/", "//host/x", "http://h/p?q=1#f", "/a?b", "", "///", "x://", "?"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, target string) {
		path, query := splitTarget(target)
		if strings.ContainsAny(path, "?#") && !strings.HasPrefix(target, path) {
			t.Fatalf("path %q is not part of %q", path, target)
		}
		_ = query
	})
}

func FuzzCookies(f *testing.F) {
	for _, seed := range []string{"a=b; c=d", `csrf_nonce="x\"y"; Path=/`, "a=b c=d", "$Version=1; a=b", "a=; ;; =b", "\x00=\xff"} {
		f.Add(seed, "csrf_nonce")
	}
	f.Fuzz(func(t *testing.T, header, name string) {
		getCookie(header, name)
		value, ok := getCookieStrict(header, name)
		if ok && strings.Contains(header, ";") && strings.Count(header, name+"=") > 1 && strings.Count(header, ";") > 0 {
			// Repeated names must refuse, never pick one.
			parts := 0
			for _, p := range strings.Split(header, ";") {
				if k, _, _ := strings.Cut(strings.Trim(p, " \t"), "="); k == name {
					parts++
				}
			}
			if parts > 1 {
				t.Fatalf("strict parse took %q from %q", value, header)
			}
		}
	})
}

func FuzzHostAndOrigin(f *testing.F) {
	for _, seed := range []string{"exit.example.test", "[::1]:8095", "a@b", "http://[", "https://exit.example.test:443", "x:99999", ""} {
		f.Add(seed)
	}
	s := settingsWithHosts("exit.example.test,other.example.test:8443")
	f.Fuzz(func(t *testing.T, value string) {
		s.HostAllowed(value)
		if s.OriginAllowed(value) && value != "" {
			lower := strings.ToLower(value) // the scheme is case-insensitive, as in urlsplit
			if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
				t.Fatalf("allowed Origin %q", value)
			}
		}
	})
}
