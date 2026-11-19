package tunneldial

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestCanonicalName(t *testing.T) {
	good := map[string]string{
		"se-got-wg-socks5-001.relays.mullvad.net": "se-got-wg-socks5-001.relays.mullvad.net",
		"Example.NET.":      "example.net",
		"_srv.example.test": "_srv.example.test",
		"a":                 "a",
	}
	for in, want := range good {
		if got, err := canonicalName(in); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	bad := []string{"", ".", "192.0.2.1", "2001:db8::1", "a..b", "-a.test", "a-.test", "a b.test",
		"a/b.test", "ex\x00ample.test", "exämple.test", strings.Repeat("a", 64) + ".test",
		strings.Repeat("a.", 127) + "aa"}
	for _, in := range bad {
		if _, err := canonicalName(in); !errors.Is(err, ErrName) {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestBuildQuery(t *testing.T) {
	got := buildQuery(0xBEEF, "a.example.test", TypeAAAA)
	want := []byte{0xBE, 0xEF, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
		1, 'a', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 4, 't', 'e', 's', 't', 0, 0, 28, 0, 1}
	if !bytes.Equal(got, want) {
		t.Fatalf("% x", got)
	}
}

const testName = "relay.example.test"

func TestParseAnswerA(t *testing.T) {
	q := buildQuery(7, testName, TypeA)
	got, err := parseAnswer(reply(q, 0, aRecord("192.0.2.1"), aRecord("192.0.2.2")), 7, testName, TypeA)
	want := []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("%v %v", got, err)
	}
}

func TestParseAnswerAAAAAndCase(t *testing.T) {
	q := buildQuery(7, testName, TypeAAAA)
	ip := netip.MustParseAddr("2001:db8::1").As16()
	// The owner in another case still names the question.
	msg := reply(q, 0, testRR{owner: "RELAY.Example.TEST", rtype: TypeAAAA, data: ip[:]})
	got, err := parseAnswer(msg, 7, testName, TypeAAAA)
	if err != nil || len(got) != 1 || got[0] != netip.MustParseAddr("2001:db8::1") {
		t.Fatalf("%v %v", got, err)
	}
}

func TestParseAnswerFollowsCNAMEs(t *testing.T) {
	q := buildQuery(7, testName, TypeA)
	msg := reply(q, 0,
		testRR{rtype: TypeCNAME, data: wireName("mid.example.test")},
		testRR{owner: "other.example.test", rtype: TypeA, data: []byte{198, 51, 100, 9}},
		testRR{owner: "mid.example.test", rtype: TypeCNAME, data: wireName("end.example.test")},
		testRR{owner: "end.example.test", rtype: TypeA, data: []byte{192, 0, 2, 7}})
	got, err := parseAnswer(msg, 7, testName, TypeA)
	if err != nil || len(got) != 1 || got[0] != netip.MustParseAddr("192.0.2.7") {
		t.Fatalf("%v %v", got, err)
	}
}

func TestParseAnswerIgnoresOtherClassesAndTypes(t *testing.T) {
	q := buildQuery(7, testName, TypeA)
	msg := reply(q, 0,
		testRR{rtype: TypeA, class: 3, data: []byte{198, 51, 100, 1}},
		testRR{rtype: 16, data: []byte("\x04text")},
		aRecord("192.0.2.3"))
	got, err := parseAnswer(msg, 7, testName, TypeA)
	if err != nil || len(got) != 1 || got[0] != netip.MustParseAddr("192.0.2.3") {
		t.Fatalf("%v %v", got, err)
	}
}

func TestParseAnswerRefusals(t *testing.T) {
	q := buildQuery(7, testName, TypeA)
	good := reply(q, 0, aRecord("192.0.2.1"))
	edit := func(f func(m []byte) []byte) []byte { return f(append([]byte(nil), good...)) }
	setFlags := func(flags uint16) []byte {
		return edit(func(m []byte) []byte { binary.BigEndian.PutUint16(m[2:], flags); return m })
	}
	cases := []struct {
		name string
		msg  []byte
		want error
	}{
		{"short", good[:11], ErrMalformed},
		{"too long", append(append([]byte(nil), good...), make([]byte, MaxMessage)...), ErrMalformed},
		{"other id", edit(func(m []byte) []byte { m[1] = 8; return m }), ErrMismatch},
		{"a query", setFlags(0x0100), ErrMismatch},
		{"another opcode", setFlags(0x8000 | 2<<11), ErrMismatch},
		{"truncated", setFlags(0x8380), ErrTruncated},
		{"two questions", edit(func(m []byte) []byte { m[5] = 2; return m }), ErrMismatch},
		{"no question", edit(func(m []byte) []byte { m[5] = 0; return m }), ErrMismatch},
		{"other name", reply(buildQuery(7, "other.example.test", TypeA), 0, aRecord("192.0.2.1")), ErrMismatch},
		{"other type", reply(buildQuery(7, testName, TypeAAAA), 0, aRecord("192.0.2.1")), ErrMismatch},
		{"other class", edit(func(m []byte) []byte { m[headerLen+len(wireName(testName))+3] = 3; return m }), ErrMismatch},
		{"servfail", reply(q, 2), ErrServFail},
		{"nxdomain", reply(q, 3), ErrNotFound},
		{"refused", reply(q, 5), ErrRefused},
		{"no answer", reply(q, 0), ErrNoAddress},
		{"short A", reply(q, 0, testRR{rtype: TypeA, data: []byte{192, 0, 2}}), ErrMalformed},
		{"long A", reply(q, 0, testRR{rtype: TypeA, data: make([]byte, 16)}), ErrMalformed},
		{"rdata past the end", good[:len(good)-1], ErrMalformed},
		{"more answers than records", edit(func(m []byte) []byte { m[7] = 2; return m }), ErrMalformed},
		{"too many answers", edit(func(m []byte) []byte { m[6], m[7] = 0, maxAnswers+1; return m }), ErrMalformed},
		{"forward pointer", edit(func(m []byte) []byte {
			at := len(q)
			m[at], m[at+1] = 0xC0, byte(at+2)
			return m
		}), ErrMalformed},
		{"self pointer", edit(func(m []byte) []byte {
			at := len(q)
			m[at], m[at+1] = 0xC0, byte(at)
			return m
		}), ErrMalformed},
		{"reserved label type", edit(func(m []byte) []byte { m[len(q)] = 0x40; return m }), ErrMalformed},
		{"control byte in a label", reply(q, 0, testRR{owner: "a\x01.b", rtype: TypeA, data: []byte{192, 0, 2, 1}}), ErrMalformed},
		{"CNAME loop", reply(q, 0,
			testRR{rtype: TypeCNAME, data: wireName("x.example.test")},
			testRR{owner: "x.example.test", rtype: TypeCNAME, data: wireName(testName)}), ErrMalformed},
		{"CNAME with trailing data", reply(q, 0, testRR{rtype: TypeCNAME, data: append(wireName("x.test"), 0)}), ErrMalformed},
		{"two CNAMEs for one name", reply(q, 0,
			testRR{rtype: TypeCNAME, data: wireName("x.test")},
			testRR{rtype: TypeCNAME, data: wireName("y.test")}), ErrMalformed},
		{"CNAME without its address", reply(q, 0, testRR{rtype: TypeCNAME, data: wireName("x.test")}), ErrNoAddress},
	}
	for _, c := range cases {
		if got, err := parseAnswer(c.msg, 7, testName, TypeA); !errors.Is(err, c.want) || got != nil {
			t.Errorf("%s: %v %v, want %v", c.name, got, err, c.want)
		}
	}
}

func TestReadNameBoundsLength(t *testing.T) {
	// Five 63-byte labels are 320 bytes on the wire, past the 255 limit.
	var msg []byte
	for i := 0; i < 5; i++ {
		msg = append(msg, 63)
		msg = append(msg, bytes.Repeat([]byte{'a'}, 63)...)
	}
	msg = append(msg, 0)
	if _, _, err := readName(msg, 0); !errors.Is(err, ErrMalformed) {
		t.Fatal(err)
	}
	// A chain of backward pointers past the bound.
	msg = []byte{0}
	for i := 0; i <= maxPointers; i++ {
		at := len(msg) - 2
		if i == 0 {
			at = 0
		}
		msg = append(msg, 0xC0, byte(at))
	}
	if _, _, err := readName(msg, len(msg)-2); !errors.Is(err, ErrMalformed) {
		t.Fatal(err)
	}
}

// FuzzParseAnswer checks that no message panics or reads past its end.
func FuzzParseAnswer(f *testing.F) {
	q := buildQuery(7, testName, TypeA)
	f.Add(reply(q, 0, aRecord("192.0.2.1")))
	f.Add(reply(q, 0, testRR{rtype: TypeCNAME, data: wireName("x.test")}, testRR{owner: "x.test", rtype: TypeA, data: []byte{1, 2, 3, 4}}))
	f.Fuzz(func(t *testing.T, msg []byte) {
		_, _ = parseAnswer(msg, 7, testName, TypeA)
	})
}
