package contract

// Ported from tools/test_owner_record.py. The shell/Python agreement tests
// have no Go counterpart: the shell reader goes away with the shell, and the
// Go reader is the only one left.

import (
	"net/netip"
	"strings"
	"testing"
)

const (
	bootID = "00000000-0000-4000-8000-0000000000aa"
	line   = "molebridge-exit 1 " + bootID + " 1000 5:4026531992 0a0a 203.0.113.1 2001:db8:3::1 conf 2 990\n"
)

func TestTheWrittenShapeParses(t *testing.T) { // test_the_written_shape_parses
	rec, ok := ParseOwnerRecord(line)
	if !ok {
		t.Fatal("refused")
	}
	want := OwnerRecord{Boot: bootID, Stamp: 1000, NetNS: "5:4026531992", Generation: "0a0a",
		Addr4: netip.MustParseAddr("203.0.113.1"), Addr6: netip.MustParseAddr("2001:db8:3::1"),
		Rule94: "conf", Repairs: 2, LastRepair: 990, HasLastRepair: true}
	if rec != want {
		t.Fatalf("%+v", rec)
	}
	rec, ok = ParseOwnerRecord("molebridge-exit 1 " + bootID + " 1000 5:1 0a0a - - applier 0 -\n")
	if !ok || rec.Addr4.IsValid() || rec.Addr6.IsValid() || rec.HasLastRepair {
		t.Fatalf("%+v %v", rec, ok)
	}
}

func TestOwnerRecordRoundTrips(t *testing.T) {
	for _, in := range []string{line, "molebridge-exit 1 " + bootID + " 1000 5:1 0a0a - - applier 0 -\n",
		"molebridge-exit 1 " + bootID + " 7 5:1 0a0a 203.0.113.1 - conf 0 -\n"} {
		rec, ok := ParseOwnerRecord(in)
		if !ok || rec.Format() != in {
			t.Errorf("%q: %q %v", in, rec.Format(), ok)
		}
	}
}

func TestAnythingElseIsRefused(t *testing.T) { // test_anything_else_is_refused
	for name, in := range map[string]string{
		"no newline":        strings.TrimSuffix(line, "\n"),
		"two lines":         line + line,
		"version 2":         strings.Replace(line, "molebridge-exit 1", "molebridge-exit 2", 1),
		"unknown owner":     strings.Replace(line, " conf ", " other ", 1),
		"leading zero":      strings.Replace(line, "203.0.113.1", "203.0.113.01", 1),
		"upper case":        strings.Replace(line, "2001:db8:3::1", "2001:DB8:3::1", 1),
		"not canonical":     strings.Replace(line, "2001:db8:3::1", "2001:db8:3:0::1", 1),
		"IPv6 in IPv4 slot": strings.Replace(line, "203.0.113.1 2001", "2001:db8::1 2001", 1),
		"applier with addr": strings.Replace(line, " conf ", " applier ", 1),
		"namespace":         strings.Replace(line, "5:4026531992", "5", 1),
		"negative stamp":    strings.Replace(line, " 1000 ", " -1 ", 1),
		"upper case id":     strings.Replace(line, " 0a0a ", " 0A0A ", 1),
		"bad last repair":   strings.Replace(line, " 990", " x", 1),
		"boot with spaces":  strings.Replace(line, bootID, "boot id", 1),
		"empty":             "",
		"too long":          strings.Repeat("x", 600) + "\n",
		"mapped address":    strings.Replace(line, "2001:db8:3::1", "::ffff:203.0.113.1", 1),
	} {
		if _, ok := ParseOwnerRecord(in); ok {
			t.Errorf("%s accepted", name)
		}
	}
}

func valid(age int, opts ...func(*validArgs)) bool {
	a := validArgs{boot: bootID, netns: "5:4026531992", line: line}
	for _, o := range opts {
		o(&a)
	}
	rec, ok := ParseOwnerRecord(a.line)
	return OwnerValid(rec, ok, a.boot, uint64(1000+age), a.netns, a.seen)
}

type validArgs struct {
	boot, netns, line string
	seen              *OwnerSeen
}

func TestValidityBoundaries(t *testing.T) { // test_validity_boundaries
	if OwnerExpiry != 6 {
		t.Fatal(OwnerExpiry)
	}
	if !valid(6) || valid(7) {
		t.Error("expiry")
	}
	if !valid(-1) || valid(-2) {
		t.Error("future")
	}
	if valid(0, func(a *validArgs) { a.boot = "00000000-0000-4000-8000-0000000000bb" }) {
		t.Error("another boot")
	}
	if valid(0, func(a *validArgs) { a.netns = "5:1" }) {
		t.Error("another namespace")
	}
	if !valid(0, func(a *validArgs) { a.seen = &OwnerSeen{"0a0a", 1000} }) || valid(0, func(a *validArgs) { a.seen = &OwnerSeen{"0a0a", 1001} }) {
		t.Error("went backwards")
	}
	if !valid(0, func(a *validArgs) { a.seen = &OwnerSeen{"0b0b", 1001} }) {
		t.Error("a new generation")
	}
	if valid(0, func(a *validArgs) { a.line = "garbage\n" }) {
		t.Error("garbage")
	}
}

func TestCanonical6(t *testing.T) {
	for in, want := range map[string]string{
		"2001:db8:3::1": "2001:db8:3::1", "::": "::", "::1": "::1", "1::": "1::",
		"2001:db8:0:0:1:0:0:1": "2001:db8::1:0:0:1", "2001:0:0:1:0:0:0:1": "2001:0:0:1::1",
		"1:2:3:4:5:6:7:8": "1:2:3:4:5:6:7:8", "1:0:3:4:5:6:7:8": "1:0:3:4:5:6:7:8",
		"::ffff:1.2.3.4": "::ffff:102:304", "fe80::1": "fe80::1",
	} {
		if got := Canonical6(netip.MustParseAddr(in)); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
}
