package pystr

import "testing"

func TestEscapeMatchesPython(t *testing.T) {
	if got := Escape(`a&b<c>d"e'f`); got != "a&amp;b&lt;c&gt;d&quot;e&#x27;f" {
		t.Fatalf("Escape = %q", got)
	}
}

func TestStripAndFields(t *testing.T) {
	if got := Strip("\x1c a b \x1f"); got != "a b" {
		t.Fatalf("Strip = %q", got)
	}
	got := Fields("  a \x1db\tc ")
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("Fields = %q", got)
	}
}

func TestIsPrintable(t *testing.T) {
	for s, want := range map[string]bool{"": true, "a b": true, "é": true, "a\x07": false, "a\u200bb": false, "a\nb": false, "a b": false} {
		if IsPrintable(s) != want {
			t.Errorf("IsPrintable(%q) = %v", s, !want)
		}
	}
}

func TestEncodeAndQuote(t *testing.T) {
	if got := Encode(Pair{"next", "/?exit=a b"}, Pair{"x", "é"}); got != "next=%2F%3Fexit%3Da+b&x=%C3%A9" {
		t.Fatalf("Encode = %q", got)
	}
	if got := Quote("s3cr3t/value+x ~"); got != "s3cr3t%2Fvalue%2Bx%20~" {
		t.Fatalf("Quote = %q", got)
	}
}

func TestReprMatchesPython(t *testing.T) {
	// Each want is what Python 3's repr() prints for the same text.
	for _, tc := range []struct{ in, want string }{
		{"", `''`},
		{"abc", `'abc'`},
		{"a b", `'a b'`},
		// Double quotes when the text holds a single quote and no double one.
		{"it's", `"it's"`},
		{`say "hi"`, `'say "hi"'`},
		{`both ' and "`, `'both \' and "'`},
		{`back\slash`, `'back\\slash'`},
		{`"it's" \`, `'"it\'s" \\'`},
		{"a\nb\rc\td", `'a\nb\rc\td'`},
		{"\x00\x1b\x7f", `'\x00\x1b\x7f'`},
		{"\u0080\u00a0\u00ad", `'\x80\xa0\xad'`},
		{"é ü ß", `'é ü ß'`},
		{"\u200b\u2028\u0378", `'\u200b\u2028\u0378'`},
		{"\U000e0001", `'\U000e0001'`},
		{"\U0001f600", "'\U0001f600'"},
	} {
		if got := Repr(tc.in); got != tc.want {
			t.Errorf("Repr(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
}
