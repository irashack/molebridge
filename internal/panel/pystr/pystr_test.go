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
