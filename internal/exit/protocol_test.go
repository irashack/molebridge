package exit

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

const goodGen = "0123456789abcdef0123456789abcdef"

func TestRoundTrip(t *testing.T) {
	msgs := []Msg{
		{Type: TypeRenew, Gen: goodGen, Seq: 3, Loops: map[string]int64{"mutator": 1500000000, "watcher": 1600000000}},
		{Type: TypeReady, Gen: goodGen},
		{Type: TypeUnready, Gen: goodGen, Reason: "the routing contract cannot be restored"},
		{Type: TypeStatus, Gen: goodGen, Seq: 9, Record: map[string]any{"schema": int64(2), "status": "ok"}},
		{Type: TypeLog, Gen: goodGen, Level: "warn", Text: "something happened"},
	}
	for _, m := range msgs {
		b, err := m.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if b[len(b)-1] != '\n' || bytes.Count(b, []byte("\n")) != 1 {
			t.Fatalf("not exactly one line: %q", b)
		}
		got, err := DecodeFromWorker(b[:len(b)-1])
		if err != nil {
			t.Fatalf("%s: %v", m.Type, err)
		}
		if got.Type != m.Type || got.Gen != m.Gen || got.Seq != m.Seq || got.Reason != m.Reason || got.Text != m.Text {
			t.Errorf("%s: %+v", m.Type, got)
		}
	}
	back := []Msg{
		{Type: TypeAck, Gen: goodGen, Seq: 3, ExpiryBootNs: 99},
		{Type: TypeStop},
		{Type: TypeNetBird, Gen: goodGen, Launch: 2, State: NBLaunching, LogOffset: 1234, AtBootNs: 77},
	}
	for _, m := range back {
		b, err := m.Encode()
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecodeFromSupervisor(bytes.TrimSuffix(b, []byte("\n")))
		if err != nil {
			t.Fatalf("%s: %v", m.Type, err)
		}
		if got.Type != m.Type || got.ExpiryBootNs != m.ExpiryBootNs || got.Launch != m.Launch || got.State != m.State || got.LogOffset != m.LogOffset || got.AtBootNs != m.AtBootNs {
			t.Errorf("%s: %+v", m.Type, got)
		}
	}
}

func TestDecodeRefusesMalformedMessages(t *testing.T) {
	bad := map[string]string{
		"not json":              `{"type":`,
		"not an object":         `[1]`,
		"empty":                 ``,
		"duplicate member":      `{"type":"ready","gen":"` + goodGen + `","gen":"` + goodGen + `"}`,
		"unknown type":          `{"type":"hello"}`,
		"supervisor's type":     `{"type":"stop"}`,
		"missing type":          `{"gen":"` + goodGen + `"}`,
		"extra member":          `{"type":"ready","gen":"` + goodGen + `","x":1}`,
		"short gen":             `{"type":"ready","gen":"abc"}`,
		"upper-case gen":        `{"type":"ready","gen":"0123456789ABCDEF0123456789abcdef"}`,
		"gen not a string":      `{"type":"ready","gen":5}`,
		"negative seq":          `{"type":"renew","gen":"` + goodGen + `","seq":-1,"loops":{}}`,
		"fractional seq":        `{"type":"renew","gen":"` + goodGen + `","seq":1.5,"loops":{}}`,
		"loops not object":      `{"type":"renew","gen":"` + goodGen + `","seq":1,"loops":[]}`,
		"loop time not integer": `{"type":"renew","gen":"` + goodGen + `","seq":1,"loops":{"mutator":"now"}}`,
		"loop time negative":    `{"type":"renew","gen":"` + goodGen + `","seq":1,"loops":{"mutator":-5}}`,
		"unready without why":   `{"type":"unready","gen":"` + goodGen + `"}`,
		"reason with escape":    `{"type":"unready","gen":"` + goodGen + `","reason":"a\u001b[2Jb"}`,
		"status record string":  `{"type":"status","gen":"` + goodGen + `","seq":1,"record":"x"}`,
		"unknown log level":     `{"type":"log","gen":"` + goodGen + `","level":"debug","msg":"x"}`,
		"invalid utf-8":         "{\"type\":\"log\",\"gen\":\"" + goodGen + "\",\"level\":\"info\",\"msg\":\"\xff\"}",
		"nan":                   `{"type":"renew","gen":"` + goodGen + `","seq":NaN,"loops":{}}`,
	}
	for name, line := range bad {
		t.Run(name, func(t *testing.T) {
			_, err := DecodeFromWorker([]byte(line))
			if !errors.Is(err, ErrProtocol) {
				t.Fatalf("err = %v, want a protocol violation", err)
			}
		})
	}
	if _, err := DecodeFromSupervisor([]byte(`{"type":"ready","gen":"` + goodGen + `"}`)); !errors.Is(err, ErrProtocol) {
		t.Error("a worker message is not valid from the supervisor")
	}
	if _, err := DecodeFromSupervisor([]byte(`{"type":"netbird","gen":"` + goodGen + `","launch":1,"state":"weird","log_offset":0,"at_boot_ns":0}`)); !errors.Is(err, ErrProtocol) {
		t.Error("unknown NetBird state")
	}
	if _, err := DecodeFromSupervisor([]byte(`{"type":"netbird","gen":"` + goodGen + `","launch":4294967296,"state":"started","log_offset":0,"at_boot_ns":0}`)); !errors.Is(err, ErrProtocol) {
		t.Error("a launch number beyond 32 bits")
	}
}

func TestLineReaderBoundsLines(t *testing.T) {
	long := strings.Repeat("a", MaxLine)
	r := NewLineReader(strings.NewReader(long + "\nok\n"))
	line, err := r.Next()
	if err != nil || len(line) != MaxLine {
		t.Fatalf("a line of exactly the limit is fine: %d %v", len(line), err)
	}
	if line, err = r.Next(); err != nil || string(line) != "ok" {
		t.Fatalf("%q %v", line, err)
	}
	if _, err = r.Next(); err != io.EOF {
		t.Fatalf("EOF expected, got %v", err)
	}

	r = NewLineReader(strings.NewReader(long + "a\nok\n"))
	if _, err = r.Next(); !errors.Is(err, ErrProtocol) {
		t.Fatalf("a line one byte over the limit must be a violation: %v", err)
	}

	r = NewLineReader(strings.NewReader("half a message"))
	if _, err = r.Next(); !errors.Is(err, ErrProtocol) {
		t.Fatalf("a line with no newline at EOF is a violation: %v", err)
	}
}

func TestEncodeRefusesAnOversizedLine(t *testing.T) {
	rec := map[string]any{"message": strings.Repeat("x", MaxLine)}
	if _, err := (Msg{Type: TypeStatus, Gen: goodGen, Seq: 1, Record: rec}).Encode(); err == nil {
		t.Fatal("a line over 64 KiB must not be sent")
	}
}

func TestSenderWritesWholeLines(t *testing.T) {
	var buf bytes.Buffer
	s := NewSender(&buf)
	done := make(chan struct{})
	for i := 0; i < 20; i++ {
		go func() {
			_ = s.Send(Msg{Type: TypeReady, Gen: goodGen})
			done <- struct{}{}
		}()
	}
	for i := 0; i < 20; i++ {
		<-done
	}
	if n := strings.Count(buf.String(), "\n"); n != 20 {
		t.Fatalf("%d lines", n)
	}
	for _, line := range strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n") {
		if _, err := DecodeFromWorker([]byte(line)); err != nil {
			t.Fatalf("interleaved write: %v", err)
		}
	}
}
