package relayproxy

import (
	"errors"
	"net"
	"testing"
	"time"
)

// scripted runs a fake relay proxy that sends each reply after reading the
// client's next message, then closes.
func scripted(t *testing.T, replies ...[]byte) net.Conn {
	t.Helper()
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		buf := make([]byte, 300)
		for _, r := range replies {
			if _, err := server.Read(buf); err != nil {
				return
			}
			if _, err := server.Write(r); err != nil {
				return
			}
		}
	}()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestSocksConnectReplies(t *testing.T) {
	ok := []byte{5, 0}
	cases := []struct {
		name    string
		replies [][]byte
		want    error
	}{
		{"IPv4 bound address", [][]byte{ok, {5, 0, 0, 1, 10, 124, 0, 1, 0, 80}}, nil},
		{"IPv6 bound address", [][]byte{ok, append(append([]byte{5, 0, 0, 4}, make([]byte, 16)...), 0, 80)}, nil},
		{"domain bound address", [][]byte{ok, {5, 0, 0, 3, 3, 'a', '.', 'b', 0, 80}}, nil},
		{"wrong greeting version", [][]byte{{4, 0}}, ErrHandshake},
		{"authentication wanted", [][]byte{{5, 2}}, ErrNoAuth},
		{"no acceptable method", [][]byte{{5, 0xFF}}, ErrNoAuth},
		{"wrong reply version", [][]byte{ok, {4, 0, 0, 1, 0, 0, 0, 0, 0, 0}}, ErrHandshake},
		{"reserved byte set", [][]byte{ok, {5, 0, 1, 1, 0, 0, 0, 0, 0, 0}}, ErrHandshake},
		{"unknown address type", [][]byte{ok, {5, 0, 0, 9, 0, 0, 0, 0, 0, 0}}, ErrHandshake},
		{"empty domain", [][]byte{ok, {5, 0, 0, 3, 0, 0, 80}}, ErrHandshake},
		{"short reply", [][]byte{ok, {5, 0, 0, 1, 10}}, ErrHandshake},
		{"closed after the greeting", [][]byte{ok}, ErrHandshake},
	}
	for _, c := range cases {
		err := socksConnect(scripted(t, c.replies...), "example.net", 443)
		if c.want == nil && err != nil || c.want != nil && !errors.Is(err, c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// A failure reply is its code, even when the proxy closes before the
	// bound address.
	err := socksConnect(scripted(t, ok, []byte{5, 5, 0, 1}), "example.net", 443)
	var reply *ReplyError
	if !errors.As(err, &reply) || reply.Code != ReplyConnectionRefused || !reply.Target() {
		t.Fatal(err)
	}
	if (&ReplyError{Code: 0x42}).Error() != "relayproxy: relay proxy replied code 66" {
		t.Fatal("unknown code text")
	}
}
