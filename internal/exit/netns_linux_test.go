package exit

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestNameNetNamespace(t *testing.T) {
	inode := func(string) (string, error) { return "net:[4026532001]", nil }
	for _, c := range []struct {
		name   string
		cookie func() (uint64, error)
		want   string
	}{
		{"a cookie", func() (uint64, error) { return 4096, nil }, "netns-cookie:4096"},
		{"a kernel without cookies", func() (uint64, error) { return 0, unix.ENOPROTOOPT }, "net:[4026532001]"},
		{"a denied option", func() (uint64, error) { return 0, unix.EPERM }, ""},
		{"a denied socket", func() (uint64, error) { return 0, unix.EACCES }, ""},
	} {
		if got := nameNetNamespace(c.cookie, inode); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}
