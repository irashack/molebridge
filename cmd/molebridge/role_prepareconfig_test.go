package main

import "testing"

func TestFileToolRolesAreRegistered(t *testing.T) {
	for _, name := range []string{"prepare-config", "nordvpn-key"} {
		if _, ok := roles[name]; !ok {
			t.Errorf("role %s is not registered", name)
		}
	}
}
