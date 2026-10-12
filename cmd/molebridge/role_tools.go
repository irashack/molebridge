package main

import (
	"os"
	"strings"
)

// toolsEnv returns the process environment as a map, for the file tools.
func toolsEnv() map[string]string {
	env := map[string]string{}
	for _, kv := range os.Environ() {
		if k, v, ok := strings.Cut(kv, "="); ok {
			env[k] = v
		}
	}
	return env
}
