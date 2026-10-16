//go:build !linux

package exit

// netNamespace: there are no network namespaces to name.
func netNamespace() string { return "" }

// NetNamespace is netNamespace, for tests outside the package.
func NetNamespace() string { return netNamespace() }
