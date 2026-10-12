//go:build !linux

package proc

// BecomeSubreaper does nothing off Linux.
func BecomeSubreaper() error { return nil }
