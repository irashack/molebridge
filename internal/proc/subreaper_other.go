//go:build !linux

package proc

// BecomeSubreaper does nothing off Linux.
func BecomeSubreaper() error { return nil }

// StopBeingSubreaper does nothing off Linux.
func StopBeingSubreaper() error { return nil }
