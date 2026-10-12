// Package nbprofile ports the NetBird gate's refusals (routing/wait-for-guards
// in 0.7.x): the settings NetBird must not run with, the stored profile the
// daemon will load, and the interface blacklist (D25) with its repair tool.
//
// NetBird source references are to the pinned release, 0.80.0.
package nbprofile

// Refusal is a start-time refusal. Its text is a fixed message: it never
// carries anything read from a profile (profiles hold the peer's private key).
type Refusal struct {
	// Why is the reason, without the frame.
	Why string
	// bare marks the two refusals the gate printed without the
	// "refusing to start NetBird" frame.
	bare bool
}

// Error returns the line the gate printed. The frame text is quoted by
// docs/troubleshooting.md and must not change.
func (r *Refusal) Error() string {
	if r.bare {
		return r.Why
	}
	return "NetBird gate: refusing to start NetBird: " + r.Why + " (see docs/troubleshooting.md)"
}

func refuse(why string) error { return &Refusal{Why: why} }

func refuseBare(line string) error { return &Refusal{Why: line, bare: true} }
