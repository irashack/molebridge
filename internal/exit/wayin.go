package exit

// wayIn is the supervisor's one boundary to the exit's way in: the client
// peers reach the exit through, NetBird for an overlay exit (nbManager, in
// netbird.go) and nothing for a sidecar (noWayIn).
//
// The supervisor decides when the way in may run, and the way in never
// decides that itself: Launch is called only while the worker says the
// routing contract holds, the lease is held and no stop is under way;
// Unready is called when the worker says the contract no longer holds; and
// the stop sequence calls Close and TermAll at T+0, KillAll at T+StopKill,
// and Alive until then. What the client is (its processes, its log lines,
// what the worker is told about it) is the implementation's. Every method is
// called on the supervisor's goroutine, except Alive, TermAll and KillAll,
// which must never wait on a process creation in flight.
type wayIn interface {
	// Launch starts the way in unless a launch is already active.
	Launch(h wayInHost)
	// Unready stops the way in because the worker cannot hold the routing
	// contract (reason is the worker's); it may be launched again.
	Unready(h wayInHost, reason string)
	// Handle processes an event the way in pushed to the supervisor's loop;
	// a non-empty reason starts the stop sequence, after detail is logged.
	Handle(h wayInHost, e any) (reason, detail string)
	// Close refuses every later launch.
	Close()
	// TermAll and KillAll signal every process of the way in.
	TermAll()
	KillAll()
	// Alive reports whether any process of the way in is alive or being
	// created.
	Alive() bool
	// Left names the way in in the stop sequence's "cleanup incomplete" line.
	Left() string
}

// wayInHost is what a way in may use of the supervisor.
type wayInHost struct {
	// logf writes one of the supervisor's own lines.
	logf func(format string, a ...any)
	// tell queues a message for the worker, stamped with the current
	// generation; it never blocks.
	tell func(m Msg)
	// again asks the supervisor to launch the way in if it still may.
	again func()
}

// noWayIn is the way in of an exit kind that runs no client (the sidecars):
// it has no process and never stops the exit.
type noWayIn struct{}

func (noWayIn) Launch(wayInHost)                       {}
func (noWayIn) Unready(wayInHost, string)              {}
func (noWayIn) Handle(wayInHost, any) (string, string) { return "", "" }
func (noWayIn) Close()                                 {}
func (noWayIn) TermAll()                               {}
func (noWayIn) KillAll()                               {}
func (noWayIn) Alive() bool                            { return false }
func (noWayIn) Left() string                           { return "" }

// newWayIn is the way in this exit's kind runs; it is created once the
// reaper exists, before the worker starts.
func (s *Supervisor) newWayIn() wayIn {
	if !s.s.Overlay() {
		return noWayIn{}
	}
	return newNetBirdWayIn(s.s, s.reap, s.c, s.stderr, func(e any) { s.push(evWayIn{e}) })
}

// host is the supervisor as a way in sees it.
func (s *Supervisor) host() wayInHost {
	return wayInHost{logf: s.logf,
		tell:  func(m Msg) { m.Gen = s.gen; s.send(m) },
		again: s.maybeStartWayIn}
}

// wayInChecks are the status record's checks the way in of an exit with these
// settings owns, which the supervisor's failure record fails (FailureRecord):
// NetBird's for an overlay exit, none for a sidecar.
func wayInChecks(s *Settings) []string {
	if !s.Overlay() {
		return nil
	}
	return netbirdChecks
}
