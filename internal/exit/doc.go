// Package exit is the exit container's process: the supervisor that is PID 1,
// the worker that owns the routing, the lease between them, the NetBird child,
// status publication and the stop sequence (decisions D3, D7, D8, D21 of the
// 0.8.0 plan).
//
// # Processes
//
// `molebridge exit` is the supervisor. It validates the settings, forks the
// worker (`molebridge exit --worker`, in its own process group, with a pipe in
// each direction), starts NetBird when the worker says the contract holds, and
// runs the stop sequence. It never touches the kernel's routing itself and
// never blocks on the worker: it owns the only clock that matters, the boot
// clock, and checks the lease deadline from its own ticker.
//
// The worker holds the routing contract through the mutation owner
// (internal/mutator), watches the kernel (internal/watch), brings the tunnel
// up, runs the provider pipeline and reports to the supervisor over the pipe.
//
// `molebridge exit --cleanup` is the independent cleanup the supervisor runs
// after the worker is gone: it removes the interfaces a stopping exit owns and
// leaves every rule in place.
//
// # The lease (D21)
//
// The worker may send one renewal every 2 seconds, and only when each loop it
// supervises has completed a step within its bound. The supervisor accepts a
// renewal only for the current launch generation, with a sequence number above
// the last accepted and loop times that are neither in the future nor older
// than the loop's bound; an accepted renewal sets the expiry to now plus
// GUARD_GRACE on the supervisor's boot clock. A lapse, the worker's exit, a
// NetBird process's unexpected exit or a protocol violation starts the stop
// sequence.
//
// # Timing (all bounded; see Timing and the constants in lease.go)
//
// Loops report to the lease every 2 seconds (the mutation owner within 10
// seconds under load). A loop is late after its bound (10 s for the owner, 3 s
// for the 2-second loops: 2 s plus one second of scheduling slack), and the
// supervisor allows one more second for the pipe. The longest failure-to-stop
// bound is therefore the loop bound plus GUARD_GRACE plus the stop budget:
// T+0 stop and TERM, T+6 KILL, T+7 reaped, T+7..12 cleanup, T+13 exit.
//
// # Wire protocol
//
// Newline-delimited JSON on two pipes, every line at most 64 KiB, decoded
// strictly (internal/validate). See protocol.go for the messages.
package exit
