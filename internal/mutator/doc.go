// Package mutator is the single owner of every routing mutation in the exit
// namespace: the repairer's passes, the install of the contract, the tunnel
// coming up, and provider transactions such as PIA's address change all run
// as operations of one goroutine, one at a time.
//
// The point of the single owner is that the expected state (contract.Spec)
// and the kernel move together. An operation updates the expected state
// before each kernel change that needs it, and because nothing else mutates
// concurrently, a repair pass that starts later judges the kernel against the
// state the previous operation left, never against a stale one. A
// transaction in progress is therefore never undone by the repairer: the
// repairer is simply the next operation in the queue.
//
// Progress. Every operation completes or fails within OpTimeout (10 seconds):
// kernel requests carry deadlines derived from what is left of the
// operation's budget, and operations check their context between steps. An
// idle owner reports a step every IdleStep (2 seconds). Progress returns the
// boot-clock time of the last completion or step; the supervisor's lease
// rests on it, so a wedged owner stops the exit's NetBird within a stated
// time rather than being waited on. An operation that overruns is not
// abandoned (another goroutine could then mutate beside the owner): the owner
// reports no step until it returns, and the lease lapses.
//
// The mutation owner is never to be held across a provider HTTP call: do the
// call first, then run the kernel steps as one operation.
package mutator
