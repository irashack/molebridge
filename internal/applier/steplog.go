package applier

import "context"

// FailureRelog is how long, in seconds, a step that keeps failing for the
// same reason goes unlogged after its line: a step retried on every pass (5
// seconds) would otherwise fill the log, and one that is never logged leaves
// nothing to diagnose.
const FailureRelog = 10 * 60

// stepFailure is the last line logged for a failing step.
type stepFailure struct {
	cause string
	at    float64
}

// stepFailed logs the failure of a step that is retried on every pass: the
// first failure, each change of cause, and the same cause again once
// FailureRelog has passed since its line. line is the fixed text; the cause
// follows it. A failure while ctx is ending (a stop) is not logged.
//
// Callers pass errors that name a step, an interface or a file, never a
// credential or a token (netx's carry no URL).
func (a *Applier) stepFailed(ctx context.Context, step, line string, err error) {
	if ctx.Err() != nil {
		return
	}
	cause, now := err.Error(), a.clock()
	if last, ok := a.failures[step]; ok && last.cause == cause && now-last.at < FailureRelog {
		return
	}
	if a.failures == nil {
		a.failures = map[string]stepFailure{}
	}
	a.failures[step] = stepFailure{cause: cause, at: now}
	a.log(line + ": " + cause)
}

// stepSucceeded forgets a step's failure and, when it had one, logs line (if
// any) once.
func (a *Applier) stepSucceeded(step, line string) {
	if _, ok := a.failures[step]; !ok {
		return
	}
	delete(a.failures, step)
	if line != "" {
		a.log(line)
	}
}
