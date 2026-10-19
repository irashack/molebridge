package applier

import (
	"fmt"
	"math"
	"strings"

	"github.com/irashack/molebridge/internal/attempt"
)

// traceKey is what a switch's log line follows: the attempt, its state, its
// outcome and its message. A pass that saves the attempt without changing
// them (a re-check scheduled again, the owner generation noted) logs nothing.
func traceKey(at *attempt.Attempt) string {
	return strings.Join([]string{at.AttemptID, at.Target, at.State, at.Outcome, at.Message}, "\x00")
}

// traceAttempt logs one line when the attempt's state changed since the last
// line: admitted (attempting), verified, applied but unverified, pending,
// rejected or failed. The server name is quoted (%q): the catalogue and the
// request validate it, and the quoting keeps any odd character visible. The
// messages are the pipeline's own.
func (a *Applier) traceAttempt() {
	at := a.attempt
	key := traceKey(at)
	if key == a.traced {
		return
	}
	a.traced = key
	if at.Target == "" {
		return
	}
	switch at.State {
	case "attempting":
		a.log(fmt.Sprintf("applier: switch to %q admitted (%s, change %d); applying", at.Target, orSeed(at.Source), at.Attempts))
	case "idle":
		if at.Outcome == "verified" {
			a.log(fmt.Sprintf("applier: %q is verified", at.Target))
		}
	case "unverified":
		a.log(fmt.Sprintf("applier: %q is applied but not verified; checked again every %d seconds", at.Target, RefreshSec))
	case "pending":
		a.log(fmt.Sprintf("applier: switch to %q waits: %s", at.Target, at.Message))
	case "rejected":
		a.log(fmt.Sprintf("applier: switch to %q rejected: %s", at.Target, at.Message))
	case "failed":
		line := fmt.Sprintf("applier: switch to %q failed: %s", at.Target, at.Message)
		if at.NextAction == "reapply" && at.NextActionAt != nil {
			line += fmt.Sprintf(" (next try in %d s)", int(math.Max(0, math.Ceil(*at.NextActionAt-a.clock()))))
		}
		a.log(line)
	}
}

func orSeed(source string) string {
	if source == "" {
		return "seed"
	}
	return source
}
