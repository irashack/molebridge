// Tests for what the port adds around the Python behavior: the error classes
// of the pipeline (a definite refusal, a failure of the applier's own file
// I/O), the boot clock, the supervisor's result writer and the owner_record
// seam. There is no Python counterpart.
package applier

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/irashack/molebridge/internal/netx"
	"github.com/irashack/molebridge/internal/providers"
	"github.com/irashack/molebridge/internal/validate"
)

func TestADefiniteRefusalIsRecordedAsDefinite(t *testing.T) {
	dir := t.TempDir()
	k := newKernel(t)
	k.keys = []string{otherKey}
	o := &overridden{Provider: NewMullvad()}
	a := buildApplier(t, k, dir, o, "")
	o.applyRelay = func(context.Context, *Applier, *providers.Relay, []string) error {
		return fmt.Errorf("provider said no: %w", ErrMutationRefused)
	}
	desire(t, a, requestAt(testHost, nil))
	r := mustTick(t, a)
	if status(r) != "failed" || a.attempt.MutationCertainty != "definite" || a.attempt.NextAction != "reapply" ||
		a.attempt.Outcome != "mutation-failed" {
		t.Fatalf("%s %s %q", status(r), a.attempt.State, a.attempt.MutationCertainty)
	}
}

func TestAnUncertainFailureIsRecordedAsUncertain(t *testing.T) {
	dir := t.TempDir()
	k := newKernel(t)
	k.keys = []string{otherKey}
	o := &overridden{Provider: NewMullvad()}
	a := buildApplier(t, k, dir, o, "")
	o.applyRelay = func(context.Context, *Applier, *providers.Relay, []string) error {
		return errors.New("connection reset")
	}
	desire(t, a, requestAt(testHost, nil))
	mustTick(t, a)
	if a.attempt.MutationCertainty != "uncertain" {
		t.Fatalf("%q", a.attempt.MutationCertainty)
	}
}

func TestAMissingCredentialFileIsInspectedOnTheNextPassAndRetried(t *testing.T) {
	// PIA's credential file missing when a switch starts is the applier's own
	// I/O failure: the pass ends ("applier: control cycle failed") with the
	// attempt saved as attempting. Python's process died there and its
	// restart inspected the attempt; the worker survives, so its next pass
	// inspects it, fails it with the cause in the message, and once the file
	// is back the re-apply on the backoff switches.
	a, k, _, _, secrets := piaSetup(t, false)
	password := filepath.Join(secrets, "password")
	if err := os.Remove(password); err != nil {
		t.Fatal(err)
	}
	piaDesire(t, a)
	r, err := a.Tick(context.Background())
	if err == nil || r != nil || caught(err) {
		t.Fatalf("tick: %v %v", r, err)
	}
	if a.attempt.State != "attempting" || len(k.mutations) != 0 {
		t.Fatalf("%s %v", a.attempt.State, k.mutations)
	}
	if saved(t, filepath.Dir(filepath.Dir(a.attemptPath)))["state"] != "attempting" {
		t.Error("not saved as attempting")
	}
	r = mustTick(t, a)
	if a.attempt.State != "failed" || a.attempt.NextAction != "reapply" || a.attempt.NextActionAt == nil {
		t.Fatalf("after the next pass: %s %s", a.attempt.State, a.attempt.NextAction)
	}
	want := "The last switch stopped on a file error (open " + password +
		": no such file or directory); retrying automatically."
	if r.Get("status") != "failed" || message(r) != want {
		t.Errorf("record: %v %q", r.Get("status"), message(r))
	}
	if saved(t, filepath.Dir(filepath.Dir(a.attemptPath)))["state"] != "failed" {
		t.Error("the inspection was not saved")
	}
	writeFile(t, password, piaPassword, 0o600)
	k.now = *a.attempt.NextActionAt
	mustTick(t, a)
	if a.attempt.State != "idle" || a.attempt.Outcome != "verified" || len(k.mutations) == 0 {
		t.Errorf("after the re-apply: %s %s %v", a.attempt.State, a.attempt.Outcome, k.mutations)
	}
}

func TestACompletedPassForgetsAnEarlierIOFailure(t *testing.T) {
	// The cause an inspection names is the failure of the pass just before.
	a, _, _ := mullvadSetup(t)
	a.ioFailure = "earlier"
	mustTick(t, a)
	if a.ioFailure != "" {
		t.Errorf("%q", a.ioFailure)
	}
}

func TestAFailingPublishCallbackIsAnIOFailure(t *testing.T) {
	a, k, _ := mullvadSetup(t)
	a.publish = func(*Record) error { return errors.New("disk full") }
	desire(t, a, requestAt(testHost, nil))
	if _, err := a.Tick(context.Background()); err == nil || caught(err) {
		t.Fatalf("tick: %v", err)
	}
	_ = k
}

func TestACanceledContextEndsATickWithoutPublishingAnEgressFailure(t *testing.T) {
	a, k, _ := mullvadSetup(t)
	ctx, cancel := context.WithCancel(context.Background())
	k.hooks = append(k.hooks, func(r netx.Request) error {
		if strings.Contains(r.URL, "am.i.mullvad.net") {
			cancel()
			return context.Canceled
		}
		return nil
	})
	if _, err := a.Inspect(ctx, false); err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if ctx.Err() == nil {
		t.Fatal("not canceled")
	}
}

func TestBootClockCountsUpInSeconds(t *testing.T) {
	a, b := BootClock(), BootClock()
	if a < 0 || b < a || b-a > 5 {
		t.Fatalf("%v %v", a, b)
	}
}

func TestWriteResultIsAtomicAndReadableByThePanel(t *testing.T) {
	a, _, dir := mullvadSetup(t)
	rec := a.inspect(t)
	if err := WriteResult(dir, rec); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(ResultPath(dir))
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("%v %v", info, err)
	}
	raw, _ := os.ReadFile(ResultPath(dir))
	text, _ := validate.MarshalJSON(rec)
	if string(raw) != string(text) {
		t.Error("the file is not the record")
	}
}

func TestOwnerRecordIsLeftUnknownForTheSupervisor(t *testing.T) {
	a, _, _ := mullvadSetup(t)
	rec := a.inspect(t)
	if checkState(rec, "owner_record") != "unknown" {
		t.Fatalf("owner_record is %s", checkState(rec, "owner_record"))
	}
	// Judged as the supervisor will publish it, with its own check in place.
	if checkState(a.judged(rec), "owner_record") != "pass" {
		t.Error("the supervisor's check was not applied")
	}
	// Other kinds keep their fixed state.
	a.ownerCheck = func() validate.Obj { return validate.Members("state", "fail") }
	fixed := a.blankChecks().Set("owner_record", validate.Members("state", "n/a"))
	rec = &Record{members: validate.Members("checks", fixed)}
	for _, pair := range a.judged(rec).Get("checks").(validate.Obj) {
		if pair.Key == "owner_record" && pair.Value.(validate.Obj)[0].Value != "n/a" {
			t.Error("a fixed owner_record check was overwritten")
		}
	}
}

func TestChangePIAAddressWithNoOldAddress(t *testing.T) {
	a, k, _, _, _ := piaSetup(t, false)
	_ = a
	if err := ChangePIAAddress(context.Background(), k, mustAddr("0.0.0.0").Prev(), mustAddr("10.0.0.2")); err != nil {
		// 0.0.0.0.Prev() is the zero Addr: no old address.
		t.Fatal(err)
	}
	if !same(addrStrings(k), []string{"10.0.0.2"}) || !same(k.sources94(), []string{"10.0.0.2"}) || !same(k.sources98(), []string{"10.0.0.2"}) {
		t.Fatalf("%v %v %v", addrStrings(k), k.sources94(), k.sources98())
	}
	for _, c := range k.calls {
		if strings.HasPrefix(c, "address del") || strings.HasPrefix(c, "rule del") {
			t.Errorf("removed something: %s", c)
		}
	}
}

func TestTruncateCharsAndSurrogateEscape(t *testing.T) {
	if got := truncateChars(strings.Repeat("\U0001F600", 300), 256); validate.RuneCount(got) != 256 {
		t.Errorf("%d", validate.RuneCount(got))
	}
	if truncateChars("abc", 256) != "abc" {
		t.Error("short strings change")
	}
	if got := surrogateEscape("a\xffb"); validate.RuneCount(got) != 3 || !strings.HasPrefix(got, "a") {
		t.Errorf("%q", got)
	}
	raw, err := validate.MarshalJSON(surrogateEscape("a\xffb"))
	if err != nil || string(raw) != `"a\udcffb"` {
		t.Errorf("%s %v", raw, err)
	}
}
