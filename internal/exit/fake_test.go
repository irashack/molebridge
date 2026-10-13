package exit

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/bootclock"
	"github.com/irashack/molebridge/internal/proc"
)

// The test binary doubles as the fake worker and the fake cleanup child:
// `exit.test fake-worker <mode>` and `exit.test fake-cleanup <mode>`.

func TestMain(m *testing.M) {
	if len(os.Args) >= 3 {
		switch os.Args[1] {
		case "fake-worker":
			fakeWorker(os.Args[2])
			os.Exit(0)
		case "fake-cleanup":
			fakeCleanup(os.Args[2])
			os.Exit(0)
		}
	}
	os.Exit(m.Run())
}

// reaperFor lends a test the process's reaper (and the sub-reaper role) for
// its own duration. The test binary has none otherwise: a reaper collects
// every child with wait4(-1), and the helpers the drills run (exec.Command:
// ip, nft, ping) wait for their own pid and would lose the race to it.
func reaperFor(t *testing.T) *proc.Reaper {
	t.Helper()
	reapersMu.Lock()
	defer reapersMu.Unlock()
	if r, ok := reapers[t]; ok {
		return r
	}
	_ = proc.BecomeSubreaper()
	r, err := proc.NewReaper()
	if err != nil {
		t.Fatal(err)
	}
	reapers[t] = r
	t.Cleanup(func() {
		r.Close()
		_ = proc.StopBeingSubreaper()
		reapersMu.Lock()
		delete(reapers, t)
		reapersMu.Unlock()
	})
	return r
}

var (
	reapersMu sync.Mutex
	reapers   = map[*testing.T]*proc.Reaper{}
)

func trace(format string, a ...any) {
	path := os.Getenv("MB_TRACE_FILE")
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	fmt.Fprintf(f, format+"\n", a...)
	f.Close()
}

func fakeCleanup(mode string) {
	var names []string
	for _, kv := range os.Environ() {
		if k, _, ok := strings.Cut(kv, "="); ok {
			names = append(names, k)
		}
	}
	sort.Strings(names)
	// The cleanup child's environment is interface names only: the trace file
	// comes on the command line.
	if len(os.Args) > 3 {
		os.Setenv("MB_TRACE_FILE", os.Args[3])
	}
	trace("cleanup %s", mode)
	trace("cleanup env %s", strings.Join(names, " "))
	switch mode {
	case "fail":
		os.Exit(1)
	case "hang":
		time.Sleep(time.Minute)
	}
}

// fakeWorker speaks the worker's side of the protocol.
func fakeWorker(mode string) {
	gen := os.Getenv("MOLEBRIDGE_GENERATION")
	if os.Getenv("NB_SETUP_KEY") != "" || os.Getenv("WT_SETUP_KEY") != "" {
		trace("worker has the setup key")
	}
	out := os.NewFile(3, "to-supervisor")
	in := os.NewFile(4, "from-supervisor")
	send := NewSender(out)
	clock := bootclock.System()
	s := settingsFor("overlay", "wireguard", "mullvad")
	var seq atomic.Uint64
	var sendMu sync.Mutex
	// Sequence numbers are taken under the lock the write is made under, so
	// they reach the supervisor in order.
	sendSeq := func(m Msg) {
		sendMu.Lock()
		defer sendMu.Unlock()
		m.Seq = seq.Add(1)
		_ = send.Send(m)
	}
	renew := func() {
		now := int64(clock())
		sendSeq(Msg{Type: TypeRenew, Gen: gen, Loops: map[string]int64{LoopMutator: now, LoopWatcher: now}})
	}
	status := func() {
		sendSeq(Msg{Type: TypeStatus, Gen: gen, Rec: okRecord(s, time.Now().UTC())})
	}
	hangStop := mode == "hangstop"
	if hangStop {
		signalIgnore()
	}
	go func() {
		lr := NewLineReader(in)
		for {
			line, err := lr.Next()
			if err != nil {
				trace("worker saw EOF")
				if !hangStop {
					os.Exit(0)
				}
				return
			}
			m, err := DecodeFromSupervisor(line)
			if err != nil {
				continue
			}
			switch m.Type {
			case TypeStop:
				trace("worker told to stop")
				if !hangStop {
					os.Exit(0)
				}
			case TypeNetBird:
				trace("worker told netbird %s %d offset=%d at>0=%v", m.State, m.Launch, m.LogOffset, m.AtBootNs > 0)
				if mode == "unready-after-start" && m.State == NBStarted && m.Launch == 1 {
					_ = send.Send(Msg{Type: TypeUnready, Gen: gen, Reason: "test: the contract cannot be restored"})
					go func() {
						time.Sleep(700 * time.Millisecond)
						renew()
						_ = send.Send(Msg{Type: TypeReady, Gen: gen})
						trace("worker ready again")
					}()
				}
			}
		}
	}()
	switch mode {
	case "badprotocol":
		renew()
		time.Sleep(200 * time.Millisecond)
		fmt.Fprintln(out, "this is not json")
		time.Sleep(time.Minute)
	case "oversize":
		renew()
		fmt.Fprintln(out, strings.Repeat("x", MaxLine+10))
		time.Sleep(time.Minute)
	case "crash":
		renew()
		time.Sleep(300 * time.Millisecond)
		trace("worker crashing")
		os.Exit(3)
	}
	start := time.Now()
	renew()
	status()
	time.Sleep(100 * time.Millisecond)
	renew()
	_ = send.Send(Msg{Type: TypeReady, Gen: gen})
	trace("worker ready")
	for {
		time.Sleep(200 * time.Millisecond)
		if mode == "freeze" && time.Since(start) > time.Second {
			trace("worker frozen")
			_ = syscall.Kill(os.Getpid(), syscall.SIGSTOP)
		}
		if mode == "stale" && time.Since(start) > time.Second {
			// Renewals keep coming, but the loops they report have stopped
			// advancing: a wedged mutation owner.
			old := int64(clock()) - int64(time.Hour)
			if old < 0 {
				old = 0
			}
			sendSeq(Msg{Type: TypeRenew, Gen: gen, Loops: map[string]int64{LoopMutator: old, LoopWatcher: int64(clock())}})
			continue
		}
		renew()
		if mode == "good" || mode == "unready-after-start" {
			status()
		}
	}
}
