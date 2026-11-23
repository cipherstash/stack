package guest

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestLockRefusesAnEndedContextEvenWhenFree(t *testing.T) {
	var l Lock
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for range 100 {
		if err := l.Acquire(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("Acquire with an ended context: %v, want context.Canceled", err)
		}
	}
	// And the refusals left it free.
	if err := l.Acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	l.Unlock()
}

func TestLockWaitEndsWithTheContext(t *testing.T) {
	var l Lock
	l.Lock()
	defer l.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := l.Acquire(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Acquire on a held lock: %v, want the deadline", err)
	}
}

func TestTryLockTakesOnlyAFreeLock(t *testing.T) {
	var l Lock
	if !l.TryLock() {
		t.Fatal("TryLock on a free lock did not take it")
	}
	if l.TryLock() {
		t.Fatal("TryLock on a held lock took it")
	}
	l.Unlock()
	if !l.TryLock() {
		t.Fatal("TryLock after Unlock did not take it")
	}
	l.Unlock()
}

type valueKey struct{}

func TestDetachKeepsValuesNotCancellation(t *testing.T) {
	caller, cancel := context.WithCancel(context.WithValue(context.Background(), valueKey{}, "v"))
	run, done := Detach(caller, time.Hour)
	defer done()
	cancel()
	if run.Err() != nil {
		t.Fatal("the caller's cancellation reached the call's context")
	}
	if run.Value(valueKey{}) != "v" {
		t.Error("the caller's values did not reach the call's context")
	}
	if Caller(run) != caller {
		t.Error("Caller does not give back the caller's context")
	}
	if Caller(caller) != caller {
		t.Error("Caller outside a detached call is not the context itself")
	}
}

func TestDetachEndsStuckAfterTheCaller(t *testing.T) {
	caller, cancel := context.WithCancel(context.Background())
	run, done := Detach(caller, 10*time.Millisecond)
	defer done()
	cancel()
	select {
	case <-run.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the call's context did not end after the caller's")
	}
	if !Stuck(run) {
		t.Errorf("the backstop ended the call's context with %v, want ErrStuck", context.Cause(run))
	}
}

// A call that finishes ends its context with no stuck cause, whether or not
// its caller gave up first.
func TestDetachDoneIsNotStuck(t *testing.T) {
	caller, cancel := context.WithCancel(context.Background())
	run, done := Detach(caller, time.Hour)
	cancel()
	done()
	if Stuck(run) {
		t.Fatal("a call that finished was reported stuck")
	}
	// And stays so: the backstop's timer was stopped.
	time.Sleep(10 * time.Millisecond)
	if Stuck(run) {
		t.Fatal("a call that finished was reported stuck later")
	}
}

func TestAcquireUnlessLeavesWhenAbandoned(t *testing.T) {
	var l Lock
	l.Lock()
	defer l.Unlock()
	abandon := make(chan struct{})
	got := make(chan error, 1)
	go func() { got <- l.AcquireUnless(context.Background(), abandon) }()
	select {
	case err := <-got:
		t.Fatalf("AcquireUnless on a held lock returned %v before it was abandoned", err)
	case <-time.After(10 * time.Millisecond):
	}
	close(abandon)
	select {
	case err := <-got:
		if !errors.Is(err, ErrAbandoned) {
			t.Fatalf("AcquireUnless: %v, want ErrAbandoned", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("AcquireUnless did not leave when abandoned")
	}
}

// An abandoned lock is refused even when it is free, and the refusal leaves
// it free.
func TestAcquireUnlessRefusesAnAbandonedFreeLock(t *testing.T) {
	var l Lock
	abandon := make(chan struct{})
	close(abandon)
	for range 100 {
		if err := l.AcquireUnless(context.Background(), abandon); !errors.Is(err, ErrAbandoned) {
			t.Fatalf("AcquireUnless: %v, want ErrAbandoned", err)
		}
	}
	if !l.TryLock() {
		t.Fatal("a refused AcquireUnless left the lock held")
	}
	l.Unlock()
}

func TestAcquireUnlessTakesAFreeLock(t *testing.T) {
	var l Lock
	if err := l.AcquireUnless(context.Background(), make(chan struct{})); err != nil {
		t.Fatal(err)
	}
	if l.TryLock() {
		t.Fatal("AcquireUnless did not take the lock")
	}
	l.Unlock()
}

// A call that finished before its caller's context ended keeps nothing
// running: the context the call ran under has ended by done, not by a timer.
func TestDetachDoneEndsTheCall(t *testing.T) {
	caller, cancel := context.WithCancel(context.Background())
	defer cancel()
	run, done := Detach(caller, time.Hour)
	done()
	select {
	case <-run.Done():
	default:
		t.Fatal("done left the call's context running")
	}
}
