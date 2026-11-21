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
