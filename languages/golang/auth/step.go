package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/cipherstash/stack/languages/golang/internal/guest"
	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
	"github.com/tetratelabs/wazero/api"
)

// The token operations step. The guest never waits on the network: a token
// fetch or a device session's refresh that needs the token service pauses
// at its request instead, and hands Go the request and a handle
// (guest.ErrNeedsIO, then sa_auth_io). Go performs the request outside the
// profile's lock and resumes the operation with the response
// (sa_auth_resume), until it is done. So the lock is held only while the
// guest runs, never across a request, and while one caller's exchange is in
// flight every other caller enters the guest and gets the strategy's
// current token from stack-auth's own cache.
//
// A caller that finds no usable token while another caller exchanges
// waits for that exchange inside the guest: its operation parks, asking Go
// for nothing. The guest lists parked operations that may run again
// (sa_auth_runnable), and Go asks after every step, resume and abort,
// because a lock passes to one waiter at a time: one parked caller running
// can be what lets the next run.
//
// An operation whose request is in flight is never dropped. A caller that
// gives up returns at once (Strategy.Token), and the operation is resumed
// with the response, or with the transport failure, on a goroutine of its
// own. For an access-key or OIDC exchange that failure comes at once: the
// request is cancelled with its caller. A device session's refresh runs on
// for refreshGrace, so the rotated refresh token the service sends back is
// kept. A parked operation holds nothing in flight, and is aborted when
// its caller gives up.

// maxPaused is the most token operations that may be paused in the guest at
// once, parked ones included: the guest's MAX_OPEN, which refuses one more,
// as TestMaxPausedIsTheGuestsLimit checks. A call that finishes on its first
// step opens nothing and never waits. A start the guest refuses because
// that many are open waits for one of them to end, and is tried again
// (startUnlock).
const maxPaused = 64

// authStep is a paused operation's step, as the guest hands it over: its
// handle, whether it is parked, and the requests it waits on.
type authStep struct {
	handle   uint64
	parked   bool
	requests []authRequest
}

// authRequest is one request the guest needs performed. The headers and
// body carry the access key or a refresh token, so both are wiped once
// performed.
type authRequest struct {
	method, url   string
	headers, body []byte
}

func (s *authStep) wipe() {
	for _, r := range s.requests {
		guest.Wipe(r.headers)
		guest.Wipe(r.body)
	}
}

// errStepMalformed describes the problem with a step that this package
// cannot read. The error for such a step wraps errStepMalformed.
// guest.BadAnswer builds that error. The error is ErrInternal, and it
// names sa_auth_io, the export that returns the step.
var errStepMalformed = errors.New("the step is malformed")

// errMalformedStep is the error for a step that this package cannot read.
var errMalformedStep = guest.BadAnswer("sa_auth_io", errStepMalformed)

// decodeAuthStep reads `{"handle": u64, "parked": bool, "requests":
// [{"method", "url", "headers", "body"}, ...]}`. Every byte slice it
// returns is its own copy.
func decodeAuthStep(raw []byte) (*authStep, error) {
	decoded, err := vcffi.Unmarshal(raw)
	if err != nil {
		return nil, guest.BadAnswer("sa_auth_io", fmt.Errorf("%w: %w", errStepMalformed, err))
	}
	return authStepFrom(decoded)
}

// authStepFrom is decodeAuthStep over the decoded frame, which it owns: the
// step it returns keeps the frame's byte slices. A frame it refuses is
// wiped whole, every request's headers and body included, wherever the
// refusal came.
func authStepFrom(decoded any) (*authStep, error) {
	refuse := func() (*authStep, error) {
		guest.WipeDecoded(decoded)
		return nil, errMalformedStep
	}
	obj, ok := decoded.(vcvalue.Object)
	if !ok {
		return refuse()
	}
	step := &authStep{}
	var sawHandle, sawParked, sawRequests bool
	for _, f := range obj {
		switch f.Key {
		case "handle":
			step.handle, ok = f.Value.(uint64)
			sawHandle = ok
		case "parked":
			step.parked, ok = f.Value.(bool)
			sawParked = ok
		case "requests":
			var items []any
			items, ok = f.Value.([]any)
			sawRequests = ok
			for _, item := range items {
				var r authRequest
				if r, ok = decodeAuthRequest(item); !ok {
					break
				}
				step.requests = append(step.requests, r)
			}
		default:
			ok = false
		}
		if !ok {
			return refuse()
		}
	}
	// A parked operation asks for nothing; an empty list otherwise is a
	// yield.
	if !sawHandle || !sawParked || !sawRequests || (step.parked && len(step.requests) > 0) {
		return refuse()
	}
	return step, nil
}

// decodeAuthRequest reads one request of a step. A request it refuses is
// wiped whole, the fields after the refused one included.
func decodeAuthRequest(item any) (authRequest, bool) {
	refuse := func() (authRequest, bool) {
		guest.WipeDecoded(item)
		return authRequest{}, false
	}
	obj, ok := item.(vcvalue.Object)
	if !ok {
		return refuse()
	}
	var r authRequest
	for _, f := range obj {
		switch f.Key {
		case "method":
			r.method, ok = f.Value.(string)
		case "url":
			r.url, ok = f.Value.(string)
		case "headers":
			r.headers, ok = f.Value.([]byte)
		case "body":
			r.body, ok = f.Value.([]byte)
		default:
			ok = false
		}
		if !ok {
			return refuse()
		}
	}
	if r.method == "" || r.url == "" {
		return refuse()
	}
	return r, true
}

// decodeRunnable reads the list of parked handles the guest may resume.
func decodeRunnable(raw []byte) ([]uint64, error) {
	decoded, err := guest.DecodeAnswer("sa_auth_runnable", raw)
	if err != nil {
		return nil, err
	}
	items, ok := decoded.([]any)
	if !ok {
		return nil, guest.BadAnswer("sa_auth_runnable", fmt.Errorf("it is %s, not a list", guest.KindOf(decoded)))
	}
	handles := make([]uint64, 0, len(items))
	for i, item := range items {
		h, ok := item.(uint64)
		if !ok {
			return nil, guest.BadAnswer("sa_auth_runnable", fmt.Errorf("operation %d is %s, not a handle", i, guest.KindOf(item)))
		}
		handles = append(handles, h)
	}
	return handles, nil
}

// response is the token service's answer to one request, as the guest
// reads it: the HTTP status, or -1 with the failure's text as the body.
type response struct {
	status        int32
	headers, body []byte
}

// encodeResponses encodes responses, in the order of the requests, for
// sa_auth_resume: `[{"status": i32, "headers": bytes, "body": bytes}, ...]`.
// The caller wipes the encoding once the guest has it.
func encodeResponses(responses []response) ([]byte, error) {
	items := make([]any, 0, len(responses))
	for _, r := range responses {
		headers, body := r.headers, r.body
		if headers == nil {
			headers = []byte{}
		}
		if body == nil {
			body = []byte{}
		}
		items = append(items, vcvalue.Object{
			{Key: "status", Value: r.status},
			{Key: "headers", Value: headers},
			{Key: "body", Value: body},
		})
	}
	return vcffi.Marshal(items)
}

// run drives one token operation, started by the export start selects with
// args, to its end, and returns its output: a token. ctx is the caller's.
// It bounds the wait for the profile's lock before the operation starts,
// for an operation to end when the guest holds as many as it can, and the
// wait while it is parked. Once a request is in
// flight the operation is finished whatever ctx does (see above), and a
// caller whose ctx ended by then gets its error and no output.
//
// Every operation is counted on the root from its start to its last step,
// so ProfileStore.Close waits for it. Once Close has begun, no operation
// starts, and a parked one is aborted rather than resumed.
func (s *ProfileStore) run(ctx context.Context, start export, args ...guest.Arg) ([]byte, error) {
	r := s.root
	if err := r.mu.Acquire(ctx); err != nil {
		return nil, err
	}
	if r.closing || r.closed {
		r.mu.Unlock()
		return nil, ErrState
	}
	// Added under the lock, before Close can see closing unset and wait.
	r.ops.Add(1)
	defer r.ops.Done()
	out, step, err := s.startUnlock(ctx, start, args...)
	if step != nil {
		// Paused: open in the guest until driven to its end (stepLocked
		// counted it).
		defer s.endOpen()
	}
	// Once started, the operation is driven to its end: a resume waits for
	// the lock, and runs, whatever the caller's context does. Its steps
	// still run under the stuck-call backstop, armed by ctx (stepLocked).
	for step != nil {
		var responses []response
		if step.parked {
			woken := s.waitRunnable(ctx, step.handle)
			r.mu.Lock()
			if !woken || r.closing {
				defer r.mu.Unlock()
				s.abortLocked(ctx, step.handle)
				if !woken {
					return nil, ctx.Err()
				}
				return nil, ErrState
			}
			r.mu.Unlock()
		} else {
			// Requests run outside the lock; there are none for a yield.
			for _, req := range step.requests {
				status, headers, body := r.inst.transport.perform(ctx, req, r.stuck)
				responses = append(responses, response{status, headers, body})
			}
			step.wipe()
		}
		encoded, encodeErr := encodeResponses(responses)
		for _, resp := range responses {
			guest.Wipe(resp.body)
		}
		if encodeErr != nil {
			r.mu.Lock()
			defer r.mu.Unlock()
			s.abortLocked(ctx, step.handle)
			return nil, fmt.Errorf("%w: encoding the responses: %w", ErrInternal, encodeErr)
		}
		r.mu.Lock()
		out, step, err = s.stepUnlock(ctx, true, func(i *instance) api.Function { return i.authResume },
			guest.ScalarArg(step.handle), guest.BufArg(encoded))
		guest.Wipe(encoded)
		if err != nil {
			return nil, withCtxErr(ctx, err)
		}
	}
	if err != nil {
		return nil, withCtxErr(ctx, err)
	}
	// A caller whose context ended while the operation ran on gets no
	// token. What the operation brought stays in the guest for the next
	// call.
	if ctxErr := ctx.Err(); ctxErr != nil {
		guest.Wipe(out)
		return nil, ctxErr
	}
	return out, nil
}

// withCtxErr names ctx's error on err too, when ctx has ended.
func withCtxErr(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil && !errors.Is(err, ctxErr) {
		return fmt.Errorf("%w: %w", ctxErr, err)
	}
	return err
}

// startUnlock runs an operation's first step for a caller that holds the
// profile's lock, and releases it. A start the guest refuses because as many
// operations as it holds are open waits, without the lock, for one of them
// to end, and is tried again. ctx bounds that wait.
func (s *ProfileStore) startUnlock(ctx context.Context, start export, args ...guest.Arg) ([]byte, *authStep, error) {
	r := s.root
	for {
		// Unlocked by a defer: the application's OIDC provider runs in a
		// first step, and its panic is raised again in it (callLocked).
		out, step, full, err := func() ([]byte, *authStep, <-chan struct{}, error) {
			defer r.mu.Unlock()
			out, step, err := s.stepLocked(ctx, false, start, args...)
			if errors.Is(err, ErrState) && !r.closed && !r.closing && r.open >= maxPaused {
				return nil, nil, r.freed, err
			}
			return out, step, nil, err
		}()
		if full == nil {
			return out, step, err
		}
		select {
		case <-full:
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		}
		if err := r.mu.Acquire(ctx); err != nil {
			return nil, nil, err
		}
		if r.closing || r.closed {
			r.mu.Unlock()
			return nil, nil, ErrState
		}
	}
}

// endOpen takes an operation its caller has driven to its end off open,
// and wakes the starts waiting for one to end.
func (s *ProfileStore) endOpen() {
	r := s.root
	r.mu.Lock()
	defer r.mu.Unlock()
	r.open--
	close(r.freed)
	r.freed = make(chan struct{})
}

// stepUnlock is stepLocked for a caller that holds the profile's lock, and
// releases it, panic or not: the application's OIDC provider runs inside a
// guest call, and its panic is raised again here (callLocked).
func (s *ProfileStore) stepUnlock(ctx context.Context, resume bool, fn export, args ...guest.Arg) ([]byte, *authStep, error) {
	defer s.root.mu.Unlock()
	return s.stepLocked(ctx, resume, fn, args...)
}

// stepLocked runs one step of an operation, the export fn with args, with
// the profile's lock held, and says what came of it: the output when done,
// or the operation's step when it paused. A parked operation is registered
// to be woken before the lock is released, and every guest call here is
// followed by waking the operations the guest says may run, so no wake is
// lost between the two.
//
// ctx is the caller's. The first step runs as any call does
// (callLocked). A resume runs on once the caller has gone: its result is
// the operation's, not the caller's (callDetachedLocked). Either way the
// stuck-call backstop starts when ctx ends.
func (s *ProfileStore) stepLocked(ctx context.Context, resume bool, fn export, args ...guest.Arg) ([]byte, *authStep, error) {
	r := s.root
	var out []byte
	var err error
	if resume {
		out, err = s.callDetachedLocked(ctx, fn, args...)
	} else {
		out, err = s.callLocked(ctx, fn, args...)
	}
	defer s.wakeRunnableLocked(ctx)
	if !errors.Is(err, guest.ErrNeedsIO) {
		return out, nil, err
	}
	step, err := s.takeIOLocked(ctx)
	if err != nil {
		return nil, nil, err
	}
	if !resume {
		r.open++
	}
	// Once Close has begun, a parked operation is not waited on: it is
	// left out of parked, so its caller finds it woken, and aborts it.
	if step.parked && !r.closing {
		r.parked[step.handle] = make(chan struct{})
	}
	return nil, step, nil
}

// takeIOLocked takes the step a paused export left (sa_auth_io), once.
//
// It runs whatever the caller's context has done since the export paused:
// the step must be taken, and wazero closes a module called under an ended
// context. So it runs detached, as a resume does (callDetachedLocked): ctx
// only arms the stuck-call backstop, which ends the call StuckAfter ctx
// does. A step that cannot be taken or read closes the profile: the
// operation is still open in the guest, with no handle to abort it by, and
// may hold a lock other operations wait on.
func (s *ProfileStore) takeIOLocked(ctx context.Context) (*authStep, error) {
	ctx, done := guest.Detach(ctx, s.root.stuck)
	defer done()
	inst := s.root.inst
	// The memory stays mapped until the step is copied out and its buffer
	// freed, as around any guest call.
	inst.mem.Enter()
	defer inst.mem.Exit()
	res, err := inst.authIO.Call(ctx)
	if err != nil {
		s.closeLocked()
		return nil, fmt.Errorf("%w: guest call: %w; the profile is closed", guest.ErrTrap, err)
	}
	unreadable := func(why string) (*authStep, error) {
		s.closeLocked()
		return nil, fmt.Errorf("%w: %s; the profile is closed", ErrInternal, why)
	}
	if len(res) == 0 || res[0]>>32 == 0 {
		return unreadable("the guest paused without a step")
	}
	out := guest.Buf{Ptr: uint32(res[0] >> 32), Len: uint32(res[0])} //nolint:gosec // splits the packed u64 into its two u32 halves
	defer inst.exports.Free(ctx, out)
	view, ok := inst.module.Memory().Read(out.Ptr, out.Len)
	if !ok {
		return unreadable("the guest returned an out-of-range step")
	}
	raw := make([]byte, len(view))
	copy(raw, view)
	defer guest.Wipe(raw)
	step, err := decodeAuthStep(raw)
	if err != nil {
		s.closeLocked()
		return nil, fmt.Errorf("%w; the profile is closed", err)
	}
	return step, nil
}

// abortLocked drops a paused or parked operation, and wakes any operation
// that dropping it lets run.
func (s *ProfileStore) abortLocked(ctx context.Context, handle uint64) {
	delete(s.root.parked, handle)
	_, _ = s.callDetachedLocked(ctx, func(i *instance) api.Function { return i.authAbort }, guest.ScalarArg(handle))
	s.wakeRunnableLocked(ctx)
}

// waitRunnable waits for the parked operation handle to be woken, or for
// ctx to end, and says which: true for woken.
func (s *ProfileStore) waitRunnable(ctx context.Context, handle uint64) bool {
	r := s.root
	r.mu.Lock()
	wake, ok := r.parked[handle]
	r.mu.Unlock()
	if !ok {
		// Woken, or the profile closed, before this caller got here.
		return true
	}
	select {
	case <-wake:
		return true
	case <-ctx.Done():
		select {
		case <-wake:
			return true
		default:
			return false
		}
	}
}

// wakeRunnableLocked wakes the parked operations the guest lists as
// runnable. If the list cannot be had, it wakes every parked operation:
// one resumed before it can run only parks again, but one never woken
// would wait for good.
func (s *ProfileStore) wakeRunnableLocked(ctx context.Context) {
	r := s.root
	if len(r.parked) == 0 {
		return
	}
	out, err := s.callDetachedLocked(ctx, func(i *instance) api.Function { return i.authRunnable })
	var handles []uint64
	if err == nil {
		handles, err = decodeRunnable(out)
	}
	if err != nil {
		s.wakeAllLocked()
		return
	}
	for _, h := range handles {
		if wake, ok := r.parked[h]; ok {
			close(wake)
			delete(r.parked, h)
		}
	}
}

// wakeAllLocked wakes every parked operation: when the guest cannot say
// which may run, and when the profile closes, so a parked caller finds out.
func (s *ProfileStore) wakeAllLocked() {
	for h, wake := range s.root.parked {
		close(wake)
		delete(s.root.parked, h)
	}
}
