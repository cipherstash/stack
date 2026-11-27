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
// once, parked ones included: the guest's MAX_OPEN, which refuses one more.
// Each operation takes a slot for its whole life, so callers past it wait
// for a slot rather than fail.
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

var errMalformedStep = fmt.Errorf("%w: the guest's step is malformed", ErrInternal)

// decodeAuthStep reads `{"handle": u64, "parked": bool, "requests":
// [{"method", "url", "headers", "body"}, ...]}`. Every byte slice it
// returns is its own copy.
func decodeAuthStep(raw []byte) (*authStep, error) {
	decoded, err := vcffi.Unmarshal(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errMalformedStep, err)
	}
	obj, ok := decoded.(vcvalue.Object)
	if !ok {
		return nil, errMalformedStep
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
			step.wipe()
			return nil, errMalformedStep
		}
	}
	// A parked operation asks for nothing; an empty list otherwise is a
	// yield.
	if !sawHandle || !sawParked || !sawRequests || (step.parked && len(step.requests) > 0) {
		step.wipe()
		return nil, errMalformedStep
	}
	return step, nil
}

func decodeAuthRequest(item any) (authRequest, bool) {
	obj, ok := item.(vcvalue.Object)
	if !ok {
		return authRequest{}, false
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
			guest.Wipe(r.headers)
			guest.Wipe(r.body)
			return authRequest{}, false
		}
	}
	if r.method == "" || r.url == "" {
		guest.Wipe(r.headers)
		guest.Wipe(r.body)
		return authRequest{}, false
	}
	return r, true
}

// decodeRunnable reads the list of parked handles the guest may resume.
func decodeRunnable(raw []byte) ([]uint64, error) {
	decoded, err := vcffi.Unmarshal(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: the runnable operations: %w", ErrInternal, err)
	}
	items, ok := decoded.([]any)
	if !ok {
		return nil, fmt.Errorf("%w: the runnable operations are not a list", ErrInternal)
	}
	handles := make([]uint64, 0, len(items))
	for _, item := range items {
		h, ok := item.(uint64)
		if !ok {
			return nil, fmt.Errorf("%w: a runnable operation is not a handle", ErrInternal)
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
// It bounds the wait for a slot and for the profile's lock before the
// operation starts, and the wait while it is parked. Once a request is in
// flight the operation is finished whatever ctx does (see above), and a
// caller whose ctx ended by then gets its error and no output.
func (s *ProfileStore) run(ctx context.Context, start export, args ...guest.Arg) ([]byte, error) {
	r := s.root
	select {
	case r.slots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-r.slots }()

	if err := r.mu.Acquire(ctx); err != nil {
		return nil, err
	}
	out, step, err := s.stepUnlock(ctx, start, args...)
	// Once started, the operation is driven to its end: a resume waits for
	// the lock, and runs, whatever the caller's context does.
	resumeCtx := context.WithoutCancel(ctx)
	for step != nil {
		var responses []response
		if step.parked {
			if !s.waitRunnable(ctx, step.handle) {
				r.mu.Lock()
				defer r.mu.Unlock()
				s.abortLocked(resumeCtx, step.handle)
				return nil, ctx.Err()
			}
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
			s.abortLocked(resumeCtx, step.handle)
			return nil, fmt.Errorf("%w: encoding the responses: %w", ErrInternal, encodeErr)
		}
		r.mu.Lock()
		out, step, err = s.stepUnlock(resumeCtx, func(i *instance) api.Function { return i.authResume },
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

// stepUnlock is stepLocked for a caller that holds the profile's lock, and
// releases it, panic or not: the application's OIDC provider runs inside a
// guest call, and its panic is raised again here (callLocked).
func (s *ProfileStore) stepUnlock(ctx context.Context, fn export, args ...guest.Arg) ([]byte, *authStep, error) {
	defer s.root.mu.Unlock()
	return s.stepLocked(ctx, fn, args...)
}

// stepLocked runs one step of an operation, the export fn with args, with
// the profile's lock held, and says what came of it: the output when done,
// or the operation's step when it paused. A parked operation is registered
// to be woken before the lock is released, and every guest call here is
// followed by waking the operations the guest says may run, so no wake is
// lost between the two.
func (s *ProfileStore) stepLocked(ctx context.Context, fn export, args ...guest.Arg) ([]byte, *authStep, error) {
	r := s.root
	out, err := s.callLocked(ctx, fn, args...)
	defer s.wakeRunnableLocked(ctx)
	if !errors.Is(err, guest.ErrNeedsIO) {
		return out, nil, err
	}
	step, err := s.takeIOLocked(ctx)
	if err != nil {
		return nil, nil, err
	}
	if step.parked {
		r.parked[step.handle] = make(chan struct{})
	}
	return nil, step, nil
}

// takeIOLocked takes the step a paused export left (sa_auth_io), once.
func (s *ProfileStore) takeIOLocked(ctx context.Context) (*authStep, error) {
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
	if len(res) == 0 || res[0]>>32 == 0 {
		return nil, fmt.Errorf("%w: the guest paused without a step", ErrInternal)
	}
	out := guest.Buf{Ptr: uint32(res[0] >> 32), Len: uint32(res[0])} //nolint:gosec // splits the packed u64 into its two u32 halves
	defer inst.exports.Free(ctx, out)
	view, ok := inst.module.Memory().Read(out.Ptr, out.Len)
	if !ok {
		return nil, fmt.Errorf("%w: the guest returned an out-of-range step", ErrInternal)
	}
	raw := make([]byte, len(view))
	copy(raw, view)
	defer guest.Wipe(raw)
	return decodeAuthStep(raw)
}

// abortLocked drops a paused or parked operation, and wakes any operation
// that dropping it lets run.
func (s *ProfileStore) abortLocked(ctx context.Context, handle uint64) {
	delete(s.root.parked, handle)
	_, _ = s.callLocked(ctx, func(i *instance) api.Function { return i.authAbort }, guest.ScalarArg(handle))
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
	out, err := s.callLocked(context.WithoutCancel(ctx), func(i *instance) api.Function { return i.authRunnable })
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
