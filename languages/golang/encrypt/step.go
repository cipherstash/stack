package encrypt

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/cipherstash/stack/languages/golang/internal/guest"
	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// The step loop. The guest never waits on the network: an export that
// needs ZeroKMS pauses instead, returning the requests it is waiting on and
// a handle (guest.ErrNeedsIO, then se_io). The host performs the requests,
// outside the client's lock, and resumes the operation with the responses
// (se_resume), until it is done. So the lock is held only while the guest
// runs, never across a network round trip, and a caller that gives up
// between two steps aborts the operation (se_abort) while the guest is not
// running at all.
//
// A step can also pause with no requests: a yield. The guest's engine yields
// every few dozen data keys while it builds, seals or opens a batch, because
// the Go runtime cannot preempt a running guest call: its garbage
// collector's stop-the-world pause, and every other caller of the client,
// would otherwise wait for the whole batch. Fields with an EQL type are not
// built in chunks: the guest prepares every such field of every row before
// its first yield. The host resumes a yield at once, with no responses, and
// the client's lock is released in between like any step.

// stepFunc runs one step of an operation in the guest, under ctx.
type stepFunc func(ctx context.Context, inst *instance) ([]byte, error)

// ioStep is a paused operation's step, as the guest hands it over: the
// operation's handle and the requests it waits on, none for a yield.
// performStep sets netErr to the net error of the first request that could
// not be performed, if that request failed on the network. A later request's
// net error is not taken: the first failure may have had another cause.
type ioStep struct {
	handle   uint64
	requests []ioRequest
	netErr   error
}

// ioRequest is one HTTP request the guest needs performed. The headers
// carry the bearer token and the body key-material contexts, so both are
// wiped once performed.
type ioRequest struct {
	method, url   string
	headers, body []byte
}

func (s *ioStep) wipe() {
	for _, r := range s.requests {
		wipe(r.headers)
		wipe(r.body)
	}
}

var errMalformedStep = errors.New("encrypt: the guest's step is malformed")

// takeIO takes the step a paused export left (se_io), once.
func (inst *instance) takeIO(ctx context.Context) (*ioStep, error) {
	// The same bracket guest.Call keeps: the memory stays mapped until the
	// step is copied out and its buffer freed.
	inst.mem.Enter()
	defer inst.mem.Exit()
	res, err := inst.io.Call(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: guest call: %w", errGuestTrap, err)
	}
	if len(res) == 0 || res[0]>>32 == 0 {
		return nil, fmt.Errorf("%w: the guest paused without a step", guest.ErrInternal)
	}
	out := guest.Buf{Ptr: uint32(res[0] >> 32), Len: uint32(res[0])} //nolint:gosec // splits the packed u64 into its two u32 halves
	defer inst.exports.Free(ctx, out)
	view, ok := inst.module.Memory().Read(out.Ptr, out.Len)
	if !ok {
		return nil, errors.New("encrypt: guest returned an out-of-range buffer")
	}
	raw := make([]byte, len(view))
	copy(raw, view)
	defer wipe(raw)
	return decodeStep(raw)
}

// decodeStep reads `{"handle": u64, "requests": [{"method", "url",
// "headers", "body"}, ...]}`. Every byte slice the decoder returns is its
// own copy.
func decodeStep(raw []byte) (*ioStep, error) {
	decoded, err := vcffi.Unmarshal(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errMalformedStep, err)
	}
	obj, ok := decoded.(vcvalue.Object)
	if !ok {
		return nil, errMalformedStep
	}
	step := &ioStep{}
	var sawHandle, sawRequests bool
	for _, f := range obj {
		switch f.Key {
		case "handle":
			h, ok := f.Value.(uint64)
			if !ok {
				return nil, errMalformedStep
			}
			step.handle, sawHandle = h, true
		case "requests":
			items, ok := f.Value.([]any)
			if !ok {
				return nil, errMalformedStep
			}
			sawRequests = true
			for _, item := range items {
				r, ok := decodeRequest(item)
				if !ok {
					step.wipe()
					return nil, errMalformedStep
				}
				step.requests = append(step.requests, r)
			}
		default:
			step.wipe()
			return nil, errMalformedStep
		}
	}
	// An empty list is a yield; a missing one is malformed.
	if !sawHandle || !sawRequests {
		step.wipe()
		return nil, errMalformedStep
	}
	return step, nil
}

func decodeRequest(item any) (ioRequest, bool) {
	obj, ok := item.(vcvalue.Object)
	if !ok {
		return ioRequest{}, false
	}
	var r ioRequest
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
			wipe(r.headers)
			wipe(r.body)
			return ioRequest{}, false
		}
	}
	if r.method == "" || r.url == "" {
		wipe(r.headers)
		wipe(r.body)
		return ioRequest{}, false
	}
	return r, true
}

// maxParallelRequests bounds how many of a step's requests are performed at
// once. The guest asks for at most `max_concurrent_reqs` in a step (3, in
// its cipher_init), so this never binds for it; it keeps a step from
// starting any number of goroutines.
const maxParallelRequests = 8

// performStep performs a step's requests, up to maxParallelRequests at once,
// and encodes the responses, in the order of the requests, for se_resume:
// `[{"status": i32, "headers": bytes, "body": bytes}, ...]`. A step's
// requests are independent: the guest sends several at once only when it
// can use their responses in any order. The responses can carry wrapped
// keys: the caller wipes the encoding once the guest has it, and every
// other copy is wiped here.
func (t *transport) performStep(ctx context.Context, step *ioStep) ([]byte, error) {
	defer step.wipe()
	type result struct {
		status        int32
		headers, body []byte
		netErr        error
	}
	results := make([]result, len(step.requests))
	defer func() {
		for _, r := range results {
			wipe(r.body)
		}
	}()
	slots := make(chan struct{}, maxParallelRequests)
	var wg sync.WaitGroup
	// A panic in the caller's RoundTripper is recovered in its goroutine
	// and raised again here, on the caller's goroutine, once every request
	// has finished, as when the requests were performed one at a time. A
	// panic left in the goroutine would end the process, past any recover
	// of the caller's, such as net/http's in each handler.
	var panicOnce sync.Once
	var panicked any
	for i, r := range step.requests {
		slots <- struct{}{}
		wg.Go(func() {
			defer func() { <-slots }()
			defer func() {
				if p := recover(); p != nil {
					panicOnce.Do(func() { panicked = p })
				}
			}()
			status, headers, body, netErr := t.perform(ctx, r.method, r.url, r.headers, r.body)
			results[i] = result{status, headers, body, netErr}
		})
	}
	wg.Wait()
	if panicked != nil {
		panic(panicked)
	}
	responses := make([]any, 0, len(results))
	failed := false
	for _, r := range results {
		if !failed && r.status == transportFailed {
			failed = true
			step.netErr = r.netErr
		}
		status, headers, body := r.status, r.headers, r.body
		if headers == nil {
			headers = []byte{}
		}
		if body == nil {
			body = []byte{}
		}
		responses = append(responses, vcvalue.Object{
			{Key: "status", Value: status},
			{Key: "headers", Value: headers},
			{Key: "body", Value: body},
		})
	}
	return vcffi.Marshal(responses)
}
