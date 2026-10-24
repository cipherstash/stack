package encrypt

import (
	"context"
	"errors"
	"fmt"

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

// stepFunc runs one step of an operation in the guest, under ctx.
type stepFunc func(ctx context.Context, inst *instance) ([]byte, error)

// ioStep is a paused operation's step, as the guest hands it over: the
// operation's handle and the requests it waits on.
type ioStep struct {
	handle   uint64
	requests []ioRequest
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
	var sawHandle bool
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
	if !sawHandle || len(step.requests) == 0 {
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
	return r, r.method != "" && r.url != ""
}

// performStep performs every request of a step, in order, and encodes the
// responses for se_resume: `[{"status": i32, "headers": bytes, "body":
// bytes}, ...]`. The responses can carry wrapped keys: the caller wipes the
// encoding once the guest has it, and every other copy is wiped here.
func (t *transport) performStep(ctx context.Context, step *ioStep) ([]byte, error) {
	defer step.wipe()
	responses := make([]any, 0, len(step.requests))
	var bodies [][]byte
	defer func() {
		for _, b := range bodies {
			wipe(b)
		}
	}()
	for _, r := range step.requests {
		status, headers, body := t.perform(ctx, r.method, r.url, r.headers, r.body)
		if headers == nil {
			headers = []byte{}
		}
		if body == nil {
			body = []byte{}
		}
		bodies = append(bodies, body)
		responses = append(responses, vcvalue.Object{
			{Key: "status", Value: status},
			{Key: "headers", Value: headers},
			{Key: "body", Value: body},
		})
	}
	return vcffi.Marshal(responses)
}
