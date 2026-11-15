package encrypt

import (
	"context"
	"errors"
	"fmt"
	"time"

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
// A key vendor backend pauses the same way, for three things: its HTTP
// requests, the short-lived credential it signs them with (answered from
// the backend's credential source, which may itself wait on the network),
// and the backoff before a retry. The guest blocks on none of them.

// stepFunc runs one step of an operation in the guest, under ctx.
type stepFunc func(ctx context.Context, inst *instance) ([]byte, error)

// ioStep is a paused operation's step, as the guest hands it over: the
// operation's handle and the requests it waits on.
type ioStep struct {
	handle   uint64
	requests []ioRequest
}

// ioRequest is one thing the guest needs done: an HTTP request performed
// (method and url set), a key vendor credential fetched (credential set),
// or a wait sat out (wait set). An HTTP request's headers carry the bearer
// token and its body key-material contexts, so both are wiped once
// performed.
type ioRequest struct {
	method, url   string
	headers, body []byte
	// credential is the key vendor credential the guest asks for.
	credential *credentialRequest
	// wait is how long the guest asks to wait, when it asks.
	wait *time.Duration
}

// credentialRequest is a key vendor credential the guest asks for: the
// vendor's KeyVendor byte and the OAuth scope, empty when it has none.
type credentialRequest struct {
	vendor uint32
	scope  string
}

// maxScopeBytes bounds the scope of a credential request. A real OAuth
// scope is well under it.
const maxScopeBytes = 1024

// maxWait bounds a wait the guest asks for. A vendor client's backoff is
// far under it; a longer one is cut to it rather than hold a caller.
const maxWait = 30 * time.Second

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
	if len(obj) == 1 {
		switch obj[0].Key {
		case "credential":
			c, ok := decodeCredentialRequest(obj[0].Value)
			return ioRequest{credential: c}, ok
		case "wait_ms":
			ms, ok := obj[0].Value.(uint64)
			if !ok {
				return ioRequest{}, false
			}
			wait := maxWait
			if ms < uint64(maxWait/time.Millisecond) {
				wait = time.Duration(ms) * time.Millisecond //nolint:gosec // bounded by maxWait above
			}
			return ioRequest{wait: &wait}, true
		}
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

// decodeCredentialRequest reads `{"vendor": u32, "scope": string}`.
func decodeCredentialRequest(value any) (*credentialRequest, bool) {
	obj, ok := value.(vcvalue.Object)
	if !ok {
		return nil, false
	}
	var c credentialRequest
	var sawVendor, sawScope bool
	for _, f := range obj {
		switch f.Key {
		case "vendor":
			c.vendor, ok = f.Value.(uint32)
			sawVendor = true
		case "scope":
			c.scope, ok = f.Value.(string)
			sawScope = true
		default:
			ok = false
		}
		if !ok {
			return nil, false
		}
	}
	if !sawVendor || !sawScope || len(c.scope) > maxScopeBytes {
		return nil, false
	}
	return &c, true
}

// operation is what the host keeps for one operation across its steps: the
// key vendor credentials it has fetched for it, so that an operation that
// makes several vendor requests asks the source once per vendor and scope,
// and why the source last failed, which the guest sees only as a failed
// request. The credentials are wiped when the operation ends.
type operation struct {
	credentials map[credentialRequest][]byte
	credErr     error
}

// end wipes the credentials the operation fetched.
func (op *operation) end() {
	for _, c := range op.credentials {
		wipe(c)
	}
	op.credentials = nil
}

// performStep performs every request of a step, in order, and encodes the
// responses for se_resume: `[{"status": i32, "headers": bytes, "body":
// bytes}, ...]`. The responses can carry key material (a ZeroKMS response,
// or from a key vendor backend an unwrapped key in plaintext) or a
// credential: the caller wipes the encoding once the guest has it, and
// every other copy this side holds is wiped here. The copies in net/http,
// TLS and the RoundTripper are not.
func (t *transport) performStep(ctx context.Context, step *ioStep, op *operation) ([]byte, error) {
	defer step.wipe()
	responses := make([]any, 0, len(step.requests))
	var bodies [][]byte
	defer func() {
		for _, b := range bodies {
			wipe(b)
		}
	}()
	for _, r := range step.requests {
		var status int32
		var headers, body []byte
		switch {
		case r.credential != nil:
			status, body = t.credential(ctx, *r.credential, op)
		case r.wait != nil:
			status = t.sit(ctx, *r.wait)
		default:
			status, headers, body = t.perform(ctx, r.method, r.url, r.headers, r.body)
		}
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

// credential answers a credential request: status 0 and the credential,
// encoded for the guest, or transportFailed and the error text. The
// credential is fetched once per operation, vendor and scope, outside the
// client's lock, under the caller's context; the body returned is a copy
// the caller wipes.
func (t *transport) credential(ctx context.Context, req credentialRequest, op *operation) (int32, []byte) {
	if c, ok := op.credentials[req]; ok {
		return 0, append([]byte(nil), c...)
	}
	if t.vendor == nil {
		op.credErr = errors.New("encrypt: the guest asked for a key vendor credential, but the client has no key vendor backend")
		return transportFailed, []byte(op.credErr.Error())
	}
	cred, err := t.vendor.vendorCredential(ctx, req.vendor, req.scope)
	if err != nil {
		op.credErr = err
		// The guest reads the text; it names the failure, never a secret,
		// since the source's errors carry none.
		return transportFailed, []byte(err.Error())
	}
	if op.credentials == nil {
		op.credentials = make(map[credentialRequest][]byte)
	}
	op.credentials[req] = cred
	return 0, append([]byte(nil), cred...)
}

// sit waits d, or until ctx ends: a retry's backoff, sat out with the
// client free for other callers. Status 0 once it has passed; a caller
// that gives up meanwhile ends the operation in drive, between steps.
func (t *transport) sit(ctx context.Context, d time.Duration) int32 {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return 0
	case <-ctx.Done():
		return transportFailed
	}
}
