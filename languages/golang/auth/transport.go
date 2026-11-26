package auth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cipherstash/stack/languages/golang/internal/guest"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// OIDCProvider supplies the identity-provider JWT of the user a call is
// for. The Rust federation strategy asks on every Strategy.Token call: the
// JWT is how it tells one user from another, and it keeps one CTS token per
// distinct JWT, exchanging a JWT only when it has no unexpired CTS token.
// So a server that serves many users through one client must return the
// JWT of the user behind ctx, not a value captured once, and should keep
// the call cheap, as identity-provider SDKs that cache their session are.
//
// Token runs inside the guest call that needs it, while the ProfileStore
// that owns the strategy is locked. It must not call back into that
// ProfileStore or any strategy of it (reading a stored token, building
// another strategy): the call would wait on the same lock and deadlock
// rather than fail. OAuth2TokenSource does not touch the store, so it is
// safe to use from here.
type OIDCProvider interface {
	Token(context.Context) (string, error)
}

// OIDCProviderFunc adapts a function to OIDCProvider.
type OIDCProviderFunc func(context.Context) (string, error)

// Token calls f with ctx and returns what f returns.
func (f OIDCProviderFunc) Token(ctx context.Context) (string, error) { return f(ctx) }

const maxAuthResponseBytes = 16 << 20

// authHTTPStatus records the status of the last HTTP response the transport
// received during one guest call. The guest's error does not always name it
// (a refused response whose body could not be read reaches the guest as a
// transport failure, with no status), and a guest built before se_last_error
// gives no error at all, so without it a refused exchange (the edge in front
// of CTS answering 403) could reach the caller as a bare ErrTransport. It lives on the call's
// context, which wazero hands to the host import, so concurrent calls on
// different profiles never see each other's status.
type authHTTPStatus struct{ code int }

type authHTTPStatusKey struct{}

func withAuthHTTPStatus(ctx context.Context) (context.Context, *authHTTPStatus) {
	status := &authHTTPStatus{}
	return context.WithValue(ctx, authHTTPStatusKey{}, status), status
}

// wrap names the HTTP status of a refused exchange on an ErrTransport
// ("cipherstash: auth transport failed: Server error: 403: HTTP 403", the
// guest's Diagnostic then the status). The body is never included: it may
// be an HTML error page, or echo a credential.
func (s *authHTTPStatus) wrap(err error) error {
	if err == nil || !errors.Is(err, ErrTransport) || s.code == 0 || (s.code >= 200 && s.code < 300) {
		return err
	}
	return fmt.Errorf("%w: HTTP %d", err, s.code)
}

type authTransport struct {
	rt http.RoundTripper
	// grace is how long a refresh request runs on after its caller gives
	// up: refreshGrace, shortened by tests.
	grace        time.Duration
	mu           sync.Mutex
	providers    map[uint32]OIDCProvider
	nextProvider uint32
	// abandoned limits the calls of the application's code that callers
	// gave up on and that are still running (callApplication).
	abandoned abandonLimit
}

func newAuthTransport(rt http.RoundTripper) *authTransport {
	if rt == nil {
		rt = http.DefaultTransport
	}
	return &authTransport{rt: rt, grace: refreshGrace, providers: make(map[uint32]OIDCProvider)}
}

func (t *authTransport) register(provider OIDCProvider) uint32 {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.nextProvider++
	if t.nextProvider == 0 {
		t.nextProvider++
	}
	id := t.nextProvider
	t.providers[id] = provider
	return id
}

func (t *authTransport) unregister(id uint32) {
	t.mu.Lock()
	delete(t.providers, id)
	t.mu.Unlock()
}

// refreshGrace is how long a device session's refresh request runs on after
// its caller's context ends. The token service rotates the refresh token
// when it answers a refresh, so a refresh abandoned after the service
// answered would lose the new token, and the next refresh would send one
// the service has retired. So a refresh is not cancelled with its caller:
// the caller returns at once (Strategy.Token), the request finishes, and
// the guest saves what came back. A refresh still running this long after
// its caller gave up fails as a transport failure, well inside
// guest.StuckAfter, so the profile stays open.
//
// Every other request to the token service (an access-key exchange, an
// OIDC exchange) rotates nothing, and is cancelled with its caller.
const refreshGrace = 10 * time.Second

// refreshKey marks the context of a device session's refresh call
// (withRefresh), whose requests get refreshGrace.
type refreshKey struct{}

// withRefresh marks ctx as a refresh call's.
func withRefresh(ctx context.Context) context.Context {
	return context.WithValue(ctx, refreshKey{}, true)
}

// requestContext is the context a request to the token service runs under:
// the caller's, so a caller that gives up cancels it, except for a refresh,
// which runs on for the grace (see refreshGrace). done must be called when
// the request is finished with.
//
// wait is how long send waits for the application's RoundTripper
// (callApplication). For most requests it is the request's own context.
// For a refresh it is the guest call's: the RoundTripper may ignore its
// request's context, and a rotated refresh token it brings back after the
// grace must still reach the guest, so send waits for it until the
// stuck-call backstop, as it did before it could leave a hung call.
func (t *authTransport) requestContext(ctx context.Context) (req, wait context.Context, done func()) {
	if refresh, _ := ctx.Value(refreshKey{}).(bool); refresh {
		req, done := guest.Detach(guest.Caller(ctx), t.grace)
		return req, ctx, done
	}
	return guest.Caller(ctx), guest.Caller(ctx), func() {}
}

func (t *authTransport) instantiate(ctx context.Context, r wazero.Runtime) error {
	_, err := r.NewHostModuleBuilder("cipherstash_transport").
		NewFunctionBuilder().WithFunc(t.send).Export("transport_send").
		NewFunctionBuilder().WithFunc(t.oidcTokenGet).Export("oidc_token_get").
		Instantiate(ctx)
	return err
}

// send is the same host import contract used by encrypt: four input
// buffers and two output slots, with a negative status on transport failure.
func (t *authTransport) send(ctx context.Context, m api.Module,
	methodPtr, methodLen, urlPtr, urlLen, headersPtr, headersLen, bodyPtr, bodyLen uint32,
	respHeadersPtrOut, respHeadersLenOut, respBodyPtrOut, respBodyLenOut uint32,
) int32 {
	mem := m.Memory()
	method, ok1 := mem.Read(methodPtr, methodLen)
	url, ok2 := mem.Read(urlPtr, urlLen)
	headers, ok3 := mem.Read(headersPtr, headersLen)
	body, ok4 := mem.Read(bodyPtr, bodyLen)
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return t.placeResponse(ctx, m, respHeadersPtrOut, respHeadersLenOut, respBodyPtrOut, respBodyLenOut, -1, nil, []byte("request buffer out of range"))
	}
	requestBody := newAuthRequestBody(body)
	reqCtx, waitCtx, done := t.requestContext(ctx)
	defer done()
	req, err := http.NewRequestWithContext(reqCtx, string(method), string(url), requestBody)
	if err != nil {
		_ = requestBody.Close()
		return t.placeResponse(ctx, m, respHeadersPtrOut, respHeadersLenOut, respBodyPtrOut, respBodyLenOut, -1, nil, []byte(err.Error()))
	}
	req.ContentLength = int64(len(body))
	req.Header = parseAuthHeaders(headers)
	resp, err := callApplication(waitCtx, &t.abandoned, func() (authResponse, error) { return t.exchange(req) },
		func(r authResponse) { guest.Wipe(r.body) })
	defer guest.Wipe(resp.body)
	// The body carries the access key or the refresh grant. The transport
	// wipes it by closing it, as the RoundTripper contract asks, but code
	// that panicked or was left running may never close it; a read after
	// this Close fails rather than send a wiped body.
	if errors.Is(err, errApplicationPanicked) || errors.Is(err, errAbandoned) || errors.Is(err, errTooManyAbandoned) {
		_ = requestBody.Close()
	}
	if status, ok := ctx.Value(authHTTPStatusKey{}).(*authHTTPStatus); ok && resp.status != 0 {
		status.code = resp.status
	}
	if err != nil {
		return t.placeResponse(ctx, m, respHeadersPtrOut, respHeadersLenOut, respBodyPtrOut, respBodyLenOut, -1, nil, []byte(err.Error()))
	}
	return t.placeResponse(ctx, m, respHeadersPtrOut, respHeadersLenOut, respBodyPtrOut, respBodyLenOut, int32(resp.status), encodeAuthHeaders(resp.header), resp.body) //nolint:gosec // range-checked in exchange
}

// authResponse is a token service response, read whole.
type authResponse struct {
	// status is the HTTP status, or 0 when no valid response arrived.
	status int
	header http.Header
	body   []byte
}

// exchange sends req through the RoundTripper and reads the response. A
// response it refuses (too large, or an unreadable body) still reports its
// status, for authHTTPStatus.
func (t *authTransport) exchange(req *http.Request) (authResponse, error) {
	resp, err := t.rt.RoundTrip(req)
	if err != nil {
		return authResponse{}, err
	}
	defer resp.Body.Close()
	// A caller's RoundTripper can return any int; the guest gets an i32.
	if resp.StatusCode < 100 || resp.StatusCode > 999 {
		return authResponse{}, fmt.Errorf("invalid HTTP status %d", resp.StatusCode)
	}
	refused := authResponse{status: resp.StatusCode}
	if resp.ContentLength > maxAuthResponseBytes {
		return refused, errors.New("auth response exceeds limit")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAuthResponseBytes+1))
	if err != nil {
		guest.Wipe(body)
		return refused, err
	}
	if len(body) > maxAuthResponseBytes {
		guest.Wipe(body)
		return refused, errors.New("auth response exceeds limit")
	}
	return authResponse{status: resp.StatusCode, header: resp.Header, body: body}, nil
}

// The application's code that the guest's host functions call (the
// RoundTripper, an OIDCProvider) runs in the middle of a guest call, with
// the ProfileStore locked. callApplication keeps it from ending that call
// badly. Without it, a panic there was recovered by wazero as a guest trap,
// which closed the profile for good and never reached the caller; and a
// RoundTripper that ignored its request's context held the store's lock,
// and every caller that needed a token, until it returned, or until the
// stuck-call backstop closed the profile.

// errApplicationPanicked is the failure a host function gives the guest
// when the application's code it called panicked. The guest fails the
// request as it fails any transport failure, and callArgs raises the panic
// again on the caller's goroutine (hostPanic).
var errApplicationPanicked = errors.New("the application's code panicked")

// errAbandoned is the failure a host function gives the guest when its
// caller gave up before the application's code returned.
var errAbandoned = errors.New("the caller gave up before the application's code returned")

// errTooManyAbandoned is the failure a host function gives the guest, without
// calling the application's code, while maxAbandoned calls of it that callers
// gave up on are still running.
var errTooManyAbandoned = errors.New("too many calls of the application's code that callers gave up on are still running")

// maxAbandoned is how many calls of the application's code that callers
// gave up on may still be running for one store. Each holds a goroutine,
// and a request the application has not let go of. Code that ignores its
// context could otherwise leave one behind for every caller that gives up,
// where before it could leave one: it held the store's lock. Past the limit
// a call fails at once, as a transport failure, until one of them returns.
const maxAbandoned = 4

// abandonLimit counts the running calls of the application's code whose
// callers gave up.
type abandonLimit struct {
	mu sync.Mutex
	n  int
}

// full reports whether no more calls may be left running.
func (l *abandonLimit) full() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.n >= maxAbandoned
}

func (l *abandonLimit) add() {
	l.mu.Lock()
	l.n++
	l.mu.Unlock()
}

func (l *abandonLimit) done() {
	l.mu.Lock()
	l.n--
	l.mu.Unlock()
}

// hostPanic holds a panic of the application's code, recorded by a host
// function during a guest call, for callArgs to raise again on the
// caller's goroutine once the call has returned: as a panic in encrypt's
// RoundTripper reaches the caller, which can recover it as net/http does
// in each handler.
type hostPanic struct {
	mu    sync.Mutex
	value any
	set   bool
}

type hostPanicKey struct{}

// withHostPanic gives ctx a hostPanic for the guest call it runs.
func withHostPanic(ctx context.Context) (context.Context, *hostPanic) {
	h := &hostPanic{}
	return context.WithValue(ctx, hostPanicKey{}, h), h
}

// record keeps the first panic of a call.
func (h *hostPanic) record(p any) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.set {
		h.value, h.set = p, true
	}
}

// raise panics with the recorded panic, if there is one, after calling
// before (to wipe what the call returned, say).
func (h *hostPanic) raise(before func()) {
	h.mu.Lock()
	value, set := h.value, h.set
	h.mu.Unlock()
	if set {
		if before != nil {
			before()
		}
		panic(value)
	}
}

// callApplication runs f, application code a host function calls, on a
// goroutine of its own, and waits for f or for ctx to end, whichever comes
// first.
//
//   - When ctx ends first, it returns errAbandoned, with ctx's error, at
//     once. f is left to finish; what it returns then goes to discard, and a
//     panic of it is dropped: there is no caller left to raise it to.
//   - When f panics, the panic is recorded on ctx's hostPanic, and
//     callApplication returns errApplicationPanicked.
//   - When ctx has already ended, it returns errAbandoned and does not
//     call f.
//   - limit, when not nil, counts the calls left running. While it is full,
//     callApplication returns errTooManyAbandoned and does not call f.
func callApplication[T any](ctx context.Context, limit *abandonLimit, f func() (T, error), discard func(T)) (T, error) {
	var zero T
	// A caller that has already gone starts nothing: the guest may retry a
	// request whose caller gave up, and the retry would leave another call
	// running.
	if err := ctx.Err(); err != nil {
		return zero, fmt.Errorf("%w: %w", errAbandoned, err)
	}
	if limit != nil && limit.full() {
		return zero, errTooManyAbandoned
	}
	type result struct {
		value    T
		err      error
		panicked bool
		panic    any
	}
	done := make(chan result, 1)
	go func() {
		var r result
		defer func() {
			if p := recover(); p != nil {
				r = result{panicked: true, panic: p}
			}
			done <- r
		}()
		r.value, r.err = f()
	}()
	settle := func(r result) (T, error) {
		if r.panicked {
			if h, ok := ctx.Value(hostPanicKey{}).(*hostPanic); ok {
				h.record(r.panic)
			}
			return zero, errApplicationPanicked
		}
		return r.value, r.err
	}
	select {
	case r := <-done:
		return settle(r)
	case <-ctx.Done():
		// f that finished as ctx ended still answers.
		select {
		case r := <-done:
			return settle(r)
		default:
		}
		if limit != nil {
			limit.add()
		}
		go func() {
			if r := <-done; !r.panicked && discard != nil {
				discard(r.value)
			}
			if limit != nil {
				limit.done()
			}
		}()
		return zero, fmt.Errorf("%w: %w", errAbandoned, ctx.Err())
	}
}

func (t *authTransport) placeResponse(ctx context.Context, m api.Module,
	hp, hl, bp, bl uint32, status int32, headers, body []byte,
) int32 {
	if !guest.Place(ctx, m, hp, hl, headers) || !guest.Place(ctx, m, bp, bl, body) {
		return -1
	}
	return status
}

func (t *authTransport) oidcTokenGet(ctx context.Context, m api.Module, provider, ptrOut, lenOut uint32) int32 {
	t.mu.Lock()
	source := t.providers[provider]
	t.mu.Unlock()
	if source == nil {
		return 1
	}
	caller := guest.Caller(ctx)
	token, err := callApplication(caller, &t.abandoned, func() (string, error) { return source.Token(caller) }, nil)
	if err != nil || token == "" || strings.ContainsAny(token, "\r\n\x00") {
		return 1
	}
	bytes := []byte(token)
	defer guest.Wipe(bytes)
	if !guest.Place(ctx, m, ptrOut, lenOut, bytes) {
		return 1
	}
	return 0
}

func parseAuthHeaders(buf []byte) http.Header {
	h := make(http.Header)
	for _, line := range strings.Split(string(buf), "\n") {
		name, value, ok := strings.Cut(line, ":")
		if ok {
			h.Add(strings.TrimSpace(name), strings.TrimSpace(value))
		}
	}
	return h
}

func encodeAuthHeaders(h http.Header) []byte {
	names := make([]string, 0, len(h))
	for name := range h {
		names = append(names, name)
	}
	sort.Strings(names)
	var out strings.Builder
	for _, name := range names {
		for _, value := range h[name] {
			if out.Len() > 0 {
				out.WriteByte('\n')
			}
			fmt.Fprintf(&out, "%s: %s", name, value)
		}
	}
	return []byte(out.String())
}

// The host owns its request-body copy until the RoundTripper closes it.
// A transport may read after RoundTrip returns, so wiping on return races.
type authRequestBody struct {
	mu     sync.Mutex
	buf    []byte
	off    int
	closed bool
}

func newAuthRequestBody(src []byte) *authRequestBody {
	buf := append([]byte(nil), src...)
	return &authRequestBody{buf: buf}
}

func (b *authRequestBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return 0, errors.New("auth request body read after close")
	}
	if b.off == len(b.buf) {
		return 0, io.EOF
	}
	n := copy(p, b.buf[b.off:])
	b.off += n
	return n, nil
}

func (b *authRequestBody) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.closed {
		guest.Wipe(b.buf)
		b.closed = true
	}
	return nil
}
