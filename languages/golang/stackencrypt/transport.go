package stackencrypt

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// transportModule is the name of the guest's one import module. Its two
// functions are the whole host surface the guest can reach.
const transportModule = "cipherstash_transport"

// tokenSource supplies the bearer token the guest presents to ZeroKMS. It
// is asked on every request, so a source that rotates tokens needs no
// re-initialisation of the client. Outside this package's tests it is
// always a *stackauth.Strategy: minting and refresh stay host-side, out of
// the crypto guest, in stackauth's credential guest. The interface is
// unexported so that no caller can hand the client a raw token, which could
// not be refreshed and would bypass the strategies' refresh lock.
type tokenSource interface {
	Token(ctx context.Context) (string, error)
}

// transport implements the guest's two host imports over a RoundTripper
// and a tokenSource. One per Client; it is bound to the module at
// instantiation and reaches the guest's allocator through the module the
// call arrives on.
type transport struct {
	rt    http.RoundTripper
	token tokenSource
	// sends counts transport_send excursions, so tests can pin the batching
	// contract (one ZeroKMS call per operation) instead of trusting it.
	sends atomic.Int64
	// tokenErr is why the token source last failed during the call in
	// flight: the guest sees only that token_get failed, so Client.call
	// attaches the cause — ErrNoCredentials, a refused refresh — to the
	// error it returns. Only touched under the client's lock, which every
	// guest call holds.
	tokenErr error
}

// transportFailed is the return value of transport_send when the request
// could not be performed at all; the body then carries the error text.
const transportFailed int32 = -1

// hostFailed is the return value of token_get when no token is available.
const hostFailed int32 = 1

// maxResponseBytes bounds what transport_send will buffer from ZeroKMS. The
// guest issues at most one 500-key batch per request, which is well under a
// megabyte either way; the bound exists so that an endpoint the transport
// was pointed at cannot make the host allocate without limit.
const maxResponseBytes = 16 << 20

// instantiate registers the host module in r.
func (t *transport) instantiate(ctx context.Context, r wazero.Runtime) error {
	_, err := r.NewHostModuleBuilder(transportModule).
		NewFunctionBuilder().WithFunc(t.send).Export("transport_send").
		NewFunctionBuilder().WithFunc(t.tokenGet).Export("token_get").
		Instantiate(ctx)
	if err != nil {
		return fmt.Errorf("stackencrypt: instantiating host transport: %w", err)
	}
	return nil
}

// send is transport_send: one HTTP request on the guest's behalf. Inputs
// are (ptr, len) pairs borrowed for the call; the two outputs are slot
// pairs filled with buffers obtained from the guest's se_alloc. Returns
// the HTTP status, or transportFailed with the error text as the body.
func (t *transport) send(ctx context.Context, m api.Module,
	methodPtr, methodLen, urlPtr, urlLen, headersPtr, headersLen, bodyPtr, bodyLen uint32,
	respHeadersPtrOut, respHeadersLenOut, respBodyPtrOut, respBodyLenOut uint32,
) int32 {
	t.sends.Add(1)
	mem := m.Memory()
	status, respHeaders, respBody := t.perform(ctx, mem,
		methodPtr, methodLen, urlPtr, urlLen, headersPtr, headersLen, bodyPtr, bodyLen)
	// The response carries wrapped key material; once it is in guest memory
	// the host copy is wiped.
	defer wipe(respBody)
	if !place(ctx, m, respHeadersPtrOut, respHeadersLenOut, respHeaders) ||
		!place(ctx, m, respBodyPtrOut, respBodyLenOut, respBody) {
		// The guest reclaims whatever was placed and refuses an unplaced
		// slot as an unregistered buffer; nothing more this side can do.
		return transportFailed
	}
	return status
}

func (t *transport) perform(ctx context.Context, mem api.Memory,
	methodPtr, methodLen, urlPtr, urlLen, headersPtr, headersLen, bodyPtr, bodyLen uint32,
) (int32, []byte, []byte) {
	method, ok1 := mem.Read(methodPtr, methodLen)
	url, ok2 := mem.Read(urlPtr, urlLen)
	headers, ok3 := mem.Read(headersPtr, headersLen)
	body, ok4 := mem.Read(bodyPtr, bodyLen)
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return transportFailed, nil, []byte("guest request buffers out of range")
	}
	// The request body may carry key-material contexts; it is copied
	// because the guest wipes its own buffer when the call returns, and the
	// RoundTripper may read it after this function has. The copy is owned
	// by the request body handed to the RoundTripper and is wiped when that
	// body is closed — not here: RoundTrip may go on reading, and close,
	// in another goroutine after it has returned, on the error path
	// included, and a wipe racing that send would put a truncated or
	// zeroed request on the wire.
	reqBody := newRequestBody(body)
	req, err := http.NewRequestWithContext(ctx, string(method), string(url), reqBody)
	if err != nil {
		reqBody.Close()
		return transportFailed, nil, []byte(err.Error())
	}
	// NewRequest only infers a length from the readers it knows; without
	// one the transport would send the body chunked.
	req.ContentLength = int64(len(body))
	req.Header = parseHeaders(headers)
	resp, err := t.rt.RoundTrip(req)
	if err != nil {
		return transportFailed, nil, []byte(err.Error())
	}
	defer resp.Body.Close()
	if resp.ContentLength > maxResponseBytes {
		return transportFailed, nil, fmt.Appendf(nil, "response of %d bytes exceeds the %d-byte limit", resp.ContentLength, maxResponseBytes)
	}
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		// ReadAll hands back what it managed to read alongside the error.
		// Those bytes are a partial ZeroKMS response and can carry wrapped
		// key material, so they are wiped rather than dropped on the floor
		// for the collector — the same discipline as the over-limit branch
		// below.
		wipe(respBody)
		return transportFailed, nil, []byte(err.Error())
	}
	if len(respBody) > maxResponseBytes {
		wipe(respBody)
		return transportFailed, nil, fmt.Appendf(nil, "response exceeds the %d-byte limit", maxResponseBytes)
	}
	return int32(resp.StatusCode), encodeHeaders(resp.Header), respBody
}

// requestBody is the io.ReadCloser a guest request goes out as. It owns
// the host copy of the body and wipes it on Close, the one point at which
// the RoundTripper contract says the transport is done with it: RoundTrip
// must close the body, but may do so in another goroutine after it has
// returned, so nothing this side can wipe any earlier without racing the
// send. Read and Close are serialised for the same reason. A transport
// that never closes the body leaves it to the collector, as any body it
// was handed; a Close before the send is complete fails the read rather
// than sending zeros in place of the request.
//
// A body of this type has no GetBody, so net/http cannot replay the
// request on a reused connection that turns out to be dead. Replay would
// need the plaintext to outlive Close, and the guest only ever POSTs,
// which net/http does not replay in any case.
type requestBody struct {
	mu     sync.Mutex
	buf    []byte
	off    int
	closed bool
}

var errRequestBodyClosed = errors.New("stackencrypt: request body read after close")

// newRequestBody copies src, which the caller does not keep alive.
func newRequestBody(src []byte) *requestBody {
	buf := make([]byte, len(src))
	copy(buf, src)
	return &requestBody{buf: buf}
}

func (b *requestBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return 0, errRequestBodyClosed
	}
	if b.off >= len(b.buf) {
		return 0, io.EOF
	}
	n := copy(p, b.buf[b.off:])
	b.off += n
	return n, nil
}

// Close wipes the body. It is idempotent and never fails.
func (b *requestBody) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.closed {
		wipe(b.buf)
		b.closed = true
	}
	return nil
}

// tokenGet is token_get: hand the guest the current bearer token.
func (t *transport) tokenGet(ctx context.Context, m api.Module, tokenPtrOut, tokenLenOut uint32) int32 {
	token, err := t.token.Token(ctx)
	if err != nil {
		t.tokenErr = err
		return hostFailed
	}
	if token == "" {
		t.tokenErr = errors.New("stackencrypt: the token source returned an empty token")
		return hostFailed
	}
	// The credential's transport copy is wiped once it is in guest memory;
	// the source's own string is the source's.
	tok := []byte(token)
	defer wipe(tok)
	if !place(ctx, m, tokenPtrOut, tokenLenOut, tok) {
		// The source did its part; the guest could not take the token (no
		// allocator, a refused allocation, an out-of-range slot). Say so,
		// or the failure reads as the source's.
		t.tokenErr = errors.New("stackencrypt: the token could not be handed to the guest")
		return hostFailed
	}
	return 0
}

// place allocates a guest buffer through the module's own se_alloc, writes
// data into it, and stores its (ptr, len) into the out-slots. The guest
// reclaims the buffer through its registry. Re-entering the guest through
// se_alloc during a host import is the one re-entry the ABI permits.
func place(ctx context.Context, m api.Module, ptrOut, lenOut uint32, data []byte) bool {
	alloc := m.ExportedFunction("se_alloc")
	if alloc == nil {
		return false
	}
	if uint64(len(data)) > math.MaxUint32 {
		return false
	}
	res, err := alloc.Call(ctx, uint64(len(data)))
	if err != nil {
		return false
	}
	ptr := api.DecodeU32(res[0])
	if ptr == 0 {
		return false
	}
	mem := m.Memory()
	if len(data) > 0 && !mem.Write(ptr, data) {
		return false
	}
	return mem.WriteUint32Le(ptrOut, ptr) && mem.WriteUint32Le(lenOut, uint32(len(data))) //nolint:gosec // bounded above
}

// parseHeaders decodes the guest's `name: value` line format. Malformed
// lines are skipped, as the guest skips them in the other direction.
func parseHeaders(buf []byte) http.Header {
	h := http.Header{}
	for _, line := range strings.Split(string(buf), "\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		h.Add(strings.TrimSpace(name), strings.TrimSpace(value))
	}
	return h
}

// encodeHeaders renders response headers in the guest's line format, in
// a deterministic order, one line per value.
func encodeHeaders(h http.Header) []byte {
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
			out.WriteString(name)
			out.WriteString(": ")
			out.WriteString(value)
		}
	}
	return []byte(out.String())
}
