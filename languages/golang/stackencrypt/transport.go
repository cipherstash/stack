package stackencrypt

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// transportModule is the name of the guest's one import module. Its two
// functions are the whole host surface the guest can reach.
const transportModule = "cipherstash_transport"

// TokenSource supplies the bearer token the guest presents to ZeroKMS. It
// is asked on every request, so a source that rotates tokens needs no
// re-initialisation of the client. Minting and refresh stay host-side; a
// future token strategy running inside the guest is an additive change to
// [Config], not to this interface.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// TokenFunc adapts a function to a [TokenSource].
type TokenFunc func(ctx context.Context) (string, error)

// Token implements TokenSource.
func (f TokenFunc) Token(ctx context.Context) (string, error) { return f(ctx) }

// StaticToken is a [TokenSource] that always returns the same token.
func StaticToken(token string) TokenSource {
	return TokenFunc(func(context.Context) (string, error) { return token, nil })
}

// transport implements the guest's two host imports over a RoundTripper
// and a TokenSource. One per Client; it is bound to the module at
// instantiation and reaches the guest's allocator through the module the
// call arrives on.
type transport struct {
	rt    http.RoundTripper
	token TokenSource
	// sends counts transport_send excursions, so tests can pin the batching
	// contract (one ZeroKMS call per operation) instead of trusting it.
	sends atomic.Int64
}

// transportFailed is the return value of transport_send when the request
// could not be performed at all; the body then carries the error text.
const transportFailed int32 = -1

// hostFailed is the return value of token_get when no token is available.
const hostFailed int32 = 1

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
	// RoundTripper may read it after this function has.
	reqBody := make([]byte, len(body))
	copy(reqBody, body)
	req, err := http.NewRequestWithContext(ctx, string(method), string(url), bytes.NewReader(reqBody))
	if err != nil {
		return transportFailed, nil, []byte(err.Error())
	}
	req.Header = parseHeaders(headers)
	resp, err := t.rt.RoundTrip(req)
	if err != nil {
		return transportFailed, nil, []byte(err.Error())
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return transportFailed, nil, []byte(err.Error())
	}
	return int32(resp.StatusCode), encodeHeaders(resp.Header), respBody
}

// tokenGet is token_get: hand the guest the current bearer token.
func (t *transport) tokenGet(ctx context.Context, m api.Module, tokenPtrOut, tokenLenOut uint32) int32 {
	token, err := t.token.Token(ctx)
	if err != nil || token == "" {
		return hostFailed
	}
	if !place(ctx, m, tokenPtrOut, tokenLenOut, []byte(token)) {
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
	res, err := alloc.Call(ctx, uint64(len(data)))
	if err != nil {
		return false
	}
	ptr := uint32(res[0])
	if ptr == 0 {
		return false
	}
	mem := m.Memory()
	if len(data) > 0 && !mem.Write(ptr, data) {
		return false
	}
	return mem.WriteUint32Le(ptrOut, ptr) && mem.WriteUint32Le(lenOut, uint32(len(data)))
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
