package stackauth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/cipherstash/cipherstash-suite/bindings/go/internal/guest"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// OIDCProvider supplies the current identity-provider JWT. The Rust
// federation strategy asks only when its cached CTS token needs renewal.
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

func (f OIDCProviderFunc) Token(ctx context.Context) (string, error) { return f(ctx) }

const maxAuthResponseBytes = 16 << 20

type authTransport struct {
	rt           http.RoundTripper
	mu           sync.Mutex
	providers    map[uint32]OIDCProvider
	nextProvider uint32
}

func newAuthTransport(rt http.RoundTripper) *authTransport {
	if rt == nil {
		rt = http.DefaultTransport
	}
	return &authTransport{rt: rt, providers: make(map[uint32]OIDCProvider)}
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

func (t *authTransport) instantiate(ctx context.Context, r wazero.Runtime) error {
	_, err := r.NewHostModuleBuilder("cipherstash_transport").
		NewFunctionBuilder().WithFunc(t.send).Export("transport_send").
		NewFunctionBuilder().WithFunc(t.oidcTokenGet).Export("oidc_token_get").
		Instantiate(ctx)
	return err
}

// send is the same host import contract used by stackencrypt: four input
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
	req, err := http.NewRequestWithContext(ctx, string(method), string(url), requestBody)
	if err != nil {
		_ = requestBody.Close()
		return t.placeResponse(ctx, m, respHeadersPtrOut, respHeadersLenOut, respBodyPtrOut, respBodyLenOut, -1, nil, []byte(err.Error()))
	}
	req.ContentLength = int64(len(body))
	req.Header = parseAuthHeaders(headers)
	resp, err := t.rt.RoundTrip(req)
	if err != nil {
		return t.placeResponse(ctx, m, respHeadersPtrOut, respHeadersLenOut, respBodyPtrOut, respBodyLenOut, -1, nil, []byte(err.Error()))
	}
	defer resp.Body.Close()
	if resp.ContentLength > maxAuthResponseBytes {
		return t.placeResponse(ctx, m, respHeadersPtrOut, respHeadersLenOut, respBodyPtrOut, respBodyLenOut, -1, nil, []byte("auth response exceeds limit"))
	}
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, maxAuthResponseBytes+1))
	if err != nil {
		guest.Wipe(responseBody)
		return t.placeResponse(ctx, m, respHeadersPtrOut, respHeadersLenOut, respBodyPtrOut, respBodyLenOut, -1, nil, []byte(err.Error()))
	}
	defer guest.Wipe(responseBody)
	if len(responseBody) > maxAuthResponseBytes {
		return t.placeResponse(ctx, m, respHeadersPtrOut, respHeadersLenOut, respBodyPtrOut, respBodyLenOut, -1, nil, []byte("auth response exceeds limit"))
	}
	return t.placeResponse(ctx, m, respHeadersPtrOut, respHeadersLenOut, respBodyPtrOut, respBodyLenOut, int32(resp.StatusCode), encodeAuthHeaders(resp.Header), responseBody)
}

func (t *authTransport) placeResponse(ctx context.Context, m api.Module,
	hp, hl, bp, bl uint32, status int32, headers, body []byte,
) int32 {
	if !placeAuth(ctx, m, hp, hl, headers) || !placeAuth(ctx, m, bp, bl, body) {
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
	token, err := source.Token(ctx)
	if err != nil || token == "" || strings.ContainsAny(token, "\r\n\x00") {
		return 1
	}
	bytes := []byte(token)
	defer guest.Wipe(bytes)
	if !placeAuth(ctx, m, ptrOut, lenOut, bytes) {
		return 1
	}
	return 0
}

// The only guest re-entry allowed during a host import is its allocator.
func placeAuth(ctx context.Context, m api.Module, ptrOut, lenOut uint32, data []byte) bool {
	alloc := m.ExportedFunction("se_alloc")
	if alloc == nil {
		return false
	}
	res, err := alloc.Call(ctx, uint64(len(data)))
	if err != nil || len(res) == 0 || res[0] == 0 {
		return false
	}
	ptr := uint32(res[0])
	mem := m.Memory()
	return (len(data) == 0 || mem.Write(ptr, data)) &&
		mem.WriteUint32Le(ptrOut, ptr) && mem.WriteUint32Le(lenOut, uint32(len(data)))
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
