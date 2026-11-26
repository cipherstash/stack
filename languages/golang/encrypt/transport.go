package encrypt

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/cipherstash/stack/languages/golang/internal/guest"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// transportModule is the name of the guest's one import module. Its one
// function, token_get, is the whole host surface the guest can reach: its
// ZeroKMS requests come back to the host through the step loop (step.go).
const transportModule = "cipherstash_transport"

// tokenSource supplies the bearer token the guest presents to ZeroKMS. It
// is asked once before each operation that can reach ZeroKMS, so a source
// that rotates tokens needs no re-initialisation of the client.
// Outside this package's tests it is always a *auth.Strategy: minting and
// refresh stay host-side, out of the crypto guest, in auth's credential
// guest. The interface is unexported so that no caller can hand the client
// a raw token, which could not be refreshed and would bypass the
// strategies' refresh lock.
type tokenSource interface {
	Token(ctx context.Context) (string, error)
}

// transport performs the guest's ZeroKMS requests over a RoundTripper and
// implements its token_get import over a tokenSource. One per Client.
type transport struct {
	rt    http.RoundTripper
	token tokenSource
	// sends counts the requests performed, so tests can pin the batching
	// contract (one ZeroKMS call per operation) instead of trusting it.
	sends atomic.Int64
	// held is the token fetched for the operation in flight, which
	// token_get hands over, and fetchErr why the source gave none. tokenErr is why
	// token_get failed, when the guest asked: the guest sees only that it
	// failed, so Client.call attaches the cause — ErrNoCredentials, a
	// refused refresh — to the error it returns. All three are set for each
	// step and only touched under the client's lock, which every step
	// holds.
	held     string
	fetchErr error
	tokenErr error
}

// transportFailed is the status of a request that could not be performed
// at all; the body then carries the error text.
const transportFailed int32 = -1

// hostFailed is the return value of token_get when no token is available.
const hostFailed int32 = 1

// maxResponseBytes bounds what perform will buffer from ZeroKMS. The guest
// issues at most one 500-key batch per request, which is well under a
// megabyte either way; the bound exists so that an endpoint the transport
// was pointed at cannot make the host allocate without limit.
const maxResponseBytes = 16 << 20

// instantiate registers the host module in r.
func (t *transport) instantiate(ctx context.Context, r wazero.Runtime) error {
	_, err := r.NewHostModuleBuilder(transportModule).
		NewFunctionBuilder().WithFunc(t.tokenGet).Export("token_get").
		Instantiate(ctx)
	if err != nil {
		return fmt.Errorf("encrypt: instantiating host transport: %w", err)
	}
	return nil
}

// fetchToken asks the token source for the token an operation's steps hand
// the guest. It runs before the first step, outside the client's lock, so a
// refresh that waits on the network holds up no other caller; the steps
// then never wait. A failure is kept for a step to report if the guest
// asks.
func (t *transport) fetchToken(ctx context.Context) (string, error) {
	if t.token == nil {
		return "", nil
	}
	token, err := t.token.Token(ctx)
	if err == nil && token == "" {
		err = errors.New("encrypt: the token source returned an empty token")
	}
	return token, err
}

// perform is one HTTP request on the guest's behalf. It returns the HTTP
// status, the response headers in the guest's line format and the body,
// or transportFailed with the error text as the body. A request that failed
// on the network also returns the net error (guest.NetError), for the
// client to wrap in the error its caller gets: the guest sees only the
// text.
func (t *transport) perform(ctx context.Context, method, url string, headers, body []byte) (int32, []byte, []byte, error) {
	t.sends.Add(1)
	// The request body may carry key-material contexts. The RoundTripper
	// reads copies of it (replaySource), never the caller's slice, because
	// the caller wipes that when the step ends and the RoundTripper may go
	// on reading after RoundTrip has returned. Each copy is wiped when it is
	// closed. When this function returns, the copies the transport can no
	// longer send are closed too (replaySource.end).
	replay := &replaySource{body: body}
	answered := false
	defer func() { replay.end(answered) }()
	req, err := http.NewRequestWithContext(ctx, method, url, replay.first())
	if err != nil {
		return transportFailed, nil, []byte(err.Error()), nil
	}
	// NewRequest only infers a length from the readers it knows; without
	// one the transport would send the body chunked.
	req.ContentLength = int64(len(body))
	req.GetBody = replay.open
	req.Header = parseHeaders(headers)
	resp, err := t.rt.RoundTrip(req)
	replay.stop()
	if err != nil {
		return transportFailed, nil, []byte(err.Error()), guest.NetError(err)
	}
	answered = true
	defer resp.Body.Close()
	// A caller's RoundTripper can return any int; the guest gets an i32.
	if resp.StatusCode < 100 || resp.StatusCode > 999 {
		return transportFailed, nil, fmt.Appendf(nil, "invalid HTTP status %d", resp.StatusCode), nil
	}
	if resp.ContentLength > maxResponseBytes {
		return transportFailed, nil, fmt.Appendf(nil, "response of %d bytes exceeds the %d-byte limit", resp.ContentLength, maxResponseBytes), nil
	}
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		// ReadAll hands back what it managed to read alongside the error.
		// Those bytes are a partial ZeroKMS response and can carry wrapped
		// key material, so they are wiped rather than dropped on the floor
		// for the collector — the same discipline as the over-limit branch
		// below.
		wipe(respBody)
		return transportFailed, nil, []byte(err.Error()), guest.NetError(err)
	}
	if len(respBody) > maxResponseBytes {
		wipe(respBody)
		return transportFailed, nil, fmt.Appendf(nil, "response exceeds the %d-byte limit", maxResponseBytes), nil
	}
	return int32(resp.StatusCode), encodeHeaders(resp.Header), respBody, nil //nolint:gosec // range-checked above
}

// requestBody is the io.ReadCloser a guest request goes out as: one copy of
// the body, which it wipes on Close. RoundTrip must close the body, but may
// do so in another goroutine after it has returned, so Read and Close are
// serialised, and a Close before the send is complete fails the read
// rather than sending zeros in place of the request. A copy the transport
// does not close is closed when the request ends (replaySource).
type requestBody struct {
	mu     sync.Mutex
	buf    []byte
	off    int
	closed bool
}

var errRequestBodyClosed = errors.New("encrypt: request body read after close")

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

// replaySource hands out a request's bodies: the first, and one more for
// each call of the request's GetBody, each a copy of its own wiped when it
// is closed. net/http calls GetBody to send a request again on a new
// connection. HTTP/2 does so for any method when the server closes the
// connection with a GOAWAY that says the request was not processed, which
// ZeroKMS does after a fixed number of requests on a connection. Without
// GetBody those requests failed.
//
// A transport can also ask for a copy and drop it unsent: after a GOAWAY,
// HTTP/2 rewinds the request through GetBody, and rewinds it again when the
// connection pool it then asks refuses. So the source keeps every copy it
// handed out, for end to close.
//
// It reads the caller's copy of the body, which stays whole until perform
// returns. perform stops the source as soon as RoundTrip returns, so a
// GetBody after that fails rather than make another copy. The standard
// transports call GetBody only inside RoundTrip.
type replaySource struct {
	mu      sync.Mutex
	body    []byte
	stopped bool
	copies  []*requestBody
}

var errRequestReplayEnded = errors.New("encrypt: request body asked for again after the request ended")

// first is the body the request goes out with.
func (s *replaySource) first() *requestBody {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.copy()
}

// open is the request's GetBody.
func (s *replaySource) open() (io.ReadCloser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return nil, errRequestReplayEnded
	}
	return s.copy(), nil
}

// copy makes a copy and keeps it to close at the end. s.mu is held.
func (s *replaySource) copy() *requestBody {
	b := newRequestBody(s.body)
	s.copies = append(s.copies, b)
	return b
}

// stop lets go of the caller's body: no GetBody reads it after this.
func (s *replaySource) stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopped, s.body = true, nil
}

// end stops the source and closes, so wipes, the copies the transport can
// no longer send. Once the server has answered, that is every copy, sent,
// dropped or never closed. When RoundTrip failed it is every copy but the
// last: a rewind replaces the request's body, so only the last copy can
// still be read, and the transport may go on reading it after RoundTrip
// has returned. That one is wiped when the transport closes it. Closing a
// copy mid-send fails its next read rather than sending zeros, so the wire
// never carries a wiped request.
func (s *replaySource) end(answered bool) {
	s.stop()
	s.mu.Lock()
	defer s.mu.Unlock()
	done := s.copies
	if !answered && len(done) > 0 {
		done = done[:len(done)-1]
	}
	for _, b := range done {
		_ = b.Close()
	}
	s.copies = nil
}

// tokenGet is token_get: hand the guest the token fetched for this step.
// It never waits: the fetch happened before the step (fetchToken).
func (t *transport) tokenGet(ctx context.Context, m api.Module, tokenPtrOut, tokenLenOut uint32) int32 {
	token := t.held
	if token == "" {
		t.tokenErr = t.fetchErr
		if t.tokenErr == nil {
			t.tokenErr = errors.New("encrypt: no token was fetched for this step")
		}
		return hostFailed
	}
	// The credential's transport copy is wiped once it is in guest memory;
	// the source's own string is the source's.
	tok := []byte(token)
	defer wipe(tok)
	if !guest.Place(ctx, m, tokenPtrOut, tokenLenOut, tok) {
		// The source did its part; the guest could not take the token (no
		// allocator, a refused allocation, an out-of-range slot). Say so,
		// or the failure reads as the source's.
		t.tokenErr = errors.New("encrypt: the token could not be handed to the guest")
		return hostFailed
	}
	return 0
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
