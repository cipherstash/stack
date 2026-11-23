package encrypt

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// A step's requests are performed at the same time, and their responses
// come back in the order of the requests, not the order they finished.
func TestAStepsRequestsArePerformedAtTheSameTime(t *testing.T) {
	paths := []string{"/a", "/b", "/c"}
	var arrived sync.WaitGroup
	arrived.Add(len(paths))
	all := make(chan struct{})
	go func() { arrived.Wait(); close(all) }()
	// The first request finishes last.
	delay := map[string]time.Duration{"/a": 40 * time.Millisecond, "/b": 20 * time.Millisecond, "/c": 0}
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		arrived.Done()
		select {
		case <-all:
		case <-time.After(10 * time.Second):
			return nil, errors.New("the other requests never arrived: the step's requests ran one at a time")
		}
		time.Sleep(delay[r.URL.Path])
		return okResponse(r.URL.Path), nil
	})
	tr := &transport{rt: rt, token: staticToken("t")}

	encoded, err := tr.performStep(context.Background(), &ioStep{requests: requestsTo(paths...)})
	if err != nil {
		t.Fatal(err)
	}
	if got := responseBodies(t, encoded); !equalStrings(got, paths) {
		t.Fatalf("responses %q, want them in the requests' order %q", got, paths)
	}
}

// However many requests a step holds, at most maxParallelRequests run at
// once, and every one is answered.
func TestAStepPerformsAtMostMaxParallelRequestsAtOnce(t *testing.T) {
	var running, most atomic.Int64
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		now := running.Add(1)
		defer running.Add(-1)
		for {
			m := most.Load()
			if now <= m || most.CompareAndSwap(m, now) {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
		return okResponse(r.URL.Path), nil
	})
	tr := &transport{rt: rt, token: staticToken("t")}
	paths := make([]string, 3*maxParallelRequests)
	for i := range paths {
		paths[i] = "/" + strings.Repeat("k", i+1)
	}

	encoded, err := tr.performStep(context.Background(), &ioStep{requests: requestsTo(paths...)})
	if err != nil {
		t.Fatal(err)
	}
	if got := responseBodies(t, encoded); !equalStrings(got, paths) {
		t.Fatalf("responses %q, want %q", got, paths)
	}
	if m := most.Load(); m > maxParallelRequests || m < 2 {
		t.Fatalf("%d requests ran at once, want between 2 and %d", m, maxParallelRequests)
	}
}

func requestsTo(paths ...string) []ioRequest {
	reqs := make([]ioRequest, len(paths))
	for i, p := range paths {
		reqs[i] = ioRequest{method: "POST", url: "https://zerokms.example" + p, headers: []byte("authorization: Bearer t"), body: []byte("{}")}
	}
	return reqs
}

func okResponse(body string) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body))}
}

// responseBodies decodes performStep's encoding and returns each response's
// body, in order.
func responseBodies(t *testing.T, encoded []byte) []string {
	t.Helper()
	decoded, err := vcffi.Unmarshal(encoded)
	if err != nil {
		t.Fatal(err)
	}
	list, ok := decoded.([]any)
	if !ok {
		t.Fatalf("decoded %T, want a list", decoded)
	}
	bodies := make([]string, len(list))
	for i, item := range list {
		obj, ok := item.(vcvalue.Object)
		if !ok {
			t.Fatalf("response %d is %T, want an object", i, item)
		}
		for _, f := range obj {
			if f.Key == "body" {
				b, ok := f.Value.([]byte)
				if !ok {
					t.Fatalf("response %d's body is %T, want bytes", i, f.Value)
				}
				bodies[i] = string(b)
			}
		}
	}
	return bodies
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
