package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

type stubRoundTripper func(*http.Request) (*http.Response, error)

func (fn stubRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

type notifyingBody struct {
	io.Reader
	once   sync.Once
	closed chan struct{}
}

func (b *notifyingBody) Close() error {
	b.once.Do(func() { close(b.closed) })
	return nil
}

func testForwardRequest(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "https://example.invalid/forward", strings.NewReader("hello"))
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func TestAwaitResponseHeadersKeepsStreamingBodyOpen(t *testing.T) {
	body := &notifyingBody{Reader: strings.NewReader("stream survives header timeout"), closed: make(chan struct{})}
	client := &http.Client{Transport: stubRoundTripper(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: body, Header: make(http.Header)}, nil
	})}
	resp, cancel, err := awaitResponseHeaders(context.Background(), client, testForwardRequest(t), 10*time.Millisecond)
	if err != nil {
		t.Fatalf("headers: %v", err)
	}
	defer cancel()
	// Header deadline must not become a deadline on the already received stream.
	time.Sleep(20 * time.Millisecond)
	payload, err := io.ReadAll(resp.Body)
	if err != nil || string(payload) != "stream survives header timeout" {
		t.Fatalf("stream: %q, %v", payload, err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-body.closed:
	default:
		t.Fatal("streaming body not closed")
	}
}

func TestAwaitResponseHeadersTimeoutCancelsAndClosesLateBody(t *testing.T) {
	release := make(chan struct{})
	seenCtx := make(chan context.Context, 1)
	body := &notifyingBody{Reader: strings.NewReader("late"), closed: make(chan struct{})}
	client := &http.Client{Transport: stubRoundTripper(func(req *http.Request) (*http.Response, error) {
		seenCtx <- req.Context()
		<-release // Deliberately ignores cancellation to simulate a late reply.
		return &http.Response{StatusCode: http.StatusOK, Body: body, Header: make(http.Header)}, nil
	})}
	resp, cancel, err := awaitResponseHeaders(context.Background(), client, testForwardRequest(t), 10*time.Millisecond)
	if !errors.Is(err, errUpstreamHeaderTimeout) || resp != nil || cancel != nil {
		t.Fatalf("expected timeout, got response=%v cancel=%v error=%v", resp != nil, cancel != nil, err)
	}
	var reqCtx context.Context
	select {
	case reqCtx = <-seenCtx:
	case <-time.After(time.Second):
		t.Fatal("upstream was not called")
	}
	select {
	case <-reqCtx.Done():
	default:
		t.Fatal("timed-out upstream was not cancelled")
	}
	close(release)
	select {
	case <-body.closed:
	case <-time.After(time.Second):
		t.Fatal("late response body was not closed")
	}
}

func TestAwaitResponseHeadersParentCancellation(t *testing.T) {
	started := make(chan struct{})
	finished := make(chan struct{})
	client := &http.Client{Transport: stubRoundTripper(func(req *http.Request) (*http.Response, error) {
		close(started)
		<-req.Context().Done()
		defer close(finished)
		return nil, req.Context().Err()
	})}
	ctx, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()
	go func() {
		<-started
		cancelParent()
	}()
	resp, cancel, err := awaitResponseHeaders(ctx, client, testForwardRequest(t), time.Second)
	if !errors.Is(err, context.Canceled) || resp != nil || cancel != nil {
		t.Fatalf("expected cancellation, got response=%v cancel=%v error=%v", resp != nil, cancel != nil, err)
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("cancelled request worker did not finish")
	}
}

func TestAwaitResponseHeadersPropagatesUpstreamError(t *testing.T) {
	want := errors.New("upstream failed")
	client := &http.Client{Transport: stubRoundTripper(func(req *http.Request) (*http.Response, error) {
		return nil, want
	})}
	resp, cancel, err := awaitResponseHeaders(context.Background(), client, testForwardRequest(t), time.Second)
	if !errors.Is(err, want) || resp != nil || cancel != nil {
		t.Fatalf("expected upstream error, got response=%v cancel=%v error=%v", resp != nil, cancel != nil, err)
	}
}
