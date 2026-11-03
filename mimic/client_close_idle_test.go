package mimic

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type closeIdleStubTransport struct {
	closed bool
}

func (s *closeIdleStubTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("not used")
}

func (s *closeIdleStubTransport) CloseIdleConnections() {
	s.closed = true
}

func TestRoundTripperCloseIdleConnectionsForwardsToH2(t *testing.T) {
	h2 := &closeIdleStubTransport{}
	client := &http.Client{Transport: &roundTripper{
		h1: &http.Transport{},
		h2: h2,
	}}
	client.CloseIdleConnections()
	if !h2.closed {
		t.Fatal("HTTP/2 transport did not receive CloseIdleConnections")
	}
}

func TestRoundTripperCloseIdleConnectionsClosesH1Socket(t *testing.T) {
	closed := make(chan struct{}, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			select {
			case closed <- struct{}{}:
			default:
			}
		}
	}
	server.Start()
	defer server.Close()

	client := &http.Client{Transport: &roundTripper{
		h1: &http.Transport{},
		h2: &closeIdleStubTransport{},
	}}
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatal(err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	client.CloseIdleConnections()

	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("HTTP/1.1 idle socket remained open")
	}
}
