package mimic

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
)

// wireRoundTripper performs HTTP/1.1 requests over the profile's own TLS
// connection and writes the request bytes by hand.
//
// Why: Go's net/http canonicalizes header names and re-sorts them, so the
// header block on the wire never matches the client being imitated — a
// difference some edges fingerprint. Writing the block ourselves reproduces
// the captured order, including the original casing (undici sends lowercase
// names for SDK-set headers and keeps the case of object-literal ones).
//
// Scope: HTTP/1.1 only, one connection per request (no keep-alive pooling),
// no chunked request bodies, no HTTP/2. That matches how the imitated
// clients (Node/undici-based) behave for a single request.
type wireRoundTripper struct {
	// dial opens the already-handshaked TLS connection.
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// order is the captured wire order of the header names.
	order []string
}

// RoundTrip implements http.RoundTripper.
func (rt *wireRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" {
		return nil, fmt.Errorf("mimic: wire order transport supports https only")
	}
	body, err := drainBody(req)
	if err != nil {
		return nil, err
	}
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	addr := req.URL.Host
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "443")
	}

	ctx := req.Context()
	conn, err := rt.dial(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	path := req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	if req.URL.RawQuery != "" {
		path += "?" + req.URL.RawQuery
	}
	fmt.Fprintf(&buf, "%s %s HTTP/1.1\r\n", req.Method, path)
	// The host header comes first, exactly like undici writes it.
	fmt.Fprintf(&buf, "host: %s\r\n", host)

	values := lowerHeaderMap(req.Header)
	written := map[string]bool{"host": true}
	for _, name := range rt.order {
		lower := strings.ToLower(name)
		if lower == "host" {
			continue
		}
		if lower == "content-length" {
			fmt.Fprintf(&buf, "%s: %d\r\n", name, len(body))
			written[lower] = true
			continue
		}
		v, ok := values[lower]
		if !ok {
			continue
		}
		fmt.Fprintf(&buf, "%s: %s\r\n", name, v)
		written[lower] = true
	}
	// Anything the caller added that the capture did not list still goes out,
	// appended in Go's canonical order.
	for name, vals := range req.Header {
		if written[strings.ToLower(name)] || len(vals) == 0 {
			continue
		}
		for _, v := range vals {
			fmt.Fprintf(&buf, "%s: %s\r\n", name, v)
		}
	}
	buf.WriteString("\r\n")
	buf.Write(body)

	if _, err := conn.Write(buf.Bytes()); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("mimic: wire write: %w", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("mimic: wire read response: %w", err)
	}
	resp.Body = &wireBody{ReadCloser: resp.Body, conn: conn}
	return decodeWireResponse(resp), nil
}

// wireBody closes the TLS connection with the response body, and decodes the
// content encodings the imitated client accepts transparently.
type wireBody struct {
	io.ReadCloser
	conn net.Conn
}

func (b *wireBody) Close() error {
	err := b.ReadCloser.Close()
	if b.conn != nil {
		_ = b.conn.Close()
	}
	return err
}

// drainBody reads the request body into memory. The wire transport sends
// plain bodies with an explicit Content-Length.
func drainBody(req *http.Request) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}
	defer req.Body.Close()
	data, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, fmt.Errorf("mimic: read request body: %w", err)
	}
	return data, nil
}

// lowerHeaderMap indexes header values by lowercase name.
func lowerHeaderMap(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for name, vals := range h {
		if len(vals) == 0 {
			continue
		}
		out[strings.ToLower(name)] = vals[0]
	}
	return out
}

// decodeWireResponse wraps a response body in the matching decompressor when
// the server answered with a content encoding the profile accepts.
func decodeWireResponse(resp *http.Response) *http.Response {
	enc := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))
	switch enc {
	case "gzip":
		if r, err := gzip.NewReader(resp.Body); err == nil {
			resp.Body = &wireBody{ReadCloser: readCloser{Reader: r, closer: resp.Body}}
		}
	case "deflate":
		if r := flate.NewReader(resp.Body); r != nil {
			resp.Body = &wireBody{ReadCloser: readCloser{Reader: r, closer: resp.Body}}
		}
	}
	return resp
}

type readCloser struct {
	io.Reader
	closer io.Closer
}

func (r readCloser) Close() error { return r.closer.Close() }
