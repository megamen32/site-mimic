//go:build unix

package mimic

import (
	"context"
	"net"
	"syscall"
	"testing"
	"time"
)

// TestChromeDialerLeavesKeepAliveOff pins Chrome's TCP behaviour.
//
// A connection that sends TCP keep-alive probes is a different client from
// one that never does, and Chrome never sends them. Go's dialer turns them
// on by default (every 15 seconds), so the interval has to be negative to
// turn them off — and the guard is here because the default is invisible
// on the wire until someone looks at the socket options.
func TestChromeDialerLeavesKeepAliveOff(t *testing.T) {
	connection := dialWith(t, chromeDialer(5*time.Second))
	defer connection.Close()

	if keepAlive := socketKeepAlive(t, connection); keepAlive != 0 {
		t.Errorf("SO_KEEPALIVE = %d, want 0; Chrome sends no keep-alive probes", keepAlive)
	}
}

// TestDefaultDialerWouldEnableTheKeepAliveMetronome is the other half of
// the guard: it proves the check above can fail. A test that passes for
// every dialer is not a test.
func TestDefaultDialerWouldEnableTheKeepAliveMetronome(t *testing.T) {
	connection := dialWith(t, &net.Dialer{})
	defer connection.Close()

	if keepAlive := socketKeepAlive(t, connection); keepAlive == 0 {
		t.Fatalf("SO_KEEPALIVE = 0 on a default dialer; the guard above cannot fail then")
	}
}

func dialWith(t *testing.T, dialer *net.Dialer) net.Conn {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		accepted, acceptErr := listener.Accept()
		if acceptErr == nil {
			defer accepted.Close()
			time.Sleep(50 * time.Millisecond)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connection, err := dialer.DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return connection
}

func socketKeepAlive(t *testing.T, connection net.Conn) int {
	t.Helper()

	rawConn, err := connection.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatalf("syscall conn: %v", err)
	}
	keepAlive := -1
	var optErr error
	if err := rawConn.Control(func(descriptor uintptr) {
		keepAlive, optErr = syscall.GetsockoptInt(int(descriptor), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE)
	}); err != nil {
		t.Fatalf("control: %v", err)
	}
	if optErr != nil {
		t.Fatalf("getsockopt SO_KEEPALIVE: %v", optErr)
	}
	return keepAlive
}
