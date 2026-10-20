package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestClientForKeepsTheTimeoutPerRequest guards the cache key of the pooled
// client. The key was (profile, proxy, resolve) and the timeout was applied
// once, at client creation, so the first request decided the timeout of every
// later one: a request that asked for ten seconds was cut off after the one
// second an earlier request had asked for.
//
// The daemon's contract calls timeout_s a per-request parameter.
func TestClientForKeepsTheTimeoutPerRequest(t *testing.T) {
	dir := t.TempDir()
	profilePath := filepath.Join(dir, "profile.json")
	const profile = `{"name":"test","tls_client_hello":"chrome_auto","user_agent":"Test/1.0"}`
	if err := os.WriteFile(profilePath, []byte(profile), 0o644); err != nil {
		t.Fatalf("write the profile: %v", err)
	}

	short, err := clientFor(fetchRequest{Profile: profilePath, TimeoutS: 1})
	if err != nil {
		t.Fatalf("clientFor(1s): %v", err)
	}
	long, err := clientFor(fetchRequest{Profile: profilePath, TimeoutS: 10})
	if err != nil {
		t.Fatalf("clientFor(10s): %v", err)
	}
	if short == long {
		t.Fatal("the client was pooled across different timeouts: the first request would decide the timeout of the rest")
	}
	if got, want := long.Timeout, 10*time.Second; got != want {
		t.Errorf("the second client's timeout = %s, want %s", got, want)
	}
	// The same timeout must still reuse the client: the pool is the point.
	again, err := clientFor(fetchRequest{Profile: profilePath, TimeoutS: 10})
	if err != nil {
		t.Fatalf("clientFor(10s) again: %v", err)
	}
	if again != long {
		t.Error("the client was not pooled for the same timeout")
	}
}
