package disclosure

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestProbeHighValuePaths(t *testing.T) {
	var mu sync.Mutex
	hits := make(map[string]int)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.Path]++
		count := hits[r.URL.Path]
		mu.Unlock()
		if r.Header.Get("User-Agent") != "huntsuite/1.0" {
			t.Errorf("unexpected user agent: %s", r.Header.Get("User-Agent"))
		}
		switch r.URL.Path {
		case "/.env":
			if count == 1 {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("PASSWORD=secret"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	findings := Probe(server.URL, 8)
	if len(findings) == 0 {
		t.Fatalf("expected findings, got none")
	}
	var found bool
	for _, f := range findings {
		if f.Path == "/.env" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected to capture /.env disclosure")
	}
	if hits["/.env"] < 2 {
		t.Fatalf("expected retries for /.env, got %d", hits["/.env"])
	}
}
