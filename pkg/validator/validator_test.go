package validator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/GhostN3xus/Huntsuite/pkg/oob"
)

func TestProbeSSRFUsesOOBAndStoresFinding(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := InitDB(filepath.Join(tmpDir, "findings.json"))
	if err != nil {
		t.Fatalf("init db: %v", err)
	}

	var received string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = r.URL.Query().Get("huntsuite")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ic := &oob.InteractClient{Domain: "oob.test"}
	ic.SetTokenGenerator(func(prefix string) string { return prefix + "-token" })
	var provided int32
	ic.SetFetcher(func(ctx context.Context) ([]oob.Interaction, error) {
		if atomic.LoadInt32(&provided) == 1 {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		atomic.StoreInt32(&provided, 1)
		return []oob.Interaction{{
			FullID:     "ssrf-token.oob.test",
			RawRequest: "GET /callback HTTP/1.1",
		}}, nil
	})
	SetInteractClientFactory(func() (*oob.InteractClient, error) { return ic, nil })
	defer SetInteractClientFactory(nil)

	finding, err := ProbeSSRF(store, server.URL, "huntsuite")
	if err != nil {
		t.Fatalf("probe ssrf: %v", err)
	}
	if finding.Type != "ssrf-confirmed" {
		t.Fatalf("expected ssrf-confirmed, got %s", finding.Type)
	}
	if !strings.Contains(received, "ssrf-token.oob.test") {
		t.Fatalf("expected SSRF payload in request, got %s", received)
	}
	data, err := os.ReadFile(filepath.Join(tmpDir, "findings.json"))
	if err != nil {
		t.Fatalf("read findings: %v", err)
	}
	if len(data) == 0 {
		t.Fatalf("expected findings persisted")
	}
}

func TestProcessInteractionsClassifiesTokens(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := InitDB(filepath.Join(tmpDir, "findings.json"))
	if err != nil {
		t.Fatalf("init db: %v", err)
	}
	interactions := []oob.Interaction{{
		FullID:     "bxss-demo.oob.test",
		RawRequest: "GET / HTTP/1.1",
	}}
	created, err := ProcessInteractions(store, "https://example.com", interactions)
	if err != nil {
		t.Fatalf("process interactions: %v", err)
	}
	if len(created) != 1 || created[0].Type != "blind-xss" {
		t.Fatalf("unexpected findings %+v", created)
	}
}
