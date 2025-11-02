package recon_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/GhostN3xus/Huntsuite/pkg/recon"
)

type mockResolver struct {
	entries map[string][]string
}

func (m *mockResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	if addrs, ok := m.entries[host]; ok {
		return addrs, nil
	}
	return []string{"1.1.1.1"}, nil
}

func TestEnumSubdomainsFiltersWildcard(t *testing.T) {
	tmpDir := t.TempDir()
	wordlistPath := filepath.Join(tmpDir, "subs.txt")
	if err := os.WriteFile(wordlistPath, []byte("admin\nstatic\n"), 0o600); err != nil {
		t.Fatalf("write wordlist: %v", err)
	}
	resolver := &mockResolver{entries: map[string][]string{
		"admin.example.com":  {"1.1.1.1"},
		"static.example.com": {"2.2.2.2"},
	}}

	r := recon.NewSimpleRecon().WithResolver(resolver)
	subs := r.EnumSubdomains("example.com", wordlistPath, 5)
	if len(subs) != 1 || subs[0] != "static.example.com" {
		t.Fatalf("expected static.example.com only, got %v", subs)
	}
}
