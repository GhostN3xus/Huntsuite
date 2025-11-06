
package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDefaultConfig(t *testing.T) {
	cfg, _, err := Load("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.General.Proxy != "" {
		t.Errorf("expected default proxy to be empty, got %s", cfg.General.Proxy)
	}
	if cfg.Scanning.Threads != 4 {
		t.Errorf("expected default threads to be 4, got %d", cfg.Scanning.Threads)
	}
}

func TestLoadCustomConfig(t *testing.T) {
	dir, err := os.MkdirTemp("", "huntsuite-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	path := filepath.Join(dir, "config.yaml")
	content := []byte(`
general:
  proxy: http://localhost:8080
scanning:
  threads: 100
`)
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}

	cfg, _, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.General.Proxy != "http://localhost:8080" {
		t.Errorf("expected proxy to be http://localhost:8080, got %s", cfg.General.Proxy)
	}
	if cfg.Scanning.Threads != 100 {
		t.Errorf("expected threads to be 100, got %d", cfg.Scanning.Threads)
	}
}
