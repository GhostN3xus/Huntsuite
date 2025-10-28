package validator

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"huntsuite/pkg/oob"
	"huntsuite/pkg/report"
)

type Finding struct {
	ID         int64   `json:"id"`
	Target     string  `json:"target"`
	Path       string  `json:"path"`
	Type       string  `json:"type"`
	Time       string  `json:"time"`
	Proof      string  `json:"proof"`
	Confidence float64 `json:"confidence"`
}

type Storage struct {
	path   string
	mu     sync.Mutex
	lastID int64
}

func InitDB(path string) (*Storage, error) {
	if path == "" {
		path = "huntsuite_findings.json"
	}

	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}

	store := &Storage{path: path}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		if err := os.WriteFile(path, []byte("[]"), 0o600); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	} else if len(data) > 0 {
		var existing []Finding
		if err := json.Unmarshal(data, &existing); err == nil {
			for _, f := range existing {
				if f.ID > store.lastID {
					store.lastID = f.ID
				}
			}
		}
	}

	return store, nil
}

func SaveFinding(store *Storage, f Finding) (int64, error) {
	store.mu.Lock()
	defer store.mu.Unlock()

	data, err := os.ReadFile(store.path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return 0, err
	}

	var existing []Finding
	if len(data) > 0 {
		if err := json.Unmarshal(data, &existing); err != nil {
			return 0, err
		}
	}

	store.lastID++
	f.ID = store.lastID
	existing = append(existing, f)

	out, err := json.MarshalIndent(existing, "", "  ")
	if err != nil {
		return 0, err
	}
	if err := os.WriteFile(store.path, out, 0o600); err != nil {
		return 0, err
	}

	return f.ID, nil
}

func ProbeSSRF(store *Storage, target string, param string) (*Finding, error) {
	d, _ := oob.ExecInteractWithTimeout(5 * time.Second)
	if d == "" {
		client, _ := oob.NewInteractClient()
		d = client.Domain
	}
	token := fmt.Sprintf("ssrf-%d", time.Now().UnixNano())
	oobURL := fmt.Sprintf("http://%s/%s", d, token)

	probe := fmt.Sprintf("%s?%s=%s", target, param, oobURL)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(probe)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()

	f := Finding{
		Target:     target,
		Path:       param,
		Type:       "ssrf-oob",
		Time:       time.Now().Format(time.RFC3339),
		Proof:      oobURL,
		Confidence: 0.5,
	}
	id, err := SaveFinding(store, f)
	if err == nil {
		f.ID = id
	}
	report.WriteJSONReport("validated_findings", f)
	return &f, nil
}
