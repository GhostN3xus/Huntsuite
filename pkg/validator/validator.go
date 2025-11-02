package validator

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/GhostN3xus/Huntsuite/pkg/oob"
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

var interactFactory = func() (*oob.InteractClient, error) {
	return oob.NewInteractClient()
}

// SetInteractClientFactory allows tests to override the Interactsh client factory.
func SetInteractClientFactory(factory func() (*oob.InteractClient, error)) {
	if factory == nil {
		interactFactory = func() (*oob.InteractClient, error) { return oob.NewInteractClient() }
		return
	}
	interactFactory = factory
}

func InitDB(path string) (*Storage, error) {
	resolved, err := resolvePath(path)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(resolved), 0o755); err != nil {
		return nil, err
	}
	store := &Storage{path: resolved}
	if err := store.bootstrap(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *Storage) bootstrap() error {
	file, err := os.OpenFile(s.path, os.O_CREATE|os.O_RDONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var entry Finding
		if err := json.Unmarshal(scanner.Bytes(), &entry); err == nil {
			if entry.ID > s.lastID {
				s.lastID = entry.ID
			}
		}
	}
	return scanner.Err()
}

func resolvePath(path string) (string, error) {
	if strings.TrimSpace(path) != "" {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".huntsuite")
	return filepath.Join(dir, "findings.json"), nil
}

func SaveFinding(store *Storage, f Finding) (int64, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.lastID++
	f.ID = store.lastID
	if f.Time == "" {
		f.Time = time.Now().Format(time.RFC3339)
	}
	data, err := json.Marshal(f)
	if err != nil {
		return 0, err
	}
	fh, err := os.OpenFile(store.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, err
	}
	defer fh.Close()
	if _, err := fh.Write(append(data, '\n')); err != nil {
		return 0, err
	}
	return f.ID, nil
}

func ProbeSSRF(store *Storage, target string, param string) (*Finding, error) {
	if store == nil {
		return nil, errors.New("nil storage")
	}
	ic, err := interactFactory()
	if err != nil {
		return nil, err
	}
	token := ic.GenerateToken("ssrf")
	oobURL := ic.URLForToken(token)
	requestURL, err := injectParameter(target, param, oobURL)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "huntsuite/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	interactions, _ := ic.WaitForToken(ctx, token, 1)
	findings, _ := ProcessInteractions(store, target, interactions)
	if len(findings) > 0 {
		latest := findings[len(findings)-1]
		return &latest, nil
	}

	f := Finding{
		Target:     target,
		Path:       param,
		Type:       "ssrf-oob",
		Proof:      oobURL,
		Confidence: 0.3,
		Time:       time.Now().Format(time.RFC3339),
	}
	id, err := SaveFinding(store, f)
	if err != nil {
		return nil, err
	}
	f.ID = id
	return &f, nil
}

// ProcessInteractions inspects interactions and records findings for supported payloads.
func ProcessInteractions(store *Storage, target string, interactions []oob.Interaction) ([]Finding, error) {
	if len(interactions) == 0 {
		return nil, nil
	}
	created := make([]Finding, 0)
	seen := map[string]struct{}{}
	for _, interaction := range interactions {
		token := extractToken(interaction.FullID)
		if token == "" {
			continue
		}
		if _, ok := seen[token]; ok {
			continue
		}
		seen[token] = struct{}{}
		findingType, confidence := classifyToken(token)
		if findingType == "" {
			continue
		}
		finding := Finding{
			Target:     target,
			Path:       token,
			Type:       findingType,
			Proof:      selectProof(interaction),
			Confidence: confidence,
			Time:       time.Now().Format(time.RFC3339),
		}
		id, err := SaveFinding(store, finding)
		if err != nil {
			return created, err
		}
		finding.ID = id
		created = append(created, finding)
	}
	return created, nil
}

func extractToken(fullID string) string {
	parts := strings.Split(fullID, ".")
	if len(parts) == 0 {
		return strings.TrimSpace(fullID)
	}
	return strings.TrimSpace(parts[0])
}

func classifyToken(token string) (string, float64) {
	switch {
	case strings.HasPrefix(token, "ssrf-"):
		return "ssrf-confirmed", 1.0
	case strings.HasPrefix(token, "bxss-"):
		return "blind-xss", 1.0
	case strings.HasPrefix(token, "log4j-"):
		return "log4shell", 1.0
	default:
		return "", 0
	}
}

func selectProof(interaction oob.Interaction) string {
	if interaction.RawRequest != "" {
		return interaction.RawRequest
	}
	if interaction.RawResponse != "" {
		return interaction.RawResponse
	}
	return interaction.FullID
}

func injectParameter(target, param, value string) (string, error) {
	if strings.TrimSpace(param) == "" {
		return "", errors.New("parameter name required")
	}
	parsed, err := url.Parse(target)
	if err != nil {
		return "", err
	}
	query := parsed.Query()
	query.Set(param, value)
	parsed.RawQuery = query.Encode()
	if parsed.Scheme == "" {
		parsed.Scheme = "https"
	}
	return parsed.String(), nil
}
