package disclosure

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var commonFiles = []string{
	"/.env",
	"/.git/HEAD",
	"/.git/config",
	"/.svn/entries",
	"/.aws/credentials",
	"/.docker/config.json",
	"/.ssh/id_rsa",
	"/.htpasswd",
	"/actuator/env",
	"/actuator/heapdump",
	"/admin/config.php",
	"/api/keys",
	"/backup.zip",
	"/config.json",
	"/config.php",
	"/credentials.json",
	"/database.sql",
	"/debug.php",
	"/git/config",
	"/id_rsa",
	"/internal/config.yml",
	"/keys.json",
	"/local.xml",
	"/manifest.json",
	"/secret.key",
	"/server-status",
	"/settings.py",
	"/system/.env",
	"/terraform.tfstate",
	"/vault/config",
	"/web.config",
	"/wp-config.php",
}

type Finding struct {
	Time    string `json:"time"`
	Target  string `json:"target"`
	Path    string `json:"path"`
	Status  int    `json:"status"`
	Snippet string `json:"snippet,omitempty"`
}

func WriteReport(outdir string, findings []Finding) {
	if len(findings) == 0 {
		return
	}
	if err := os.MkdirAll(outdir, 0o755); err != nil {
		log.Printf("[disclosure] mkdir %s: %v", outdir, err)
		return
	}
	fname := filepath.Join(outdir, "disclosure-"+time.Now().Format("20060102-150405")+".json")
	f, err := os.Create(fname)
	if err != nil {
		log.Printf("[disclosure] create report error: %v", err)
		return
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(findings); err != nil {
		log.Printf("[disclosure] encode report error: %v", err)
		return
	}
	log.Printf("[disclosure] saved report: %s", fname)
}

// Probe sends aggressive probes to high-value disclosure paths using retries and JSON logging.
func Probe(target string, timeoutSeconds int) []Finding {
	base := normaliseTarget(target)
	timeout := 8 * time.Second
	if timeoutSeconds > 0 {
		timeout = time.Duration(timeoutSeconds) * time.Second
	}
	client := &http.Client{Timeout: timeout}
	results := make([]Finding, 0)
	var mu sync.Mutex
	wg := sync.WaitGroup{}
	ctx, cancel := context.WithTimeout(context.Background(), timeout*time.Duration(len(commonFiles)))
	defer cancel()
	jobs := make(chan string)

	workerCount := 8
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range jobs {
				finding, err := probePath(ctx, client, base, path)
				if err != nil || finding == nil {
					continue
				}
				mu.Lock()
				results = append(results, *finding)
				mu.Unlock()
			}
		}()
	}

	for _, path := range commonFiles {
		select {
		case <-ctx.Done():
			break
		case jobs <- path:
		}
	}
	close(jobs)
	wg.Wait()
	WriteReport(reportDirectory(), results)
	return results
}

func probePath(ctx context.Context, client *http.Client, base, path string) (*Finding, error) {
	target := strings.TrimSuffix(base, "/") + path
	backoff := 500 * time.Millisecond
	attempts := 3
	var lastErr error
	for i := 0; i < attempts; i++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "huntsuite/1.0")
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
		} else {
			finding := evaluateResponse(base, path, resp)
			resp.Body.Close()
			if finding != nil {
				return finding, nil
			}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}
		backoff *= 2
	}
	return nil, lastErr
}

func evaluateResponse(base, path string, resp *http.Response) *Finding {
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil
	}
	snippet := string(body)
	if len(snippet) > 512 {
		snippet = snippet[:512]
	}
	lower := strings.ToLower(snippet)
	status := resp.StatusCode
	if status >= 200 && status < 300 {
		log.Printf("[disclosure] %s%s -> %d", base, path, status)
		return &Finding{
			Time:    time.Now().Format(time.RFC3339),
			Target:  base,
			Path:    path,
			Status:  status,
			Snippet: snippet,
		}
	}
	keywords := []string{"password", "secret", "aws_access_key", "mysql", "token", "apikey"}
	for _, keyword := range keywords {
		if strings.Contains(lower, keyword) {
			log.Printf("[disclosure] keyword match %s%s -> %d", base, path, status)
			return &Finding{
				Time:    time.Now().Format(time.RFC3339),
				Target:  base,
				Path:    path,
				Status:  status,
				Snippet: snippet,
			}
		}
	}
	return nil
}

func normaliseTarget(target string) string {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return ""
	}
	if !strings.HasPrefix(trimmed, "http://") && !strings.HasPrefix(trimmed, "https://") {
		trimmed = "https://" + trimmed
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return trimmed
	}
	parsed.Path = ""
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return strings.TrimSuffix(parsed.String(), "/")
}

func reportDirectory() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "reports"
	}
	dir := filepath.Join(home, ".huntsuite")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "reports"
	}
	return dir
}
