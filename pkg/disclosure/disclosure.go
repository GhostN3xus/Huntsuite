package disclosure

import (
    "encoding/json"
    "io"
    "log"
    "net/http"
    "os"
    "path/filepath"
    "strings"
    "time"
)

var commonFiles = []string{
    "/.env",
    "/.git/config",
    "/backup.zip",
    "/config.php",
    "/wp-config.php",
    "/web.config",
    "/.htpasswd",
    "/database.sql",
}

type Finding struct {
    Time string `json:"time"`
    Target string `json:"target"`
    Path string `json:"path"`
    Status int `json:"status"`
    Snippet string `json:"snippet,omitempty"`
}

func WriteReport(outdir string, findings []Finding) {
    os.MkdirAll(outdir, 0o755)
    fname := filepath.Join(outdir, "disclosure-"+time.Now().Format("20060102-150405")+".json")
    f, err := os.Create(fname)
    if err != nil {
        log.Printf("[disclosure] create report error: %v", err)
        return
    }
    defer f.Close()
    enc := json.NewEncoder(f)
    enc.SetIndent("", "  ")
    enc.Encode(findings)
    log.Printf("[disclosure] saved report: %s", fname)
}

func Probe(target string, timeoutSeconds int) []Finding {
    client := &http.Client{Timeout: time.Duration(timeoutSeconds) * time.Second}
    findings := []Finding{}
    if strings.HasPrefix(target, "http") == false {
        target = "http://" + strings.TrimSuffix(target, "/")
    }
    for _, p := range commonFiles {
        url := strings.TrimSuffix(target, "/") + p
        resp, err := client.Get(url)
        if err != nil {
            continue
        }
        body, _ := io.ReadAll(resp.Body)
        resp.Body.Close()
        if resp.StatusCode >= 200 && resp.StatusCode < 300 {
            snippet := string(body)
            if len(snippet) > 500 {
                snippet = snippet[:500]
            }
            f := Finding{
                Time: time.Now().Format(time.RFC3339),
                Target: target,
                Path: p,
                Status: resp.StatusCode,
                Snippet: snippet,
            }
            findings = append(findings, f)
            log.Printf("[disclosure] found %s -> %d", url, resp.StatusCode)
        } else {
            s := strings.ToLower(string(body))
            if strings.Contains(s, "password") || strings.Contains(s, "mysql") {
                f := Finding{
                    Time: time.Now().Format(time.RFC3339),
                    Target: target,
                    Path: p,
                    Status: resp.StatusCode,
                    Snippet: s[:min(len(s), 500)],
                }
                findings = append(findings, f)
                log.Printf("[disclosure] possible leak in %s -> %d", url, resp.StatusCode)
            }
        }
    }
    if len(findings) > 0 {
        WriteReport("reports", findings)
    }
    return findings
}

func min(a,b int) int { if a<b {return a}; return b }
