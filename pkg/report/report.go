package report

import (
    "os"
    "path/filepath"
    "huntsuite/pkg/notify"
    "encoding/json"
    "log"
    "time"
)

func WriteJSONReport(prefix string, data interface{}) string {
    os.MkdirAll("reports", 0o755)
    fname := filepath.Join("reports", prefix+"-"+time.Now().Format("20060102-150405")+".json")
    f, err := os.Create(fname)
    if err != nil {
        log.Printf("[report] create error: %v", err)
        return ""
    }
    defer f.Close()
    enc := json.NewEncoder(f)
    enc.SetIndent("", "  ")
    enc.Encode(data)
    log.Printf("[report] wrote %s", fname)
    // attempt auto-notify via Telegram if env vars set
    go func() {
        // short summary
        summary := "Report generated: " + fname
        // best-effort: absolute path
        abs, _ := filepath.Abs(fname)
        notify.AutoNotify(abs, summary)
    }()
    return fname
}
