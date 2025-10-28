package oob

import (
    "context"
    "log"
    "os/exec"
    "strings"
    "time"
)

func ExecInteract(ctx context.Context) (string, error) {
    bins := []string{"interactsh-client", "interactsh"}
    var b string
    for _, cand := range bins {
        if path, err := exec.LookPath(cand); err == nil {
            b = path
            break
        }
    }
    if b == "" {
        return "", nil
    }
    cmd := exec.CommandContext(ctx, b, "-silent")
    out, err := cmd.Output()
    if err != nil {
        log.Printf("[oob] interact exec error: %v", err)
        return "", err
    }
    s := strings.TrimSpace(string(out))
    lines := strings.Split(s, "\n")
    if len(lines) > 0 {
        return strings.TrimSpace(lines[0]), nil
    }
    return s, nil
}

func ExecInteractWithTimeout(timeout time.Duration) (string, error) {
    ctx, cancel := context.WithTimeout(context.Background(), timeout)
    defer cancel()
    return ExecInteract(ctx)
}
