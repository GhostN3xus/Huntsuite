package oob

import (
    "context"
    "fmt"
    "log"
    "time"
)

type InteractClient struct {
    Domain string
}

func NewInteractClient() (*InteractClient, error) {
    domain := fmt.Sprintf("huntsuite-%d.oob.example.com", time.Now().Unix())
    log.Printf("[oob] created stub domain: %s", domain)
    return &InteractClient{Domain: domain}, nil
}

func (ic *InteractClient) PollInteractions(ctx context.Context) {
    ticker := time.NewTicker(5 * time.Second)
    defer ticker.Stop()
    for {
        select {
        case <-ctx.Done():
            log.Printf("[oob] stopping poll")
            return
        case <-ticker.C:
            log.Printf("[oob] poll: no events (stub)")
        }
    }
}
