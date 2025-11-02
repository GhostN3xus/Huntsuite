package oob

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	interactclient "github.com/projectdiscovery/interactsh/pkg/client"
)

// Interaction represents an out-of-band event received from Interactsh.
type Interaction struct {
	FullID      string
	UniqueID    string
	Protocol    string
	RawRequest  string
	RawResponse string
	Timestamp   time.Time
}

// InteractClient wraps the Interactsh client and exposes helper utilities for payload generation.
type InteractClient struct {
	Domain       string
	client       *interactclient.Client
	pollInterval time.Duration
	httpClient   *http.Client
	seen         sync.Map
	fetchFunc    func(context.Context) ([]Interaction, error)
	tokenFunc    func(string) string
}

// NewInteractClient registers a new temporary session on the Interactsh server.
func NewInteractClient() (*InteractClient, error) {
	opts := &interactclient.Options{}
	client, err := interactclient.New(opts)
	if err != nil {
		return nil, err
	}
	domain := client.URL()
	if domain == "" {
		return nil, errors.New("interactsh: empty domain returned")
	}
	ic := &InteractClient{
		Domain:       uniqueDomain(domain),
		client:       client,
		pollInterval: 5 * time.Second,
		httpClient:   opts.HTTPClient,
	}
	log.Printf("[oob] interactsh domain: %s", ic.Domain)
	return ic, nil
}

// GenerateToken generates a unique token with the provided prefix.
func (ic *InteractClient) GenerateToken(prefix string) string {
	if ic.tokenFunc != nil {
		return ic.tokenFunc(prefix)
	}
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	token := hex.EncodeToString(b)
	if prefix != "" {
		return fmt.Sprintf("%s-%s", prefix, token)
	}
	return token
}

// URLForToken returns a fully-qualified URL that can be used as payload for SSRF.
func (ic *InteractClient) URLForToken(token string) string {
	return fmt.Sprintf("https://%s.%s", token, ic.Domain)
}

// PollInteractions polls the Interactsh API until the context is done or the maximum number of interactions is reached.
func (ic *InteractClient) PollInteractions(ctx context.Context) {
	_, _ = ic.CollectInteractions(ctx, 100)
}

// CollectInteractions polls for new interactions and returns them.
func (ic *InteractClient) CollectInteractions(ctx context.Context, limit int) ([]Interaction, error) {
	interactions := make([]Interaction, 0)
	for len(interactions) < limit {
		select {
		case <-ctx.Done():
			return interactions, ctx.Err()
		default:
		}
		batch, err := ic.fetch(ctx)
		if err != nil {
			return interactions, err
		}
		for _, item := range batch {
			if _, loaded := ic.seen.LoadOrStore(item.FullID, struct{}{}); loaded {
				continue
			}
			interactions = append(interactions, item)
			log.Printf("[oob] interaction: %s via %s", item.FullID, item.Protocol)
			if len(interactions) >= limit {
				break
			}
		}
		if len(interactions) >= limit {
			break
		}
		select {
		case <-ctx.Done():
			return interactions, ctx.Err()
		case <-time.After(ic.pollInterval):
		}
	}
	return interactions, nil
}

// WaitForToken waits until an interaction containing the token prefix is observed.
func (ic *InteractClient) WaitForToken(ctx context.Context, token string, limit int) ([]Interaction, error) {
	results := make([]Interaction, 0)
	for len(results) < limit {
		batch, err := ic.CollectInteractions(ctx, limit-len(results))
		if err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
			return results, err
		}
		for _, item := range batch {
			if strings.Contains(item.FullID, token) {
				results = append(results, item)
			}
		}
		if len(results) >= limit || errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(ctx.Err(), context.Canceled) {
			break
		}
	}
	return results, ctx.Err()
}

func (ic *InteractClient) fetch(ctx context.Context) ([]Interaction, error) {
	if ic.fetchFunc != nil {
		return ic.fetchFunc(ctx)
	}
	if ic.client == nil {
		return nil, errors.New("interactsh client not initialized")
	}
	raw, err := ic.client.Poll(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Interaction, 0, len(raw))
	for _, item := range raw {
		ts, _ := time.Parse(time.RFC3339Nano, item.Timestamp)
		out = append(out, Interaction{
			FullID:      item.FullID,
			UniqueID:    item.UniqueID,
			Protocol:    item.Protocol,
			RawRequest:  item.RawRequest,
			RawResponse: item.RawResponse,
			Timestamp:   ts,
		})
	}
	return out, nil
}

func uniqueDomain(base string) string {
	parts := strings.Split(base, ".")
	if len(parts) < 2 {
		return fmt.Sprintf("%s.%s", randomLabel(6), base)
	}
	return fmt.Sprintf("%s.%s", randomLabel(6), base)
}

// SetFetcher allows tests to override the poller implementation.
func (ic *InteractClient) SetFetcher(fn func(context.Context) ([]Interaction, error)) {
	ic.fetchFunc = fn
}

// SetTokenGenerator overrides token generation for deterministic testing.
func (ic *InteractClient) SetTokenGenerator(fn func(string) string) {
	ic.tokenFunc = fn
}

func randomLabel(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)[:n]
}
