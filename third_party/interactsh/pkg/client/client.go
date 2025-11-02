package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Options struct {
	ServerURL      string
	Secret         string
	CorrelationID  string
	HTTPClient     *http.Client
	RequestTimeout time.Duration
}

type Client struct {
	serverURL     string
	secret        string
	correlationID string
	httpClient    *http.Client
	domain        string
	mu            sync.Mutex
	seen          map[string]struct{}
}

type registerRequest struct {
	Secret        string `json:"secret"`
	CorrelationID string `json:"correlation_id"`
}

type registerResponse struct {
	Domain string `json:"domain"`
}

type pollResponse struct {
	Data []Interaction `json:"data"`
}

type Interaction struct {
	FullID      string `json:"full_id"`
	UniqueID    string `json:"unique_id"`
	Protocol    string `json:"protocol"`
	RawRequest  string `json:"raw_request"`
	RawResponse string `json:"raw_response"`
	Timestamp   string `json:"timestamp"`
}

func New(opts *Options) (*Client, error) {
	if opts == nil {
		opts = &Options{}
	}
	server := strings.TrimRight(opts.ServerURL, "/")
	if server == "" {
		server = "https://interact.sh"
	}
	httpClient := opts.HTTPClient
	if httpClient == nil {
		timeout := opts.RequestTimeout
		if timeout == 0 {
			timeout = 15 * time.Second
		}
		httpClient = &http.Client{Timeout: timeout}
		opts.HTTPClient = httpClient
	}

	secret := opts.Secret
	if secret == "" {
		secret = randomToken()
	}
	corr := opts.CorrelationID
	if corr == "" {
		corr = randomToken()
	}

	c := &Client{
		serverURL:     server,
		secret:        secret,
		correlationID: corr,
		httpClient:    httpClient,
		seen:          map[string]struct{}{},
	}
	if err := c.register(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Client) register() error {
	body, err := json.Marshal(registerRequest{Secret: c.secret, CorrelationID: c.correlationID})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, c.serverURL+"/register", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		// fallback to local fake domain if offline
		c.domain = fmt.Sprintf("%s.oob", c.correlationID)
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var parsed registerResponse
	if err := json.Unmarshal(data, &parsed); err != nil {
		return err
	}
	if parsed.Domain == "" {
		return errors.New("missing domain in response")
	}
	c.domain = parsed.Domain
	return nil
}

func (c *Client) URL() string {
	return c.domain
}

func (c *Client) Secret() string {
	return c.secret
}

func (c *Client) CorrelationID() string {
	return c.correlationID
}

func (c *Client) Poll(ctx context.Context) ([]Interaction, error) {
	endpoint := fmt.Sprintf("%s/poll?secret=%s&correlation_id=%s", c.serverURL, url.QueryEscape(c.secret), url.QueryEscape(c.correlationID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var parsed pollResponse
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, err
	}
	interactions := make([]Interaction, 0, len(parsed.Data))
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, inter := range parsed.Data {
		if inter.FullID == "" {
			inter.FullID = inter.UniqueID
		}
		if _, ok := c.seen[inter.FullID]; ok {
			continue
		}
		c.seen[inter.FullID] = struct{}{}
		interactions = append(interactions, inter)
	}
	return interactions, nil
}

func (c *Client) Delete(ctx context.Context) error {
	endpoint := fmt.Sprintf("%s/delete?secret=%s&correlation_id=%s", c.serverURL, url.QueryEscape(c.secret), url.QueryEscape(c.correlationID))
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return nil
}

func randomToken() string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 16)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
