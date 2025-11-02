package recon

import (
	"context"
	"crypto/rand"
	_ "embed"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

//go:embed wordlists/subdomains.txt
var embeddedWordlist string

// DNSResolver abstracts DNS lookups for easier testing.
type DNSResolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// SimpleRecon performs wordlist-based subdomain enumeration with wildcard detection.
type SimpleRecon struct {
	resolver DNSResolver
	wordlist []string
	mu       sync.Mutex
}

// NewSimpleRecon creates a recon engine backed by the embedded wordlist.
func NewSimpleRecon() *SimpleRecon {
	entries := parseWordlist(embeddedWordlist)
	return &SimpleRecon{resolver: net.DefaultResolver, wordlist: entries}
}

// WithResolver returns a copy of the recon engine using the provided resolver.
func (r *SimpleRecon) WithResolver(resolver DNSResolver) *SimpleRecon {
	clone := *r
	clone.resolver = resolver
	return &clone
}

// EnumSubdomains enumerates resolvable subdomains for the provided domain.
func (r *SimpleRecon) EnumSubdomains(domain string, wordlistPath string, timeoutSeconds int) []string {
	if domain = strings.TrimSpace(domain); domain == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), chooseTimeout(timeoutSeconds))
	defer cancel()

	wildcardIPs := r.detectWildcard(ctx, domain)
	unique := map[string]struct{}{}
	var mu sync.Mutex
	tasks := make(chan string)
	var wg sync.WaitGroup

	workerCount := 10
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for sub := range tasks {
				host := fmt.Sprintf("%s.%s", sub, domain)
				lookupCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
				addrs, err := r.resolver.LookupHost(lookupCtx, host)
				cancel()
				if err != nil || len(addrs) == 0 {
					continue
				}
				if matchesWildcard(addrs, wildcardIPs) {
					continue
				}
				mu.Lock()
				unique[host] = struct{}{}
				mu.Unlock()
			}
		}()
	}

	for _, sub := range r.loadWordlist(wordlistPath) {
		select {
		case <-ctx.Done():
			close(tasks)
			wg.Wait()
			return toSorted(unique)
		case tasks <- sub:
		}
	}
	close(tasks)
	wg.Wait()
	return toSorted(unique)
}

func (r *SimpleRecon) detectWildcard(ctx context.Context, domain string) map[string]struct{} {
	wildcardIPs := map[string]struct{}{}
	attempts := 3
	for i := 0; i < attempts; i++ {
		token := randomLabel(12)
		host := fmt.Sprintf("%s.%s", token, domain)
		lookupCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		addrs, err := r.resolver.LookupHost(lookupCtx, host)
		cancel()
		if err != nil || len(addrs) == 0 {
			return nil
		}
		for _, ip := range addrs {
			wildcardIPs[ip] = struct{}{}
		}
	}
	if len(wildcardIPs) == 0 {
		return nil
	}
	return wildcardIPs
}

func (r *SimpleRecon) loadWordlist(path string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if path == "" {
		return r.wordlist
	}
	// When a custom path is supplied we try to read it lazily.
	if entries, err := readWordlist(path); err == nil {
		return entries
	}
	return r.wordlist
}

func parseWordlist(data string) []string {
	lines := strings.Split(data, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

func readWordlist(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	entries := parseWordlist(string(data))
	if len(entries) == 0 {
		return nil, errors.New("empty wordlist")
	}
	return entries, nil
}

func chooseTimeout(seconds int) time.Duration {
	if seconds <= 0 {
		return 2 * time.Minute
	}
	return time.Duration(seconds) * time.Second
}

func matchesWildcard(addrs []string, wildcard map[string]struct{}) bool {
	if len(wildcard) == 0 {
		return false
	}
	for _, ip := range addrs {
		if _, ok := wildcard[ip]; ok {
			return true
		}
	}
	return false
}

func toSorted(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for host := range set {
		out = append(out, host)
	}
	sort.Strings(out)
	return out
}

func randomLabel(n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		for i := range b {
			b[i] = alphabet[i%len(alphabet)]
		}
		return string(b)
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}
