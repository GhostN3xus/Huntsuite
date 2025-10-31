package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"huntsuite/pkg/logging"
	"huntsuite/pkg/storage/sqlite"
)

// Engine coordinates the execution of scanners and persistence.
type Engine struct {
	client *http.Client
	store  *sqlite.Store
	logger *logging.Logger
}

// Options defines runtime behaviour for the scan engine.
type Options struct {
	Target     string
	OOBDomain  string
	EnableXSS  bool
	EnableSQLi bool
	EnableSSRF bool
	Timeout    time.Duration
	UserAgent  string
	Delay      time.Duration
}

// FindingSeverity enumerates severity levels.
type FindingSeverity string

const (
	SeverityCritical FindingSeverity = "critical"
	SeverityHigh     FindingSeverity = "high"
	SeverityMedium   FindingSeverity = "medium"
	SeverityLow      FindingSeverity = "low"
	SeverityInfo     FindingSeverity = "info"
)

// Finding encapsulates vulnerability details produced by the scanners.
type Finding struct {
	Title       string
	Type        string
	Severity    FindingSeverity
	Description string
	Evidence    string
	PoC         string
}

// NewEngine creates a new scanner engine.
func NewEngine(store *sqlite.Store, logger *logging.Logger, httpClient *http.Client) *Engine {
	return &Engine{store: store, logger: logger, client: httpClient}
}

// Run executes the configured scanners against the supplied target.
func (e *Engine) Run(ctx context.Context, opts Options) error {
	parsed, err := url.Parse(opts.Target)
	if err != nil {
		return fmt.Errorf("engine: invalid target: %w", err)
	}
	if parsed.Scheme == "" {
		parsed.Scheme = "https"
	}

	targetID, err := e.store.UpsertTarget(ctx, parsed.Host, "")
	if err != nil {
		return fmt.Errorf("engine: persist target: %w", err)
	}

	scanID, err := e.store.CreateScan(ctx, targetID, "running", fmt.Sprintf("xss=%t,sqli=%t,ssrf=%t", opts.EnableXSS, opts.EnableSQLi, opts.EnableSSRF))
	if err != nil {
		return fmt.Errorf("engine: create scan: %w", err)
	}
	defer func() {
		_ = e.store.UpdateScanStatus(context.Background(), scanID, "completed", "Scan finished", true)
	}()

	e.logger.Info("scan started", logging.Fields{"scan_id": scanID, "target": opts.Target})

	var findings []Finding

	if opts.EnableXSS {
		xssFindings, err := e.runXSS(ctx, scanID, parsed, opts)
		if err != nil {
			e.logger.Error("xss scanner failed", logging.Fields{"error": err})
		}
		findings = append(findings, xssFindings...)
	}

	if opts.EnableSQLi {
		sqliFindings, err := e.runSQLi(ctx, scanID, parsed, opts)
		if err != nil {
			e.logger.Error("sqli scanner failed", logging.Fields{"error": err})
		}
		findings = append(findings, sqliFindings...)
	}

	if opts.EnableSSRF && opts.OOBDomain != "" {
		ssrfFindings, err := e.runSSRF(ctx, scanID, parsed, opts)
		if err != nil {
			e.logger.Error("ssrf scanner failed", logging.Fields{"error": err})
		}
		findings = append(findings, ssrfFindings...)
	}

	summary := fmt.Sprintf("findings=%d", len(findings))
	if err := e.store.UpdateScanStatus(ctx, scanID, "completed", summary, true); err != nil {
		e.logger.Warn("failed to update scan status", logging.Fields{"error": err})
	}

	e.logger.Info("scan completed", logging.Fields{"scan_id": scanID, "findings": len(findings)})

	return nil
}

func (e *Engine) runXSS(ctx context.Context, scanID int64, target *url.URL, opts Options) ([]Finding, error) {
	e.logger.Info("running xss scanner", logging.Fields{})
	payloads := []string{
		`<script>alert(1)</script>`,
		`"><script>alert('huntsuite')</script>`,
		`'><script>alert(1)</script>`,
	}

	baseParams := target.Query()
	if len(baseParams) == 0 {
		return nil, nil
	}

	var findings []Finding

	for param := range baseParams {
		for _, payload := range payloads {
			mutated := cloneQuery(baseParams)
			mutated.Set(param, payload)
			mutatedURL := *target
			mutatedURL.RawQuery = mutated.Encode()

			finding, err := e.sendAndEvaluate(ctx, scanID, http.MethodGet, mutatedURL.String(), opts.UserAgent, func(body []byte) (bool, string) {
				if bytes.Contains(body, []byte(payload)) {
					return true, fmt.Sprintf("Payload reflected in response body for parameter '%s'", param)
				}
				return false, ""
			})
			if err != nil {
				e.logger.Debug("xss request failed", logging.Fields{"parameter": param, "error": err})
				continue
			}
			if finding != nil {
				evidence := fmt.Sprintf("Parameter '%s' reflected payload %s", param, payload)
				f := Finding{
					Title:       fmt.Sprintf("Reflected XSS in %s", param),
					Type:        "xss",
					Severity:    SeverityHigh,
					Description: "The application reflects input without proper sanitisation allowing script execution.",
					Evidence:    evidence,
					PoC:         fmt.Sprintf("curl '%s'", mutatedURL.String()),
				}
				e.logger.Warn("xss finding", logging.Fields{"parameter": param, "payload": payload})
				findings = append(findings, f)
				if err := e.persistFinding(ctx, scanID, f); err != nil {
					e.logger.Warn("persist finding failed", logging.Fields{"error": err})
				}
				break
			}
			if opts.Delay > 0 {
				select {
				case <-time.After(opts.Delay):
				case <-ctx.Done():
					return findings, ctx.Err()
				}
			}
		}
	}

	return findings, nil
}

func (e *Engine) runSQLi(ctx context.Context, scanID int64, target *url.URL, opts Options) ([]Finding, error) {
	e.logger.Info("running sqli scanner", logging.Fields{})
	baseParams := target.Query()
	if len(baseParams) == 0 {
		return nil, nil
	}

	errorPayloads := []string{"'", "\"", "' OR '1'='1"}
	timePayloads := []struct {
		Payload string
		Delay   time.Duration
	}{
		{Payload: "1' AND SLEEP(5)--", Delay: 5 * time.Second},
		{Payload: "1' AND pg_sleep(5)--", Delay: 5 * time.Second},
	}

	keywords := []string{"sql syntax", "mysql", "postgres", "near ", "syntax error"}

	var findings []Finding

	for param := range baseParams {
		baseline, err := e.timeRequest(ctx, scanID, target, baseParams, param, baseParams.Get(param), opts)
		if err != nil {
			e.logger.Debug("baseline request failed", logging.Fields{"parameter": param, "error": err})
			continue
		}

		for _, payload := range errorPayloads {
			mutated := cloneQuery(baseParams)
			mutated.Set(param, baseParams.Get(param)+payload)
			mutatedURL := *target
			mutatedURL.RawQuery = mutated.Encode()

			finding, err := e.sendAndEvaluate(ctx, scanID, http.MethodGet, mutatedURL.String(), opts.UserAgent, func(body []byte) (bool, string) {
				lower := strings.ToLower(string(body))
				for _, kw := range keywords {
					if strings.Contains(lower, kw) {
						return true, fmt.Sprintf("SQL error keyword '%s' detected in response", kw)
					}
				}
				return false, ""
			})
			if err != nil {
				e.logger.Debug("error-based sqli request failed", logging.Fields{"parameter": param, "error": err})
				continue
			}
			if finding != nil {
				f := Finding{
					Title:       fmt.Sprintf("Error-based SQL injection in %s", param),
					Type:        "sqli",
					Severity:    SeverityHigh,
					Description: "The application exposes database error messages when crafted input is supplied.",
					Evidence:    finding.Evidence,
					PoC:         fmt.Sprintf("curl '%s'", mutatedURL.String()),
				}
				e.logger.Warn("sql injection finding", logging.Fields{"parameter": param, "vector": "error-based"})
				findings = append(findings, f)
				if err := e.persistFinding(ctx, scanID, f); err != nil {
					e.logger.Warn("persist finding failed", logging.Fields{"error": err})
				}
				break
			}
		}

		for _, payload := range timePayloads {
			mutated := cloneQuery(baseParams)
			mutated.Set(param, payload.Payload)
			mutatedURL := *target
			mutatedURL.RawQuery = mutated.Encode()

			start := time.Now()
			_, err := e.sendAndEvaluate(ctx, scanID, http.MethodGet, mutatedURL.String(), opts.UserAgent, func(body []byte) (bool, string) {
				_ = body
				return false, ""
			})
			duration := time.Since(start)

			if err != nil {
				e.logger.Debug("time-based request failed", logging.Fields{"parameter": param, "error": err})
				continue
			}
			if duration-baseline > payload.Delay-2*time.Second {
				evidence := fmt.Sprintf("Response delayed by %s when injecting %q", duration.Round(time.Millisecond), payload.Payload)
				f := Finding{
					Title:       fmt.Sprintf("Time-based SQL injection in %s", param),
					Type:        "sqli",
					Severity:    SeverityHigh,
					Description: "Database time delays observed by injecting blocking expressions.",
					Evidence:    evidence,
					PoC:         fmt.Sprintf("curl '%s'", mutatedURL.String()),
				}
				e.logger.Warn("sql injection finding", logging.Fields{"parameter": param, "vector": "time-based", "duration": duration})
				findings = append(findings, f)
				if err := e.persistFinding(ctx, scanID, f); err != nil {
					e.logger.Warn("persist finding failed", logging.Fields{"error": err})
				}
				break
			}
		}
	}

	return findings, nil
}

func (e *Engine) runSSRF(ctx context.Context, scanID int64, target *url.URL, opts Options) ([]Finding, error) {
	e.logger.Info("running ssrf scanner", logging.Fields{})
	baseParams := target.Query()
	if len(baseParams) == 0 {
		return nil, nil
	}

	var findings []Finding

	for param := range baseParams {
		mutated := cloneQuery(baseParams)
		mutated.Set(param, fmt.Sprintf("http://%s", opts.OOBDomain))
		mutatedURL := *target
		mutatedURL.RawQuery = mutated.Encode()

		_, err := e.sendAndEvaluate(ctx, scanID, http.MethodGet, mutatedURL.String(), opts.UserAgent, func(body []byte) (bool, string) {
			_ = body
			return false, ""
		})
		if err != nil {
			e.logger.Debug("ssrf request failed", logging.Fields{"parameter": param, "error": err})
			continue
		}

		evidence := fmt.Sprintf("Injected callback domain %s into parameter %s", opts.OOBDomain, param)
		f := Finding{
			Title:       fmt.Sprintf("Potential SSRF in %s", param),
			Type:        "ssrf",
			Severity:    SeverityMedium,
			Description: "The parameter accepts arbitrary URLs. Monitor the OOB domain for interactions to confirm exploitation.",
			Evidence:    evidence,
			PoC:         fmt.Sprintf("curl '%s'", mutatedURL.String()),
		}
		e.logger.Info("potential ssrf discovered", logging.Fields{"parameter": param, "oob_domain": opts.OOBDomain})
		if err := e.persistFinding(ctx, scanID, f); err != nil {
			e.logger.Warn("persist finding failed", logging.Fields{"error": err})
		}
		findings = append(findings, f)
	}

	return findings, nil
}

type evaluationResult struct {
	Evidence string
}

func (e *Engine) sendAndEvaluate(ctx context.Context, scanID int64, method, targetURL, userAgent string, evaluator func([]byte) (bool, string)) (*evaluationResult, error) {
	req, err := http.NewRequestWithContext(ctx, method, targetURL, nil)
	if err != nil {
		return nil, err
	}
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}

	reqID, err := e.store.RecordRequest(ctx, scanID, method, targetURL, headerJSON(req.Header), nil)
	if err != nil {
		e.logger.Debug("failed to persist request", logging.Fields{"error": err})
	}

	start := time.Now()
	resp, err := e.client.Do(req)
	latency := time.Since(start)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if reqID != 0 {
		if _, err := e.store.RecordResponse(ctx, reqID, resp.StatusCode, headerJSON(resp.Header), body, latency); err != nil {
			e.logger.Debug("failed to persist response", logging.Fields{"error": err})
		}
	}

	matched, evidence := evaluator(body)
	if matched {
		return &evaluationResult{Evidence: evidence}, nil
	}
	return nil, nil
}

func (e *Engine) persistFinding(ctx context.Context, scanID int64, finding Finding) error {
	var cvss *float64
	switch finding.Severity {
	case SeverityCritical:
		cv := 9.5
		cvss = &cv
	case SeverityHigh:
		cv := 8.0
		cvss = &cv
	case SeverityMedium:
		cv := 6.5
		cvss = &cv
	case SeverityLow:
		cv := 3.5
		cvss = &cv
	}

	_, err := e.store.InsertFinding(ctx, &sqlite.Finding{
		ScanID:      scanID,
		Title:       finding.Title,
		Type:        finding.Type,
		Severity:    string(finding.Severity),
		CVSS:        cvss,
		Description: stringPtr(finding.Description),
		Evidence:    stringPtr(finding.Evidence),
		PoC:         stringPtr(finding.PoC),
	})
	return err
}

func (e *Engine) timeRequest(ctx context.Context, scanID int64, target *url.URL, params url.Values, param, value string, opts Options) (time.Duration, error) {
	mutated := cloneQuery(params)
	mutated.Set(param, value)
	mutatedURL := *target
	mutatedURL.RawQuery = mutated.Encode()

	start := time.Now()
	_, err := e.sendAndEvaluate(ctx, scanID, http.MethodGet, mutatedURL.String(), opts.UserAgent, func(body []byte) (bool, string) {
		_ = body
		return false, ""
	})
	return time.Since(start), err
}

func cloneQuery(q url.Values) url.Values {
	cloned := make(url.Values, len(q))
	for k, v := range q {
		cp := make([]string, len(v))
		copy(cp, v)
		cloned[k] = cp
	}
	return cloned
}

func headerJSON(h http.Header) string {
	buf, _ := json.Marshal(h)
	return string(buf)
}

func stringPtr(val string) *string {
	if strings.TrimSpace(val) == "" {
		return nil
	}
	v := val
	return &v
}
