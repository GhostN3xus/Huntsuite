package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"math"
	"net/http"
	"net/url"
	"sort"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"huntsuite/pkg/logging"
	"huntsuite/pkg/storage/sqlite"
)

const maxResponseBodyBytes = 2 * 1024 * 1024
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
	injectionPoints, err := e.enumerateInjectionPoints(ctx, scanID, parsed, opts)
	if err != nil {
		e.logger.Warn("parameter discovery failed", logging.Fields{"error": err})
	}
	e.logger.Info("injection surface enumerated", logging.Fields{"points": len(injectionPoints)})

	var findings []Finding

	if opts.EnableXSS {
		xssFindings, err := e.runXSS(ctx, scanID, injectionPoints, opts)
	var findings []Finding

	if opts.EnableXSS {
		xssFindings, err := e.runXSS(ctx, scanID, parsed, opts)
		if err != nil {
			e.logger.Error("xss scanner failed", logging.Fields{"error": err})
		}
		findings = append(findings, xssFindings...)
	}

	if opts.EnableSQLi {
		sqliFindings, err := e.runSQLi(ctx, scanID, injectionPoints, opts)
		sqliFindings, err := e.runSQLi(ctx, scanID, parsed, opts)
		if err != nil {
			e.logger.Error("sqli scanner failed", logging.Fields{"error": err})
		}
		findings = append(findings, sqliFindings...)
	}

	if opts.EnableSSRF && opts.OOBDomain != "" {
		ssrfFindings, err := e.runSSRF(ctx, scanID, injectionPoints, opts)
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

func (e *Engine) runXSS(ctx context.Context, scanID int64, points []injectionPoint, opts Options) ([]Finding, error) {
	e.logger.Info("running xss scanner", logging.Fields{"surface": len(points)})
func (e *Engine) runXSS(ctx context.Context, scanID int64, target *url.URL, opts Options) ([]Finding, error) {
	e.logger.Info("running xss scanner", logging.Fields{})
	payloads := []string{
		`<script>alert(1)</script>`,
		`"><script>alert('huntsuite')</script>`,
		`'><script>alert(1)</script>`,
	}

	var findings []Finding

	for _, point := range points {
		if err := ctx.Err(); err != nil {
			return findings, err
		}
		for idx, payload := range payloads {
			template := point.templateForValue(payload)
			result, err := e.sendAndEvaluate(ctx, scanID, template, opts.UserAgent, func(resp *responsePayload) (bool, string) {
				return detectXSS(resp, payload)
			})
			if err != nil {
				e.logger.Debug("xss request failed", logging.Fields{"parameter": point.Name, "source": point.Source, "error": err})
				continue
			}
			if result != nil {
				evidence := fmt.Sprintf("%s\n%s", point.label(), result.Evidence)
				finding := Finding{
					Title:       fmt.Sprintf("Reflected XSS in %s", point.Name),
					Type:        "xss",
					Severity:    SeverityHigh,
					Description: fmt.Sprintf("Input submitted through %s is reflected without sufficient encoding.", point.label()),
					Evidence:    evidence,
					PoC:         buildCurlCommand(template, opts.UserAgent),
				}
				e.logger.Warn("xss finding", logging.Fields{"parameter": point.Name, "source": point.Source})
				findings = append(findings, finding)
				if err := e.persistFinding(ctx, scanID, finding); err != nil {
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
			if idx < len(payloads)-1 {
				if err := waitDelay(ctx, opts.Delay); err != nil {
					return findings, err
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

func (e *Engine) runSQLi(ctx context.Context, scanID int64, points []injectionPoint, opts Options) ([]Finding, error) {
	e.logger.Info("running sqli scanner", logging.Fields{"surface": len(points)})
	errorPayloads := []string{"'", "\"", "' OR '1'='1"}
	boolPayloads := []struct {
		TruePayload  string
		FalsePayload string
	}{
		{TruePayload: "' AND 1=1--", FalsePayload: "' AND 1=2--"},
		{TruePayload: `" OR ""=""`, FalsePayload: `" OR ""="""`},
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
		{Payload: "' AND SLEEP(5)--", Delay: 5 * time.Second},
		{Payload: "' AND pg_sleep(5)--", Delay: 5 * time.Second},
	}
	keywords := []string{"sql syntax", "mysql", "postgres", "near ", "syntax error", "odbc", "warning"}

	var findings []Finding

	for _, point := range points {
		if err := ctx.Err(); err != nil {
			return findings, err
		}

		baselineTemplate := point.templateForValue(point.BaseValue)
		baseline, err := e.measureLatency(ctx, scanID, baselineTemplate, opts.UserAgent, 3)
		if err != nil {
			e.logger.Debug("baseline measurement failed", logging.Fields{"parameter": point.Name, "source": point.Source, "error": err})
			continue
		}

		errorDetected := false
		for _, payload := range errorPayloads {
			mutated := point.templateForValue(combineWithPayload(point.BaseValue, payload))
			result, err := e.sendAndEvaluate(ctx, scanID, mutated, opts.UserAgent, func(resp *responsePayload) (bool, string) {
				return detectSQLError(resp, keywords)
			})
			if err != nil {
				e.logger.Debug("error-based sqli request failed", logging.Fields{"parameter": point.Name, "source": point.Source, "error": err})
				continue
			}
			if result != nil {
				finding := Finding{
					Title:       fmt.Sprintf("Error-based SQL injection in %s", point.Name),
					Type:        "sqli",
					Severity:    SeverityHigh,
					Description: fmt.Sprintf("Database error messages were disclosed when manipulating %s.", point.label()),
					Evidence:    result.Evidence,
					PoC:         buildCurlCommand(mutated, opts.UserAgent),
				}
				e.logger.Warn("sql injection finding", logging.Fields{"parameter": point.Name, "vector": "error", "source": point.Source})
				findings = append(findings, finding)
				if err := e.persistFinding(ctx, scanID, finding); err != nil {
					e.logger.Warn("persist finding failed", logging.Fields{"error": err})
				}
				errorDetected = true
				break
			}
			if err := waitDelay(ctx, opts.Delay); err != nil {
				return findings, err
			}
		}
		if errorDetected {
			continue
		}

		booleanDetected := false
		for _, payload := range boolPayloads {
			trueTemplate := point.templateForValue(combineWithPayload(point.BaseValue, payload.TruePayload))
			falseTemplate := point.templateForValue(combineWithPayload(point.BaseValue, payload.FalsePayload))

			trueResp, err := e.execute(ctx, scanID, trueTemplate, opts.UserAgent)
			if err != nil {
				e.logger.Debug("boolean true request failed", logging.Fields{"parameter": point.Name, "source": point.Source, "error": err})
				continue
			}
			if err := waitDelay(ctx, opts.Delay); err != nil {
				return findings, err
			}
			falseResp, err := e.execute(ctx, scanID, falseTemplate, opts.UserAgent)
			if err != nil {
				e.logger.Debug("boolean false request failed", logging.Fields{"parameter": point.Name, "source": point.Source, "error": err})
				continue
			}

			if divergingResponses(trueResp, falseResp) {
				evidence := fmt.Sprintf("Responses diverged when toggling boolean condition on %s (status %d vs %d, length %d vs %d)", point.label(), trueResp.StatusCode, falseResp.StatusCode, len(trueResp.Body), len(falseResp.Body))
				finding := Finding{
					Title:       fmt.Sprintf("Boolean-based SQL injection in %s", point.Name),
					Type:        "sqli",
					Severity:    SeverityHigh,
					Description: fmt.Sprintf("Conditional SQL logic influenced the response when testing %s.", point.label()),
					Evidence:    evidence,
					PoC:         strings.Join([]string{buildCurlCommand(trueTemplate, opts.UserAgent), buildCurlCommand(falseTemplate, opts.UserAgent)}, "\n"),
				}
				e.logger.Warn("sql injection finding", logging.Fields{"parameter": point.Name, "vector": "boolean", "source": point.Source})
				findings = append(findings, finding)
				if err := e.persistFinding(ctx, scanID, finding); err != nil {
					e.logger.Warn("persist finding failed", logging.Fields{"error": err})
				}
				booleanDetected = true
				break
			}
		}
		if booleanDetected {
			continue
		}

		for _, payload := range timePayloads {
			mutated := point.templateForValue(combineWithPayload(point.BaseValue, payload.Payload))
			resp, err := e.execute(ctx, scanID, mutated, opts.UserAgent)
			if err != nil {
				e.logger.Debug("time-based request failed", logging.Fields{"parameter": point.Name, "source": point.Source, "error": err})
				continue
			}
			if resp.Latency-baseline >= payload.Delay-time.Second {
				evidence := fmt.Sprintf("Baseline latency %s vs %s after payload %q", baseline.Round(time.Millisecond), resp.Latency.Round(time.Millisecond), payload.Payload)
				finding := Finding{
					Title:       fmt.Sprintf("Time-based SQL injection in %s", point.Name),
					Type:        "sqli",
					Severity:    SeverityHigh,
					Description: fmt.Sprintf("Blocking expressions injected into %s introduced measurable delays.", point.label()),
					Evidence:    evidence,
					PoC:         buildCurlCommand(mutated, opts.UserAgent),
				}
				e.logger.Warn("sql injection finding", logging.Fields{"parameter": point.Name, "vector": "time", "source": point.Source, "latency_ms": resp.Latency.Milliseconds()})
				findings = append(findings, finding)
				if err := e.persistFinding(ctx, scanID, finding); err != nil {
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
			if err := waitDelay(ctx, opts.Delay); err != nil {
				return findings, err
			}
		}
	}

	return findings, nil
}

func (e *Engine) runSSRF(ctx context.Context, scanID int64, points []injectionPoint, opts Options) ([]Finding, error) {
	e.logger.Info("running ssrf scanner", logging.Fields{"surface": len(points)})
	if opts.OOBDomain == "" {
func (e *Engine) runSSRF(ctx context.Context, scanID int64, target *url.URL, opts Options) ([]Finding, error) {
	e.logger.Info("running ssrf scanner", logging.Fields{})
	baseParams := target.Query()
	if len(baseParams) == 0 {
		return nil, nil
	}

	var findings []Finding
  
	for _, point := range points {
		if err := ctx.Err(); err != nil {
			return findings, err
		}
		payload := fmt.Sprintf("http://%s", opts.OOBDomain)
		mutated := point.templateForValue(payload)
		resp, err := e.execute(ctx, scanID, mutated, opts.UserAgent)
		if err != nil {
			e.logger.Debug("ssrf request failed", logging.Fields{"parameter": point.Name, "source": point.Source, "error": err})
			continue
		}

		evidenceParts := []string{fmt.Sprintf("Injected %s into %s", payload, point.label())}
		severity := SeverityMedium

		if resp.Headers != nil {
			location := resp.Headers.Get("Location")
			if strings.Contains(location, opts.OOBDomain) {
				evidenceParts = append(evidenceParts, fmt.Sprintf("Server followed redirect to %s", location))
				severity = SeverityHigh
			}
		}
		if bytes.Contains(resp.Body, []byte(opts.OOBDomain)) {
			evidenceParts = append(evidenceParts, "Callback domain reflected in response body")
			if severity == SeverityMedium {
				severity = SeverityHigh
			}
		}
		if resp.StatusCode >= 400 {
			severity = SeverityLow
			evidenceParts = append(evidenceParts, fmt.Sprintf("Server responded with status %d", resp.StatusCode))
		}

		evidence := strings.Join(evidenceParts, " | ")
		finding := Finding{
			Title:       fmt.Sprintf("Potential SSRF via %s", point.Name),
			Type:        "ssrf",
			Severity:    severity,
			Description: fmt.Sprintf("The parameter %s accepts attacker-controlled URLs. Monitor %s for out-of-band interactions to confirm exploitation.", point.label(), opts.OOBDomain),
			Evidence:    evidence,
			PoC:         buildCurlCommand(mutated, opts.UserAgent),
		}
		e.logger.Info("potential ssrf discovered", logging.Fields{"parameter": point.Name, "source": point.Source, "severity": severity})
		findings = append(findings, finding)
		if err := e.persistFinding(ctx, scanID, finding); err != nil {
			e.logger.Warn("persist finding failed", logging.Fields{"error": err})
		}
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


type parameterLocation int

const (
	locationQuery parameterLocation = iota
	locationBody
)

type injectionPoint struct {
	Name        string
	Method      string
	URL         *url.URL
	Location    parameterLocation
	Values      url.Values
	ContentType string
	BaseValue   string
	Source      string
}

func (p injectionPoint) method() string {
	if p.Method == "" {
		return http.MethodGet
	}
	return strings.ToUpper(p.Method)
}

func (p injectionPoint) contentType() string {
	if strings.TrimSpace(p.ContentType) == "" {
		return "application/x-www-form-urlencoded"
	}
	return p.ContentType
}

func (p injectionPoint) templateForValue(value string) requestTemplate {
	cloned := cloneValues(p.Values)
	cloned.Set(p.Name, value)
	targetURL := cloneURL(p.URL)
	headers := http.Header{}
	var body []byte

	switch p.Location {
	case locationQuery:
		targetURL.RawQuery = cloned.Encode()
	case locationBody:
		targetURL.RawQuery = p.URL.RawQuery
		body = []byte(cloned.Encode())
		headers.Set("Content-Type", p.contentType())
	default:
		targetURL.RawQuery = cloned.Encode()
	}

	return requestTemplate{
		Method:  p.method(),
		URL:     targetURL.String(),
		Headers: headers,
		Body:    body,
	}
}

func (p injectionPoint) label() string {
	location := "query"
	if p.Location == locationBody {
		location = "body"
	}
	label := fmt.Sprintf("%s %s parameter '%s'", strings.ToUpper(p.method()), location, p.Name)
	if p.Source != "" {
		label = fmt.Sprintf("%s (%s)", label, p.Source)
	}
	return label
}

type requestTemplate struct {
	Method  string
	URL     string
	Headers http.Header
	Body    []byte
}

type responsePayload struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
	Latency    time.Duration
}

type evaluationResult struct {
	Evidence string
}

func (e *Engine) enumerateInjectionPoints(ctx context.Context, scanID int64, target *url.URL, opts Options) ([]injectionPoint, error) {
	points := make([]injectionPoint, 0)
	baseQuery := target.Query()
	if len(baseQuery) > 0 {
		for param := range baseQuery {
			points = append(points, injectionPoint{
				Name:      param,
				Method:    http.MethodGet,
				URL:       cloneURL(target),
				Location:  locationQuery,
				Values:    cloneValues(baseQuery),
				BaseValue: baseQuery.Get(param),
				Source:    "query",
			})
		}
	}

	forms, err := e.discoverForms(ctx, scanID, target, opts)
	if err != nil {
		return points, err
	}

	for idx, form := range forms {
		location := locationQuery
		method := strings.ToUpper(strings.TrimSpace(form.Method))
		if method == "" {
			method = http.MethodGet
		}
		if method == http.MethodPost {
			location = locationBody
		}

		if location == locationBody && strings.Contains(strings.ToLower(form.Enctype), "multipart") {
			e.logger.Debug("skipping multipart form", logging.Fields{"form": form.Source})
			continue
		}

		values := url.Values{}
		for _, input := range form.Inputs {
			if input.Name != "" {
				values.Set(input.Name, input.Value)
			}
		}
		if len(values) == 0 {
			continue
		}

		source := form.Source
		if source == "" {
			source = fmt.Sprintf("form#%d", idx+1)
		}

		for _, input := range form.Inputs {
			if input.Name == "" {
				continue
			}
			points = append(points, injectionPoint{
				Name:        input.Name,
				Method:      method,
				URL:         cloneURL(form.Action),
				Location:    location,
				Values:      cloneValues(values),
				ContentType: form.Enctype,
				BaseValue:   input.Value,
				Source:      source,
			})
		}
	}

	sort.Slice(points, func(i, j int) bool {
		if points[i].Source == points[j].Source {
			if points[i].URL.String() == points[j].URL.String() {
				return points[i].Name < points[j].Name
			}
			return points[i].URL.String() < points[j].URL.String()
		}
		return points[i].Source < points[j].Source
	})

	return points, nil
}

func (e *Engine) sendAndEvaluate(ctx context.Context, scanID int64, template requestTemplate, userAgent string, evaluator func(*responsePayload) (bool, string)) (*evaluationResult, error) {
	resp, err := e.execute(ctx, scanID, template, userAgent)
	if err != nil {
		return nil, err
	}
	matched, evidence := evaluator(resp)
	if matched {
		return &evaluationResult{Evidence: evidence}, nil
	}
	return nil, nil
}

func (e *Engine) execute(ctx context.Context, scanID int64, template requestTemplate, userAgent string) (*responsePayload, error) {
	var bodyReader io.Reader
	if len(template.Body) > 0 || template.Method == http.MethodPost || template.Method == http.MethodPut || template.Method == http.MethodPatch {
		bodyReader = bytes.NewReader(template.Body)
	}
	req, err := http.NewRequestWithContext(ctx, template.Method, template.URL, bodyReader)
	if err != nil {
		return nil, err
	}

	for key, values := range template.Headers {
		for _, v := range values {
			req.Header.Add(key, v)
		}
	}
	if userAgent != "" && req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", userAgent)
	}

	reqID, err := e.store.RecordRequest(ctx, scanID, req.Method, req.URL.String(), headerJSON(req.Header), template.Body)
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
  
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if reqID != 0 {
		if _, err := e.store.RecordResponse(ctx, reqID, resp.StatusCode, headerJSON(resp.Header), body, latency); err != nil {
			e.logger.Debug("failed to persist response", logging.Fields{"error": err})
		}
	}
  
	return &responsePayload{
		StatusCode: resp.StatusCode,
		Headers:    cloneHeader(resp.Header),
		Body:       body,
		Latency:    latency,
	}, nil
}

func (e *Engine) measureLatency(ctx context.Context, scanID int64, template requestTemplate, userAgent string, samples int) (time.Duration, error) {
	if samples <= 0 {
		samples = 1
	}
	var total time.Duration
	var count int
	for i := 0; i < samples; i++ {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		resp, err := e.execute(ctx, scanID, template, userAgent)
		if err != nil {
			return 0, err
		}
		total += resp.Latency
		count++
	}
	if count == 0 {
		return 0, fmt.Errorf("no samples recorded")
	}
	return total / time.Duration(count), nil
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
func detectXSS(resp *responsePayload, payload string) (bool, string) {
	if resp == nil {
		return false, ""
	}
	body := resp.Body
	if idx := bytes.Index(body, []byte(payload)); idx >= 0 {
		snippet := snippetForMatch(body, idx, len(payload))
		return true, fmt.Sprintf("Payload reflected unencoded: %s", snippet)
	}
	escaped := html.EscapeString(payload)
	if idx := bytes.Index(body, []byte(escaped)); idx >= 0 {
		snippet := snippetForMatch(body, idx, len(escaped))
		return true, fmt.Sprintf("Payload reflected HTML-encoded as %q: %s", escaped, snippet)
	}
	return false, ""
}

func detectSQLError(resp *responsePayload, keywords []string) (bool, string) {
	if resp == nil {
		return false, ""
	}
	lower := strings.ToLower(string(resp.Body))
	for _, kw := range keywords {
		if idx := strings.Index(lower, kw); idx >= 0 {
			snippet := snippetForMatch(resp.Body, idx, len(kw))
			return true, fmt.Sprintf("Response contains database error keyword %q: %s", kw, snippet)
		}
	}
	return false, ""
}

func divergingResponses(a, b *responsePayload) bool {
	if a == nil || b == nil {
		return false
	}
	if a.StatusCode != b.StatusCode {
		return true
	}
	lengthDiff := math.Abs(float64(len(a.Body) - len(b.Body)))
	avg := math.Max(float64(len(a.Body)+len(b.Body))/2, 1)
	if lengthDiff/avg > 0.25 {
		return true
	}
	return false
}

func combineWithPayload(base, payload string) string {
	if base == "" {
		return payload
	}
	return base + payload
}

func waitDelay(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func snippetForMatch(body []byte, idx, length int) string {
	if idx < 0 {
		return ""
	}
	start := idx - 60
	if start < 0 {
		start = 0
	}
	end := idx + length + 60
	if end > len(body) {
		end = len(body)
	}
	snippet := string(body[start:end])
	fields := strings.Fields(snippet)
	joined := strings.Join(fields, " ")
	runes := []rune(joined)
	if len(runes) > 160 {
		joined = string(runes[:160]) + "…"
	}
	return joined
}

func buildCurlCommand(template requestTemplate, userAgent string) string {
	parts := []string{"curl", "-i"}
	method := strings.ToUpper(template.Method)
	if method == "" {
		method = http.MethodGet
	}
	if method != http.MethodGet {
		parts = append(parts, "-X", method)
	}
	header := cloneHeader(template.Headers)
	if userAgent != "" && header.Get("User-Agent") == "" {
		header.Set("User-Agent", userAgent)
	}
	for key, values := range header {
		for _, v := range values {
			parts = append(parts, "-H", fmt.Sprintf("%s: %s", key, v))
		}
	}
	if len(template.Body) > 0 {
		parts = append(parts, "--data", escapeShellArg(string(template.Body)))
	}
	parts = append(parts, escapeShellArg(template.URL))
	return strings.Join(parts, " ")
}

func escapeShellArg(arg string) string {
	if arg == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(arg, "'", "'\\''") + "'"
}

func cloneValues(q url.Values) url.Values {
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
func cloneURL(u *url.URL) *url.URL {
	if u == nil {
		return nil
	}
	clone := *u
	if u.User != nil {
		user := *u.User
		clone.User = &user
	}
	return &clone
}

func cloneHeader(h http.Header) http.Header {
	if h == nil {
		return nil
	}
	cloned := make(http.Header, len(h))
	for k, v := range h {
		cp := make([]string, len(v))
		copy(cp, v)
		cloned[k] = cp
	}
	return cloned
}

func headerJSON(h http.Header) string {
	if h == nil {
		return "{}"
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
