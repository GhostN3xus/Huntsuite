
package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/GhostN3xus/Huntsuite/pkg/logging"
	"github.com/GhostN3xus/Huntsuite/pkg/modules"
	"github.com/GhostN3xus/Huntsuite/pkg/storage/sqlite"
)

const maxResponseBodyBytes = 2 * 1024 * 1024

// Engine coordena a execução de scanners e persistência.
type Engine struct {
	client            *http.Client
	store             *sqlite.Store
	logger            *logging.Logger
	registry          *modules.ModuleRegistry
	validatorMappings map[string]modules.VulnerabilityValidator
}

// Options define o comportamento em tempo de execução para o mecanismo de varredura.
type Options struct {
	Target             string
	OOBDomain          string
	EnableXSS          bool
	EnableSQLi         bool
	EnableSSRF         bool
	EnableLFI          bool
	EnableXXE          bool
	EnableCMDI         bool
	EnableOpenRedirect bool
	Timeout            time.Duration
	UserAgent          string
	Delay              time.Duration
	Headers            http.Header
	Threads            int
}

// FindingSeverity enumera os níveis de gravidade.
type FindingSeverity string

const (
	SeverityCritical FindingSeverity = "critical"
	SeverityHigh     FindingSeverity = "high"
	SeverityMedium   FindingSeverity = "medium"
	SeverityLow      FindingSeverity = "low"
	SeverityInfo     FindingSeverity = "info"
)

// Finding encapsula os detalhes da vulnerabilidade produzidos pelos scanners.
type Finding struct {
	Title       string
	Type        string
	Severity    FindingSeverity
	Description string
	Evidence    string
	PoC         string
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

type injectionLocation string

const (
	locationQuery injectionLocation = "query"
	locationBody  injectionLocation = "body"
	locationJSON  injectionLocation = "json"
)

type injectionPoint struct {
	Name        string
	Method      string
	URL         *url.URL
	Location    injectionLocation
	Values      url.Values
	ContentType string
	Headers     http.Header
	BaseValue   string
	Source      string
	JSONValues  map[string]string
}

func (p injectionPoint) templateForValue(value string) requestTemplate {
	method := p.Method
	if method == "" {
		method = http.MethodGet
	}
	headers := cloneHeader(p.Headers)
	target := cloneURL(p.URL)
	body := []byte(nil)

	switch p.Location {
	case locationQuery:
		values := cloneValues(p.Values)
		if values == nil {
			values = url.Values{}
		}
		values.Set(p.Name, value)
		target.RawQuery = values.Encode()
	case locationBody:
		values := cloneValues(p.Values)
		if values == nil {
			values = url.Values{}
		}
		values.Set(p.Name, value)
		body = []byte(values.Encode())
		if headers == nil {
			headers = http.Header{}
		}
		contentType := p.ContentType
		if strings.TrimSpace(contentType) == "" {
			contentType = "application/x-www-form-urlencoded"
		}
		headers.Set("Content-Type", contentType)
	case locationJSON:
		payload := cloneJSONMap(p.JSONValues)
		if payload == nil {
			payload = map[string]string{}
		}
		payload[p.Name] = value
		encoded, err := json.Marshal(payload)
		if err == nil {
			body = encoded
		}
		if headers == nil {
			headers = http.Header{}
		}
		contentType := p.ContentType
		if strings.TrimSpace(contentType) == "" {
			contentType = "application/json"
		}
		headers.Set("Content-Type", contentType)
	}

	return requestTemplate{
		Method:  method,
		URL:     target.String(),
		Headers: headers,
		Body:    body,
	}
}

func (p injectionPoint) label() string {
	source := p.Source
	if source == "" {
		if p.Location == locationBody {
			source = "corpo da requisição"
		} else if p.Location == locationJSON {
			source = "corpo JSON"
		} else {
			source = "consulta"
		}
	}
	return fmt.Sprintf("parâmetro %s '%s'", source, p.Name)
}

type contextKey string

const (
	ctxKeyInjectionPoints contextKey = "huntsuite:injection_points"
)

func withInjectionPoints(ctx context.Context, points []injectionPoint) context.Context {
	return context.WithValue(ctx, ctxKeyInjectionPoints, points)
}

func injectionPointsFromContext(ctx context.Context) ([]injectionPoint, bool) {
	if ctx == nil {
		return nil, false
	}
	points, ok := ctx.Value(ctxKeyInjectionPoints).([]injectionPoint)
	return points, ok
}

// NewEngine cria um novo mecanismo de varredura.
func NewEngine(store *sqlite.Store, logger *logging.Logger, httpClient *http.Client, registry *modules.ModuleRegistry) *Engine {
	mappings := make(map[string]modules.VulnerabilityValidator)
	if v, ok := registry.GetVulnerabilityValidator("ssrf_validator"); ok {
		mappings["SSRF"] = v
	}
	if v, ok := registry.GetVulnerabilityValidator("sqli_validator"); ok {
		mappings["SQLi"] = v
	}
	if v, ok := registry.GetVulnerabilityValidator("lfi_validator"); ok {
		mappings["LFI"] = v
	}
	if v, ok := registry.GetVulnerabilityValidator("xxe_validator"); ok {
		mappings["XXE"] = v
	}
	if v, ok := registry.GetVulnerabilityValidator("cmdi_validator"); ok {
		mappings["CMDI"] = v
	}
	if v, ok := registry.GetVulnerabilityValidator("open_redirect_validator"); ok {
		mappings["Open Redirect"] = v
	}
	return &Engine{store: store, logger: logger, client: httpClient, registry: registry, validatorMappings: mappings}
}

// Run executa os scanners configurados no alvo fornecido.
func (e *Engine) Run(ctx context.Context, opts Options) (int64, error) {
	parsed, err := url.Parse(opts.Target)
	if err != nil {
		return 0, fmt.Errorf("mecanismo: alvo inválido: %w", err)
	}
	if parsed.Scheme == "" {
		parsed.Scheme = "https"
	}

	resolved, err := e.resolveTarget(ctx, parsed, opts)
	if err != nil {
		return 0, fmt.Errorf("mecanismo: resolver alvo: %w", err)
	}
	parsed = resolved

	targetID, err := e.store.UpsertTarget(ctx, parsed.Host, "")
	if err != nil {
		return 0, fmt.Errorf("mecanismo: persistir alvo: %w", err)
	}

	scanID, err := e.store.CreateScan(ctx, targetID, "running", fmt.Sprintf("xss=%t,sqli=%t,ssrf=%t", opts.EnableXSS, opts.EnableSQLi, opts.EnableSSRF))
	if err != nil {
		return 0, fmt.Errorf("mecanismo: criar varredura: %w", err)
	}
	defer func() {
		_ = e.store.UpdateScanStatus(context.Background(), scanID, "completed", "Varredura finalizada", true)
	}()

	e.logger.Info("varredura iniciada", logging.Fields{"scan_id": scanID, "target": opts.Target})

	injectionPoints, err := e.enumerateInjectionPoints(ctx, scanID, parsed, opts)
	if err != nil {
		return 0, err
	}
	e.logger.Info("superfície de injeção enumerada", logging.Fields{"points": len(injectionPoints)})

	ctx = withInjectionPoints(ctx, injectionPoints)

	var findings []Finding

	for _, point := range injectionPoints {
		for _, gen := range e.registry.PayloadGenerators {
			payloads, err := gen.Generate(&modules.TargetContext{URL: opts.Target})
			if err != nil {
				e.logger.Warn("falha ao gerar payloads", logging.Fields{"generator": gen.Name(), "error": err})
				continue
			}

			for _, payload := range payloads {
				finalPayload := payload
				for _, bypasser := range e.registry.WAFBypassers {
					bypassedPayload, err := bypasser.Bypass(&finalPayload)
					if err != nil {
						e.logger.Warn("falha ao aplicar bypass de WAF", logging.Fields{"bypasser": bypasser.Name(), "error": err})
						continue
					}
					finalPayload = *bypassedPayload
				}

				value := combineWithPayload(point.BaseValue, finalPayload.Value)
				reqTemplate := point.templateForValue(value)

				resp, err := e.execute(ctx, scanID, reqTemplate, opts.UserAgent, opts.Headers)
				if err != nil {
					e.logger.Debug("falha na requisição", logging.Fields{"parameter": point.Name, "error": err})
					continue
				}

				if validator, ok := e.validatorMappings[payload.Type]; ok {
					valid, err := validator.Validate(&modules.ResponsePayload{
						StatusCode: resp.StatusCode,
						Headers:    resp.Headers,
						Body:       resp.Body,
						Latency:    resp.Latency,
					}, nil)
					if err != nil {
						e.logger.Warn("falha na validação", logging.Fields{"validator": validator.Name(), "error": err})
						continue
					}

					if valid {
						finding := Finding{
							Title:       fmt.Sprintf("Vulnerabilidade em %s", point.Name),
							Type:        payload.Type,
							Severity:    SeverityHigh, // Placeholder
							Description: fmt.Sprintf("Vulnerabilidade detectada em %s.", point.label()),
							Evidence:    "Placeholder",
							PoC:         buildCurlCommand(reqTemplate, opts.UserAgent),
						}
						findings = append(findings, finding)
						e.persistFinding(ctx, scanID, finding)
					}
				}
			}
		}
	}

	summary := fmt.Sprintf("descobertas=%d", len(findings))
	if err := e.store.UpdateScanStatus(ctx, scanID, "completed", summary, true); err != nil {
		e.logger.Warn("falha ao atualizar status da varredura", logging.Fields{"error": err})
	}

	e.logger.Info("varredura concluída", logging.Fields{"scan_id": scanID, "total_findings": len(findings)})
	return scanID, nil
}

// ... (o resto do arquivo permanece o mesmo, então vou omiti-lo para economizar espaço)
// ...
// ... (vou colar o resto do arquivo de volta depois)

func (e *Engine) resolveTarget(ctx context.Context, target *url.URL, opts Options) (*url.URL, error) {
	if target == nil {
		return nil, fmt.Errorf("mecanismo: alvo nulo")
	}
	current := cloneURL(target)
	if current.Scheme == "" {
		current.Scheme = "https"
	}

	visited := map[string]struct{}{current.String(): {}}
	maxRedirects := 5

	for redirects := 0; redirects <= maxRedirects; redirects++ {
		method := http.MethodHead
		for attempt := 0; attempt < 2; attempt++ {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			req, err := http.NewRequestWithContext(ctx, method, current.String(), nil)
			if err != nil {
				return nil, err
			}
			if method == http.MethodGet {
				req.Header.Set("Range", "bytes=0-0")
			}
			applyHeaders(req, nil, opts.Headers, opts.UserAgent)

			resp, err := e.client.Do(req)
			if err != nil {
				if method == http.MethodHead {
					method = http.MethodGet
					continue
				}
				return nil, fmt.Errorf("mecanismo: sondar alvo %s: %w", current.String(), err)
			}

			if _, drainErr := io.CopyN(io.Discard, resp.Body, 512); drainErr != nil && !errors.Is(drainErr, io.EOF) {
				e.logger.Debug("falha ao drenar resposta da sonda", logging.Fields{"error": drainErr})
			}
			resp.Body.Close()

			if resp.StatusCode == http.StatusMethodNotAllowed && method == http.MethodHead {
				method = http.MethodGet
				continue
			}

			if resp.StatusCode >= 300 && resp.StatusCode <= 399 {
				location := strings.TrimSpace(resp.Header.Get("Location"))
				if location == "" {
					return current, nil
				}
				next, err := current.Parse(location)
				if err != nil {
					return nil, fmt.Errorf("mecanismo: localização de redirecionamento inválida %q: %w", location, err)
				}
				canonical := next.String()
				if _, seen := visited[canonical]; seen {
					return nil, fmt.Errorf("mecanismo: loop de redirecionamento detectado para %s", canonical)
				}
				visited[canonical] = struct{}{}
				current = next
				break
			}

			if resp.StatusCode >= 200 && resp.StatusCode < 400 {
				return current, nil
			}

			if method == http.MethodHead {
				method = http.MethodGet
				continue
			}

			return nil, fmt.Errorf("mecanismo: alvo %s respondeu com status %d", current.String(), resp.StatusCode)
		}
	}

	return nil, fmt.Errorf("mecanismo: muitos redirecionamentos para %s", target.String())
}

func (e *Engine) injectionSurface(ctx context.Context, scanID int64, target *url.URL, opts Options) ([]injectionPoint, error) {
	if points, ok := injectionPointsFromContext(ctx); ok {
		return points, nil
	}
	return e.enumerateInjectionPoints(ctx, scanID, target, opts)
}

func (e *Engine) enumerateInjectionPoints(ctx context.Context, scanID int64, target *url.URL, opts Options) ([]injectionPoint, error) {
	_ = scanID
	_ = opts

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
		method := strings.ToUpper(strings.TrimSpace(form.Method))
		if method == "" {
			method = http.MethodGet
		}

		lowerEnctype := strings.ToLower(strings.TrimSpace(form.Enctype))
		location := locationQuery
		if strings.Contains(lowerEnctype, "json") {
			location = locationJSON
		} else if method == http.MethodPost {
			location = locationBody
		}

		if strings.Contains(lowerEnctype, "multipart") {
			e.logger.Debug("pulando formulário multipart", logging.Fields{"form": form.Source})
			continue
		}

		values := url.Values{}
		jsonValues := map[string]string{}
		for _, input := range form.Inputs {
			if input.Name == "" {
				continue
			}
			if location == locationJSON {
				jsonValues[input.Name] = input.Value
			} else {
				values.Set(input.Name, input.Value)
			}
		}

		if location == locationJSON && len(jsonValues) == 0 {
			continue
		}
		if location != locationJSON && len(values) == 0 {
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
			point := injectionPoint{
				Name:        input.Name,
				Method:      method,
				URL:         cloneURL(form.Action),
				Location:    location,
				ContentType: form.Enctype,
				Source:      source,
				BaseValue:   input.Value,
			}
			if location == locationJSON {
				point.JSONValues = cloneJSONMap(jsonValues)
			} else {
				point.Values = cloneValues(values)
			}
			points = append(points, point)
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

func (e *Engine) sendAndEvaluate(ctx context.Context, scanID int64, template requestTemplate, userAgent string, globalHeaders http.Header, evaluator func(*responsePayload) (bool, string)) (*evaluationResult, error) {
	resp, err := e.execute(ctx, scanID, template, userAgent, globalHeaders)
	if err != nil {
		return nil, err
	}
	matched, evidence := evaluator(resp)
	if matched {
		return &evaluationResult{Evidence: evidence}, nil
	}
	return nil, nil
}

func applyHeaders(req *http.Request, template http.Header, global http.Header, userAgent string) {
	if template != nil {
		for key, values := range template {
			for _, v := range values {
				req.Header.Add(key, v)
			}
		}
	}
	if global != nil {
		for key, values := range global {
			canon := http.CanonicalHeaderKey(key)
			if _, exists := req.Header[canon]; exists {
				continue
			}
			for _, v := range values {
				req.Header.Add(canon, v)
			}
		}
	}
	if userAgent != "" && req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", userAgent)
	}
}

func (e *Engine) execute(ctx context.Context, scanID int64, template requestTemplate, userAgent string, globalHeaders http.Header) (*responsePayload, error) {
	method := template.Method
	if method == "" {
		method = http.MethodGet
	}

	var bodyReader io.Reader
	if len(template.Body) > 0 {
		bodyReader = bytes.NewReader(template.Body)
	}

	req, err := http.NewRequestWithContext(ctx, method, template.URL, bodyReader)
	if err != nil {
		return nil, err
	}

	applyHeaders(req, template.Headers, globalHeaders, userAgent)

	reqBody := template.Body
	if reqBody == nil {
		reqBody = []byte{}
	}

	reqID, err := e.store.RecordRequest(ctx, scanID, req.Method, req.URL.String(), headerJSON(req.Header), reqBody)
	if err != nil {
		e.logger.Debug("falha ao persistir requisição", logging.Fields{"error": err})
	}

	start := time.Now()
	resp, err := e.client.Do(req)
	latency := time.Since(start)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
	if err != nil {
		return nil, err
	}

	if reqID != 0 {
		if _, err := e.store.RecordResponse(ctx, reqID, resp.StatusCode, headerJSON(resp.Header), body, latency); err != nil {
			e.logger.Debug("falha ao persistir resposta", logging.Fields{"error": err})
		}
	}

	return &responsePayload{
		StatusCode: resp.StatusCode,
		Headers:    cloneHeader(resp.Header),
		Body:       body,
		Latency:    latency,
	}, nil
}

func (e *Engine) measureLatency(ctx context.Context, scanID int64, template requestTemplate, userAgent string, globalHeaders http.Header, samples int) (time.Duration, error) {
	if samples <= 0 {
		samples = 1
	}
	var total time.Duration
	var count int
	for i := 0; i < samples; i++ {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		resp, err := e.execute(ctx, scanID, template, userAgent, globalHeaders)
		if err != nil {
			return 0, err
		}
		total += resp.Latency
		count++
	}
	if count == 0 {
		return 0, fmt.Errorf("nenhuma amostra registrada")
	}
	return total / time.Duration(count), nil
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
		return true, fmt.Sprintf("Payload refletido sem codificação: %s", snippet)
	}
	escaped := html.EscapeString(payload)
	if idx := bytes.Index(body, []byte(escaped)); idx >= 0 {
		snippet := snippetForMatch(body, idx, len(escaped))
		return true, fmt.Sprintf("Payload refletido codificado em HTML como %q: %s", escaped, snippet)
	}
	return false, ""
}

func detectSQLError(resp *responsePayload, keywords []string) (bool, string) {
	if resp == nil {
		return false, ""
	}
	lower := strings.ToLower(string(resp.Body))
	for _, kw := range keywords {
		if strings.Contains(lower, kw) {
			return true, fmt.Sprintf("Resposta continha a palavra-chave de erro SQL %q", kw)
		}
	}
	return false, ""
}

func detectSSRF(resp *responsePayload, domain string) (bool, string) {
	if resp == nil {
		return false, ""
	}
	lowerDomain := strings.ToLower(domain)
	if resp.Headers != nil {
		for key, values := range resp.Headers {
			for _, v := range values {
				if strings.Contains(strings.ToLower(v), lowerDomain) {
					return true, fmt.Sprintf("Cabeçalho %s ecoou o domínio do payload SSRF", key)
				}
			}
		}
	}
	if bytes.Contains(bytes.ToLower(resp.Body), []byte(lowerDomain)) {
		snippet := snippetForMatch(resp.Body, bytes.Index(bytes.ToLower(resp.Body), []byte(lowerDomain)), len(lowerDomain))
		return true, fmt.Sprintf("Corpo da resposta referenciou o domínio do payload SSRF: %s", snippet)
	}
	if loc := resp.Headers.Get("Location"); strings.Contains(strings.ToLower(loc), lowerDomain) {
		return true, fmt.Sprintf("Redirecionado para %s", loc)
	}
	return false, ""
}

func snippetForMatch(body []byte, idx int, length int) string {
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
	if header == nil {
		header = http.Header{}
	}
	if userAgent != "" && header.Get("User-Agent") == "" {
		header.Set("User-Agent", userAgent)
	}
	for key, values := range header {
		for _, v := range values {
			parts = append(parts, "-H", escapeShellArg(fmt.Sprintf("%s: %s", key, v)))
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

func divergingResponses(a, b *responsePayload) bool {
	if a == nil || b == nil {
		return false
	}
	if a.StatusCode != b.StatusCode {
		return true
	}
	diff := len(a.Body) - len(b.Body)
	if diff < 0 {
		diff = -diff
	}
	if diff > 50 {
		return true
	}
	return !bytes.Equal(a.Body, b.Body)
}

func cloneValues(q url.Values) url.Values {
	if q == nil {
		return nil
	}
	cloned := make(url.Values, len(q))
	for k, v := range q {
		cp := make([]string, len(v))
		copy(cp, v)
		cloned[k] = cp
	}
	return cloned
}

func cloneJSONMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	cloned := make(map[string]string, len(values))
	for k, v := range values {
		cloned[k] = v
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
		h = http.Header{}
	}
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

// executeRequest executa uma requisição HTTP e retorna a resposta
// Este é um método wrapper usado pelos novos módulos de scanner
func (e *Engine) executeRequest(ctx context.Context, req requestTemplate, opts Options) (responsePayload, error) {
	resp, err := e.execute(ctx, 0, req, opts.UserAgent, opts.Headers)
	if err != nil {
		return responsePayload{}, err
	}
	if resp == nil {
		return responsePayload{}, fmt.Errorf("resposta nula")
	}
	return *resp, nil
}

// reportFinding armazena uma descoberta no banco de dados
// Este é um método wrapper usado pelos novos módulos de scanner
func (e *Engine) reportFinding(ctx context.Context, finding Finding, point injectionPoint, req requestTemplate, resp responsePayload) error {
	// Por enquanto, apenas registraremos a descoberta
	// No futuro, isso pode ser aprimorado para armazenar no banco de dados com contexto completo
	e.logger.Info("vulnerabilidade encontrada", logging.Fields{
		"severity":    string(finding.Severity),
		"type":        finding.Type,
		"title":       finding.Title,
		"target":      req.URL,
		"parameter":   point.Name,
		"evidence":    truncateString(finding.Evidence, 200),
		"status_code": resp.StatusCode,
	})

	// Armazena no banco de dados (usando scanID 0 por enquanto, deve ser passado do contexto)
	return e.persistFinding(ctx, 0, finding)
}

// truncateString trunca uma string para um comprimento máximo
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
