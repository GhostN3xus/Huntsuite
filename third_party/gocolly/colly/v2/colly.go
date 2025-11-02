package colly

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

var ErrAlreadyVisited = errors.New("already visited")

type Collector struct {
	allowedDomains map[string]struct{}
	maxDepth       int
	async          bool
	requestTimeout time.Duration

	onRequest  []func(*Request)
	onResponse []func(*Response)
	onError    []func(*Response, error)
	onHTML     []htmlHandler

	visited map[string]int
	mu      sync.Mutex
}

type htmlHandler struct {
	tag  string
	attr string
	fn   func(*HTMLElement)
}

type CollectorOption func(*Collector)

func NewCollector(options ...CollectorOption) *Collector {
	c := &Collector{
		allowedDomains: map[string]struct{}{},
		visited:        map[string]int{},
		requestTimeout: 10 * time.Second,
	}
	for _, opt := range options {
		opt(c)
	}
	return c
}

func AllowedDomains(domains ...string) CollectorOption {
	return func(c *Collector) {
		for _, d := range domains {
			if d != "" {
				c.allowedDomains[strings.ToLower(d)] = struct{}{}
			}
		}
	}
}

func MaxDepth(depth int) CollectorOption {
	return func(c *Collector) {
		c.maxDepth = depth
	}
}

func Async(flag bool) CollectorOption {
	return func(c *Collector) {
		c.async = flag
	}
}

func (c *Collector) SetRequestTimeout(timeout time.Duration) {
	if timeout > 0 {
		c.requestTimeout = timeout
	}
}

type LimitRule struct {
	DomainGlob  string
	Parallelism int
	RandomDelay time.Duration
}

func (c *Collector) Limit(rule *LimitRule) error {
	return nil
}

func (c *Collector) OnRequest(fn func(*Request)) {
	c.onRequest = append(c.onRequest, fn)
}

func (c *Collector) OnResponse(fn func(*Response)) {
	c.onResponse = append(c.onResponse, fn)
}

func (c *Collector) OnError(fn func(*Response, error)) {
	c.onError = append(c.onError, fn)
}

func (c *Collector) OnHTML(selector string, fn func(*HTMLElement)) {
	tag, attr := parseSelector(selector)
	if tag == "" || attr == "" {
		return
	}
	c.onHTML = append(c.onHTML, htmlHandler{tag: tag, attr: attr, fn: fn})
}

func (c *Collector) Visit(raw string) error {
	return c.visit(raw, 0)
}

func (c *Collector) visit(raw string, depth int) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return err
	}
	host := strings.ToLower(parsed.Hostname())
	if len(c.allowedDomains) > 0 {
		if _, ok := c.allowedDomains[host]; !ok {
			return nil
		}
	}
	c.mu.Lock()
	if d, ok := c.visited[parsed.String()]; ok {
		if depth >= d {
			c.mu.Unlock()
			return ErrAlreadyVisited
		}
	}
	c.visited[parsed.String()] = depth
	c.mu.Unlock()

	req := &Request{collector: c, URL: parsed, depth: depth}
	for _, handler := range c.onRequest {
		handler(req)
		if req.aborted {
			return nil
		}
	}

	client := &http.Client{Timeout: c.requestTimeout}
	resp, err := client.Get(parsed.String())
	if err != nil {
		c.emitError(nil, err)
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.emitError(&Response{Request: req, StatusCode: resp.StatusCode}, err)
		return err
	}
	response := &Response{Request: req, StatusCode: resp.StatusCode, Body: body, Headers: resp.Header}
	for _, handler := range c.onResponse {
		handler(response)
	}
	c.processHTML(response)
	return nil
}

func (c *Collector) Wait() {}

func (c *Collector) emitError(resp *Response, err error) {
	for _, handler := range c.onError {
		handler(resp, err)
	}
}

func (c *Collector) processHTML(resp *Response) {
	content := string(resp.Body)
	for _, handler := range c.onHTML {
		values := extractAttributes(content, handler.tag, handler.attr)
		for _, val := range values {
			elem := &HTMLElement{Request: resp.Request, attr: handler.attr, value: val}
			handler.fn(elem)
		}
	}
}

func parseSelector(selector string) (string, string) {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return "", ""
	}
	open := strings.Index(selector, "[")
	close := strings.Index(selector, "]")
	if open == -1 || close == -1 || close <= open {
		return "", ""
	}
	tag := strings.TrimSpace(selector[:open])
	attr := strings.TrimSpace(selector[open+1 : close])
	attr = strings.Trim(attr, "\"")
	attr = strings.Trim(attr, "'")
	attr = strings.TrimSpace(attr)
	if tag == "" || attr == "" {
		return "", ""
	}
	return strings.ToLower(tag), strings.ToLower(attr)
}

func extractAttributes(html, tag, attr string) []string {
	pattern := fmt.Sprintf("(?is)<%s[^>]*%s=\\\"([^\\\"#]+)", regexp.QuoteMeta(tag), regexp.QuoteMeta(attr))
	re := regexp.MustCompile(pattern)
	matches := re.FindAllStringSubmatch(html, -1)
	results := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) > 1 {
			results = append(results, strings.TrimSpace(match[1]))
		}
	}
	return results
}

type Request struct {
	collector *Collector
	URL       *url.URL
	depth     int
	aborted   bool
}

func (r *Request) AbsoluteURL(link string) string {
	if r.URL == nil {
		return link
	}
	ref, err := url.Parse(link)
	if err != nil {
		return ""
	}
	return r.URL.ResolveReference(ref).String()
}

func (r *Request) Visit(link string) error {
	if r.collector == nil {
		return errors.New("collector not configured")
	}
	if r.collector.maxDepth > 0 && r.depth >= r.collector.maxDepth-1 {
		return ErrAlreadyVisited
	}
	abs := r.AbsoluteURL(link)
	if abs == "" {
		return nil
	}
	return r.collector.visit(abs, r.depth+1)
}

func (r *Request) Abort() {
	r.aborted = true
}

type Response struct {
	Request    *Request
	StatusCode int
	Body       []byte
	Headers    http.Header
}

type HTMLElement struct {
	Request *Request
	attr    string
	value   string
}

func (e *HTMLElement) Attr(name string) string {
	if strings.EqualFold(name, e.attr) {
		return e.value
	}
	return ""
}
