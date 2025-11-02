package mapper

import (
	"errors"
	"log"
	"net/url"
	"sync"
	"time"

	"github.com/gocolly/colly/v2"
)

// SiteMapper faz o mapeamento de links internos de um site
type SiteMapper struct{}

// NewSiteMapper cria uma nova instância do crawler
func NewSiteMapper() *SiteMapper { return &SiteMapper{} }

// Crawl percorre recursivamente links internos (mesmo domínio)
func (m *SiteMapper) Crawl(start string, timeout time.Duration) {
	if start == "" {
		return
	}
	parsed, err := url.Parse(start)
	if err != nil {
		log.Printf("[mapper] parse error: %v", err)
		return
	}
	if parsed.Scheme == "" {
		parsed.Scheme = "https"
	}
	base := parsed.String()

	collector := colly.NewCollector(
		colly.AllowedDomains(parsed.Hostname()),
		colly.MaxDepth(3),
		colly.Async(true),
	)
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	collector.SetRequestTimeout(timeout)
	collector.Limit(&colly.LimitRule{DomainGlob: "*", Parallelism: 4, RandomDelay: 250 * time.Millisecond})

	visited := struct {
		sync.Mutex
		urls map[string]struct{}
		cnt  int
	}{urls: map[string]struct{}{}}

	collector.OnRequest(func(r *colly.Request) {
		visited.Lock()
		if visited.cnt >= 500 {
			visited.Unlock()
			r.Abort()
			return
		}
		if _, ok := visited.urls[r.URL.String()]; ok {
			visited.Unlock()
			r.Abort()
			return
		}
		visited.urls[r.URL.String()] = struct{}{}
		visited.cnt++
		visited.Unlock()
		log.Printf("[mapper] visiting: %s", r.URL.String())
	})

	collector.OnHTML("a[href]", func(e *colly.HTMLElement) {
		enqueue(e, "href")
	})
	collector.OnHTML("link[href]", func(e *colly.HTMLElement) {
		enqueue(e, "href")
	})
	collector.OnHTML("script[src]", func(e *colly.HTMLElement) {
		enqueue(e, "src")
	})
	collector.OnHTML("form[action]", func(e *colly.HTMLElement) {
		enqueue(e, "action")
	})

	collector.OnError(func(r *colly.Response, err error) {
		log.Printf("[mapper] error %s: %v", r.Request.URL, err)
	})

	collector.OnResponse(func(r *colly.Response) {
		log.Printf("[mapper] %s -> %d", r.Request.URL.String(), r.StatusCode)
	})

	if err := collector.Visit(base); err != nil {
		log.Printf("[mapper] visit error: %v", err)
	}
	collector.Wait()
	visited.Lock()
	total := len(visited.urls)
	visited.Unlock()
	log.Printf("[mapper] crawl finished; discovered %d unique pages", total)
}

func enqueue(e *colly.HTMLElement, attr string) {
	raw := e.Attr(attr)
	if raw == "" {
		return
	}
	next := e.Request.AbsoluteURL(raw)
	if next == "" {
		return
	}
	if err := e.Request.Visit(next); err != nil {
		if !errors.Is(err, colly.ErrAlreadyVisited) {
			log.Printf("[mapper] enqueue error: %v", err)
		}
	}
}
