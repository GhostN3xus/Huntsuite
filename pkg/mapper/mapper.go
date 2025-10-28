package mapper

import (
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var hrefRe = regexp.MustCompile(`(?i)href=["']([^"'#]+)["']`)

// SiteMapper faz o mapeamento de links internos de um site
type SiteMapper struct{}

// NewSiteMapper cria uma nova instância do crawler
func NewSiteMapper() *SiteMapper { return &SiteMapper{} }

// Crawl percorre recursivamente links internos (mesmo domínio)
func (m *SiteMapper) Crawl(start string, timeout time.Duration) {
	log.Printf("[mapper] start crawl %s", start)
	client := &http.Client{Timeout: timeout}
	parsed, err := url.Parse(start)
	if err != nil {
		log.Printf("[mapper] parse error: %v", err)
		return
	}

	queue := []string{start}
	seen := map[string]bool{start: true}

	for len(queue) > 0 {
		u := queue[0]
		queue = queue[1:]
		log.Printf("[mapper] fetching: %s", u)
		resp, err := client.Get(u)
		if err != nil {
			log.Printf("[mapper] fetch error: %v", err)
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			log.Printf("[mapper] read error: %v", err)
			continue
		}
		log.Printf("[mapper] %s -> %d bytes", u, len(body))

		matches := hrefRe.FindAllSubmatch(body, -1)
		for _, m := range matches {
			href := strings.TrimSpace(string(m[1]))
			if href == "" {
				continue
			}
			abs, err := url.Parse(href)
			if err != nil || (abs.Scheme == "" && abs.Host == "") {
				abs = parsed.ResolveReference(&url.URL{Path: href})
			}
			if abs == nil {
				continue
			}
			if abs.Hostname() == parsed.Hostname() {
				u2 := abs.String()
				if !seen[u2] {
					seen[u2] = true
					queue = append(queue, u2)
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}

	log.Printf("[mapper] crawl finished; found %d pages", len(seen))
}
