package mapper

import (
    "log"
    "net/http"
    "net/url"
    "time"
    "io"
    "golang.org/x/net/html"
)

type SiteMapper struct{}

func NewSiteMapper() *SiteMapper { return &SiteMapper{} }

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

        doc, err := html.Parse(strings.NewReader(string(body)))
        if err != nil {
            continue
        }
        var f func(*html.Node)
        f = func(n *html.Node) {
            if n.Type == html.ElementNode && n.Data == "a" {
                for _, a := range n.Attr {
                    if a.Key == "href" {
                        href := a.Val
                        abs, err := url.Parse(href)
                        if err != nil || (abs.Scheme == "" && abs.Host == "") {
                            abs = parsed.ResolveReference(&url.URL{Path: href})
                        }
                        if abs.Hostname() == parsed.Hostname() {
                            u2 := abs.String()
                            if !seen[u2] {
                                seen[u2] = true
                                queue = append(queue, u2)
                            }
                        }
                    }
                }
            }
            for c := n.FirstChild; c != nil; c = c.NextSibling {
                f(c)
            }
        }
        f(doc)
        time.Sleep(500 * time.Millisecond)
    }

    log.Printf("[mapper] crawl finished; found %d pages", len(seen))
}
