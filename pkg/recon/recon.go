package recon

import (
    "bufio"
    "log"
    "net"
    "os"
    "path/filepath"
    "strings"
)

type SimpleRecon struct{}

func NewSimpleRecon() *SimpleRecon { return &SimpleRecon{} }

func (r *SimpleRecon) EnumSubdomains(domain string, wordlistPath string, timeoutSeconds int) []string {
    found := map[string]bool{}
    if wordlistPath == "" {
        exePath, _ := os.Executable()
        base := filepath.Dir(exePath)
        wordlistPath = filepath.Join(base, "..", "wordlists", "subdomains.txt")
    }
    f, err := os.Open(wordlistPath)
    if err == nil {
        scanner := bufio.NewScanner(f)
        for scanner.Scan() {
            sub := strings.TrimSpace(scanner.Text())
            if sub == "" {
                continue
            }
            host := sub + "." + domain
            addrs, err := net.LookupHost(host)
            if err == nil && len(addrs) > 0 {
                found[host] = true
                log.Printf("[recon] resolved %s -> %v", host, addrs)
            }
        }
        f.Close()
    } else {
        log.Printf("[recon] wordlist not found: %v", err)
    }
    res := []string{}
    for k := range found {
        res = append(res, k)
    }
    return res
}
