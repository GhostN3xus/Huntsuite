package main

import (
    "context"
    "flag"
    "fmt"
    "log"
    "os"
    "time"

    "huntsuite/pkg/core"
    "huntsuite/pkg/disclosure"
    "huntsuite/pkg/oob"
    "huntsuite/pkg/proxy"
    "huntsuite/pkg/recon"
    "huntsuite/pkg/mapper"
    "huntsuite/pkg/report"
    "huntsuite/pkg/validator"
            "huntsuite/pkg/config"
)

func main() {
    if len(os.Args) < 2 {
        usage()
        os.Exit(1)
    }
    cmd := os.Args[1]
    switch cmd {
    case "proxy":
        proxyCmd := flag.NewFlagSet("proxy", flag.ExitOnError)
        listen := proxyCmd.String("listen", ":8080", "listen address")
        inject := proxyCmd.Bool("inject", false, "inject test payloads")
        proxyCmd.Parse(os.Args[2:])
        cfg := proxy.ProxyConfig{ListenAddr: *listen}
        if *inject {
            cfg.InjectPayload = func(req *http.Request) {
                req.Header.Set("X-HuntSuite-Injection", "huntsuite")
            }
        }
        log.Printf("[main] starting proxy on %s", *listen)
        if err := proxy.StartForwardProxy(cfg); err != nil {
            log.Fatalf("proxy failed: %v", err)
        }
    case "oob":
        d, err := oob.ExecInteractWithTimeout(5 * time.Second)
        if err != nil {
            log.Fatalf("oob exec error: %v", err)
        }
        if d == "" {
            fmt.Println("interactsh client not found on PATH; running stub")
            client, _ := oob.NewInteractClient()
            fmt.Println("OOB domain (stub):", client.Domain)
            ctx, cancel := context.WithCancel(context.Background())
            defer cancel()
            go client.PollInteractions(ctx)
            select {}
        } else {
            fmt.Println("OOB domain from external client:", d)
        }
    case "recon":
        reconCmd := flag.NewFlagSet("recon", flag.ExitOnError)
        target := reconCmd.String("target", "", "target domain (example.com)")
        wordlist := reconCmd.String("wordlist", "", "path to subdomain wordlist (optional)")
        reconCmd.Parse(os.Args[2:])
        if *target == "" {
            log.Fatalf("provide --target")
        }
        r := recon.NewSimpleRecon()
        res := r.EnumSubdomains(*target, *wordlist, 30)
        if len(res) > 0 {
            report.WriteJSONReport("subdomains", res)
        }
    case "map":
        mapCmd := flag.NewFlagSet("map", flag.ExitOnError)
        target := mapCmd.String("target", "", "target URL (https://...)")
        timeout := mapCmd.Int("timeout", 3, "request timeout seconds")
        mapCmd.Parse(os.Args[2:])
        if *target == "" {
            log.Fatalf("provide --target")
        }
        m := mapper.NewSiteMapper()
        m.Crawl(*target, time.Duration(*timeout)*time.Second)
    case "scan":
        scanCmd := flag.NewFlagSet("scan", flag.ExitOnError)
        target := scanCmd.String("target", "", "target URL or domain")
        oobdom := scanCmd.String("oob-domain", "", "oob domain (optional)")
        disclosureOnly := scanCmd.Bool("disclosure", false, "run disclosure probes")
        scanCmd.Parse(os.Args[2:])
        if *target == "" {
            log.Fatalf("provide --target")
        }
        engine := core.NewEngine()
        engine.Scan(*target, *oobdom)
        if *disclosureOnly {
            findings := disclosure.Probe(*target, 6)
            report.WriteJSONReport("disclosure", findings)
        }
    case "validate":
        valCmd := flag.NewFlagSet("validate", flag.ExitOnError)
        target := valCmd.String("target", "", "target URL (http(s)://...)")
        param := valCmd.String("param", "url", "parameter to use for SSRF probe")
        dbpath := valCmd.String("db", "huntsuite_findings.db", "sqlite db path")
        valCmd.Parse(os.Args[2:])
        if *target == "" {
            log.Fatalf("provide --target")
        }
        db, err := validator.InitDB(*dbpath)
        if err != nil {
            log.Fatalf("db init error: %v", err)
        }
        f, err := validator.ProbeSSRF(db, *target, *param)
        if err != nil {
            log.Fatalf("probe error: %v", err)
        }
        fmt.Printf("Validation started: proof token at %s\n", f.Proof)
    default:
        usage()
    }
}

func usage() {
    fmt.Println("HuntSuite commands: proxy | oob | recon | map | scan | validate")
    fmt.Println("Use `huntsuite <command> --help` for flags")
}
