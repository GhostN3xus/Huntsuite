package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/GhostN3xus/Huntsuite/pkg/config"
	"github.com/GhostN3xus/Huntsuite/pkg/logging"
	"github.com/GhostN3xus/Huntsuite/pkg/output"
	"github.com/GhostN3xus/Huntsuite/pkg/report"
	pkgRuntime "github.com/GhostN3xus/Huntsuite/pkg/runtime"
	"github.com/GhostN3xus/Huntsuite/pkg/scanner"
	"github.com/GhostN3xus/Huntsuite/pkg/storage/sqlite"
)

const version = "1.0.0"

// Execute parses CLI arguments and runs the selected subcommand.
func Execute() error {
	if len(os.Args) < 2 {
		usage()
		return nil
	}

	// Check for help flags
	for _, arg := range os.Args[1:] {
		if arg == "-h" || arg == "--help" || arg == "help" {
			usage()
			return nil
		}
	}

	global := flag.NewFlagSet("huntsuite", flag.ContinueOnError)
	configPath := global.String("config", "", "Path to configuration file")
	quiet := global.Bool("quiet", false, "Only display findings and errors")
	global.BoolVar(quiet, "q", false, "Alias for --quiet")
	verbose := global.Bool("verbose", false, "Verbose logging")
	global.BoolVar(verbose, "v", false, "Alias for --verbose")
	debug := global.Bool("debug", false, "Debug logging")

	if err := global.Parse(os.Args[1:]); err != nil {
		return err
	}

	args := global.Args()
	if len(args) == 0 {
		usage()
		return nil
	}

	command := args[0]
	subArgs := args[1:]

	// Handle special commands that don't need full initialization
	switch command {
	case "version", "--version", "-version":
		fmt.Printf("HuntSuite version %s\n", version)
		return nil
	case "help", "-h", "--help":
		usage()
		return nil
	}

	ctx := pkgRuntime.WithSignalHandler(context.Background())

	cfg, cfgPath, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	runtimeOpts := logging.RuntimeOptions{Quiet: *quiet, Verbose: *verbose, Debug: *debug}
	logger, err := logging.NewLogger(cfg.Logging, runtimeOpts)
	if err != nil {
		return err
	}
	defer logger.Close()

	if !*quiet {
		output.PrintBanner(version)
		logger.Info("configuration loaded", logging.Fields{"path": cfgPath})
	}

	store, err := sqlite.Open(ctx, cfg.Database.Path)
	if err != nil {
		return err
	}
	defer store.Close()

	httpClient := &http.Client{Timeout: time.Duration(cfg.Scanning.TimeoutSeconds) * time.Second}
	if cfg.General.Proxy != "" {
		if proxyURL, err := url.Parse(cfg.General.Proxy); err == nil {
			httpClient.Transport = &http.Transport{Proxy: http.ProxyURL(proxyURL)}
		} else {
			logger.Warn("invalid proxy from config", logging.Fields{"error": err})
		}
	}

	switch command {
	case "scan":
		return runScan(ctx, logger, store, httpClient, cfg, subArgs)
	case "recon":
		return runRecon(ctx, logger, store, cfg, subArgs)
	case "findings":
		return runFindings(ctx, logger, store, subArgs)
	case "report":
		return runReport(ctx, logger, store, cfg, subArgs)
	default:
		usage()
		return fmt.Errorf("unknown command: %s", command)
	}
}

func runScan(ctx context.Context, logger *logging.Logger, store *sqlite.Store, client *http.Client, cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)

	// Main flags with aliases (similar to dirsearch)
	target := fs.String("target", "", "Target URL or host")
	fs.StringVar(target, "u", "", "Alias for --target")

	scannersArg := fs.String("scanners", "all", "Comma separated list of scanners (xss,sqli,ssrf,lfi,xxe,cmdi,open-redirect) or 'all'")
	fs.StringVar(scannersArg, "m", "all", "Alias for --scanners (modules)")

	threads := fs.Int("threads", cfg.Scanning.Threads, "Number of concurrent threads")
	fs.IntVar(threads, "t", cfg.Scanning.Threads, "Alias for --threads")

	timeout := fs.Int("timeout", cfg.Scanning.TimeoutSeconds, "Request timeout in seconds")

	oobDomain := fs.String("oob-domain", "", "Out-of-band domain for SSRF validation")
	delay := fs.Duration("delay", cfg.Scanning.RequestDelay, "Delay between payload injections")

	proxyOverride := fs.String("proxy", "", "Override HTTP proxy for this scan")
	fs.StringVar(proxyOverride, "p", "", "Alias for --proxy")

	output := fs.String("output", "", "Output file for findings (JSON)")
	fs.StringVar(output, "o", "", "Alias for --output")

	var headerArgs headerFlag
	fs.Var(&headerArgs, "header", "Additional request header in 'Key: Value' format (repeatable)")
	fs.Var(&headerArgs, "H", "Alias for --header")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *target == "" {
		return errors.New("target is required (use -u or --target)")
	}

	fullTarget := *target
	if !strings.HasPrefix(fullTarget, "http://") && !strings.HasPrefix(fullTarget, "https://") {
		fullTarget = "https://" + fullTarget
	}

	transport := client.Transport
	if *proxyOverride != "" {
		proxyURL, err := url.Parse(*proxyOverride)
		if err != nil {
			return fmt.Errorf("invalid proxy: %w", err)
		}
		transport = &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	}

	// Update client timeout
	localClient := &http.Client{
		Timeout:   time.Duration(*timeout) * time.Second,
		Transport: transport,
	}

	engine := scanner.NewEngine(store, logger.With(logging.Fields{"component": "engine"}), localClient)

	combinedHeaders := http.Header{}
	for k, v := range cfg.Scanning.Headers {
		if strings.TrimSpace(k) == "" {
			continue
		}
		combinedHeaders.Set(k, v)
	}
	for key, values := range headerArgs.Header() {
		combinedHeaders.Del(key)
		for _, v := range values {
			combinedHeaders.Add(key, v)
		}
	}

	// Parse scanner modules
	enabled := map[string]bool{
		"xss":           false,
		"sqli":          false,
		"ssrf":          false,
		"lfi":           false,
		"xxe":           false,
		"cmdi":          false,
		"open-redirect": false,
	}

	scannerList := strings.ToLower(strings.TrimSpace(*scannersArg))
	if scannerList == "all" {
		for k := range enabled {
			enabled[k] = true
		}
	} else {
		tokens := strings.Split(scannerList, ",")
		for _, token := range tokens {
			token = strings.TrimSpace(token)
			if token != "" {
				if _, exists := enabled[token]; exists {
					enabled[token] = true
				} else {
					logger.Warn("unknown scanner module", logging.Fields{"module": token})
				}
			}
		}
	}

	logger.Info("scan starting", logging.Fields{
		"target":   fullTarget,
		"scanners": *scannersArg,
		"threads":  *threads,
	})

	opts := scanner.Options{
		Target:           fullTarget,
		OOBDomain:        *oobDomain,
		EnableXSS:        enabled["xss"],
		EnableSQLi:       enabled["sqli"],
		EnableSSRF:       enabled["ssrf"],
		EnableLFI:        enabled["lfi"],
		EnableXXE:        enabled["xxe"],
		EnableCMDI:       enabled["cmdi"],
		EnableOpenRedirect: enabled["open-redirect"],
		Timeout:          localClient.Timeout,
		UserAgent:        cfg.Scanning.UserAgent,
		Delay:            *delay,
		Headers:          cloneHTTPHeader(combinedHeaders),
		Threads:          *threads,
	}

	if err := engine.Run(ctx, opts); err != nil {
		logger.Error("scan failed", logging.Fields{"error": err})
		return err
	}

	logger.Info("scan completed", logging.Fields{})

	// Export findings if output specified
	if *output != "" {
		// TODO: Implement findings export
		// For now, we just log that export was requested
		logger.Info("findings export requested", logging.Fields{"path": *output})
		logger.Warn("findings export not yet implemented", logging.Fields{})
	}

	return nil
}

func runFindings(ctx context.Context, logger *logging.Logger, store *sqlite.Store, args []string) error {
	fs := flag.NewFlagSet("findings", flag.ContinueOnError)
	scanID := fs.Int64("scan-id", 0, "Scan identifier")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *scanID == 0 {
		return errors.New("--scan-id is required")
	}
	findings, err := store.FindingsByScan(ctx, *scanID)
	if err != nil {
		return err
	}
	if len(findings) == 0 {
		fmt.Println("No findings recorded for this scan.")
		return nil
	}
	fmt.Println("Severity\tType\tTitle\tEvidence")
	for _, f := range findings {
		fmt.Printf("%s\t%s\t%s\t%s\n", strings.ToUpper(f.Severity), f.Type, f.Title, truncate(ptrValue(f.Evidence), 60))
	}
	logger.Info("findings listed", logging.Fields{"scan_id": *scanID, "count": len(findings)})
	return nil
}

func runReport(ctx context.Context, logger *logging.Logger, store *sqlite.Store, cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	scanID := fs.Int64("scan-id", 0, "Scan identifier")
	outputDir := fs.String("output", "", "Output directory for report")
	format := fs.String("format", "markdown", "Report format (markdown|html|json)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *scanID == 0 {
		return errors.New("--scan-id is required")
	}
	scan, err := store.GetScan(ctx, *scanID)
	if err != nil {
		return err
	}
	target, err := store.GetTarget(ctx, scan.TargetID)
	if err != nil {
		return err
	}
	findings, err := store.FindingsByScan(ctx, *scanID)
	if err != nil {
		return err
	}
	dir := *outputDir
	if dir == "" {
		dir = filepath.Join(cfg.General.DataDir, "reports")
	}
	formatVal := strings.ToLower(strings.TrimSpace(*format))
	var (
		path   string
		genErr error
	)
	switch formatVal {
	case "markdown", "md":
		path, genErr = report.WriteMarkdownReport(dir, scan, target, findings)
	case "html":
		path, genErr = report.WriteHTMLReport(dir, scan, target, findings)
	case "json":
		path, genErr = report.WriteJSONScanReport(dir, scan, target, findings)
	default:
		return fmt.Errorf("unsupported report format: %s", formatVal)
	}
	if genErr != nil {
		return genErr
	}
	fmt.Println("Report saved to", path)
	logger.Info("report generated", logging.Fields{"path": path, "format": formatVal})
	return nil
}

type headerFlag struct {
	header http.Header
}

func (h *headerFlag) String() string {
	if h == nil || h.header == nil {
		return ""
	}
	keys := make([]string, 0, len(h.header))
	for k := range h.header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s: %s", k, strings.Join(h.header[k], "; ")))
	}
	return strings.Join(parts, ", ")
}

func (h *headerFlag) Set(value string) error {
	if h.header == nil {
		h.header = http.Header{}
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	parts := strings.SplitN(value, ":", 2)
	if len(parts) != 2 {
		parts = strings.SplitN(value, "=", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid header %q", value)
		}
	}
	key := http.CanonicalHeaderKey(strings.TrimSpace(parts[0]))
	if key == "" {
		return fmt.Errorf("invalid header name in %q", value)
	}
	val := strings.TrimSpace(parts[1])
	h.header.Del(key)
	h.header.Add(key, val)
	return nil
}

func (h *headerFlag) Header() http.Header {
	if h.header == nil {
		h.header = http.Header{}
	}
	return h.header
}

func cloneHTTPHeader(h http.Header) http.Header {
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

func truncate(val string, limit int) string {
	if len(val) <= limit {
		return val
	}
	if limit <= 3 {
		return val[:limit]
	}
	return val[:limit-3] + "..."
}

func ptrValue(val *string) string {
	if val == nil {
		return ""
	}
	return *val
}

func runRecon(ctx context.Context, logger *logging.Logger, store *sqlite.Store, cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("recon", flag.ContinueOnError)

	domain := fs.String("domain", "", "Target domain for reconnaissance")
	fs.StringVar(domain, "d", "", "Alias for --domain")

	wordlist := fs.String("wordlist", "", "Custom wordlist path for subdomain enumeration")
	fs.StringVar(wordlist, "w", "", "Alias for --wordlist")

	output := fs.String("output", "", "Output file for subdomains")
	fs.StringVar(output, "o", "", "Alias for --output")

	threads := fs.Int("threads", 10, "Number of concurrent DNS resolution threads")
	fs.IntVar(threads, "t", 10, "Alias for --threads")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *domain == "" {
		return errors.New("domain is required (use -d or --domain)")
	}

	logger.Info("reconnaissance starting", logging.Fields{"domain": *domain, "threads": *threads})

	// TODO: Implement reconnaissance module
	fmt.Printf("Recon for %s not yet fully implemented\n", *domain)

	return nil
}

func exportFindings(path string, findings []sqlite.Finding) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(findings)
}

func usage() {
	fmt.Println(`
╔═══════════════════════════════════════════════════════════════════════════╗
║                 HuntSuite - Professional Bug Hunting Toolkit                ║
║                           Offensive Security Engine                         ║
╚═══════════════════════════════════════════════════════════════════════════╝

Usage:
  huntsuite [global options] <command> [command options]

Commands:
  scan         Execute vulnerability scanners against a target
  recon        Perform reconnaissance on a domain
  findings     List findings stored for a scan
  report       Generate reports for scan results
  version      Show version information
  help         Show this help message

Global Options:
  --config <path>        Configuration file path
  -q, --quiet            Minimal console output (only findings and errors)
  -v, --verbose          Verbose console output
  --debug                Debug console output (most detailed)

Scan Command:
  huntsuite scan -u <target> [options]

  Required:
    -u, --target <url>     Target URL or host to scan

  Options:
    -m, --scanners <list>  Scanner modules to run (comma-separated)
                           Available: xss,sqli,ssrf,lfi,xxe,cmdi,open-redirect
                           Default: all
    -t, --threads <num>    Number of concurrent threads (default: 50)
    --timeout <seconds>    Request timeout in seconds (default: 20)
    -o, --output <file>    Output file for findings (JSON format)
    -p, --proxy <url>      HTTP proxy URL (e.g., http://127.0.0.1:8080)
    -H, --header <header>  Custom HTTP header (repeatable)
                           Format: "Key: Value" or "Key=Value"
    --oob-domain <domain>  Out-of-band domain for SSRF validation
    --delay <duration>     Delay between requests (e.g., 100ms, 1s)

  Examples:
    huntsuite scan -u https://example.com
    huntsuite scan -u example.com -m xss,sqli -t 30 -o findings.json
    huntsuite scan -u https://target.com -p http://127.0.0.1:8080 -H "Cookie: session=abc"

Recon Command:
  huntsuite recon -d <domain> [options]

  Required:
    -d, --domain <domain>  Target domain for reconnaissance

  Options:
    -w, --wordlist <file>  Custom wordlist path
    -t, --threads <num>    Number of DNS resolution threads (default: 10)
    -o, --output <file>    Output file for discovered subdomains

  Examples:
    huntsuite recon -d example.com
    huntsuite recon -d example.com -w custom_subs.txt -o subdomains.txt

Findings Command:
  huntsuite findings --scan-id <id>

  Show findings for a specific scan ID.

Report Command:
  huntsuite report --scan-id <id> [options]

  Options:
    --format <type>        Report format: markdown, html, json (default: markdown)
    --output <directory>   Output directory for report

For more information, visit: https://github.com/GhostN3xus/Huntsuite
`)
}
