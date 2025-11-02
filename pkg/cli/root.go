package cli

import (
	"context"
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

	"huntsuite/pkg/config"
	"huntsuite/pkg/logging"
	"huntsuite/pkg/output"
	"huntsuite/pkg/report"
	pkgRuntime "huntsuite/pkg/runtime"
	"huntsuite/pkg/scanner"
	"huntsuite/pkg/storage/sqlite"
)

const version = "1.0.0"

// Execute parses CLI arguments and runs the selected subcommand.
func Execute() error {
	if len(os.Args) < 2 {
		usage()
		return nil
	}

	global := flag.NewFlagSet("huntsuite", flag.ContinueOnError)
	configPath := global.String("config", "", "Path to configuration file")
	quiet := global.Bool("quiet", false, "Only display findings and errors")
	verbose := global.Bool("verbose", false, "Verbose logging")
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

	output.PrintBanner(version)
	logger.Info("configuration loaded", logging.Fields{"path": cfgPath})

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
	target := fs.String("target", "", "Target URL or host")
	scannersArg := fs.String("scanners", "xss,sqli,ssrf", "Comma separated list of scanners to run")
	oobDomain := fs.String("oob-domain", "", "Out-of-band domain for SSRF validation")
	delay := fs.Duration("delay", cfg.Scanning.RequestDelay, "Delay between payload injections")
	proxyOverride := fs.String("proxy", "", "Override HTTP proxy for this scan")
	var headerArgs headerFlag
	fs.Var(&headerArgs, "header", "Additional request header in 'Key: Value' format (repeatable)")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *target == "" {
		return errors.New("--target is required")
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

	localClient := &http.Client{Timeout: client.Timeout, Transport: transport}
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

	enabled := map[string]bool{"xss": true, "sqli": true, "ssrf": true}
	if *scannersArg != "" {
		for k := range enabled {
			enabled[k] = false
		}
		tokens := strings.Split(*scannersArg, ",")
		for _, token := range tokens {
			token = strings.TrimSpace(token)
			if token != "" {
				enabled[strings.ToLower(token)] = true
			}
		}
	}

	logger.Info("scan starting", logging.Fields{"target": fullTarget, "scanners": *scannersArg})

	opts := scanner.Options{
		Target:     fullTarget,
		OOBDomain:  *oobDomain,
		EnableXSS:  enabled["xss"],
		EnableSQLi: enabled["sqli"],
		EnableSSRF: enabled["ssrf"],
		Timeout:    client.Timeout,
		UserAgent:  cfg.Scanning.UserAgent,
		Delay:      *delay,
		Headers:    cloneHTTPHeader(combinedHeaders),
	}

	if err := engine.Run(ctx, opts); err != nil {
		logger.Error("scan failed", logging.Fields{"error": err})
		return err
	}

	logger.Info("scan completed", logging.Fields{})
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

func usage() {
	fmt.Println(`HuntSuite - Professional Bug Hunting Toolkit

Usage:
  huntsuite [global options] <command> [command options]

Commands:
  scan       Execute vulnerability scanners against a target
  findings   List findings stored for a scan
  report     Generate a Markdown report for a scan

Global Options:
  --config <path>   Configuration file path
  --quiet           Minimal console output
  --verbose         Verbose console output
  --debug           Debug console output`)
}
