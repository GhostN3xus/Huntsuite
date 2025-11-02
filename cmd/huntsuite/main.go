package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/GhostN3xus/Huntsuite/pkg/core"
	"github.com/GhostN3xus/Huntsuite/pkg/recon"
	"github.com/GhostN3xus/Huntsuite/pkg/validator"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "scan":
		if err := runScan(args); err != nil {
			fmt.Fprintf(os.Stderr, "scan error: %v\n", err)
			os.Exit(1)
		}
	case "recon":
		if err := runRecon(args); err != nil {
			fmt.Fprintf(os.Stderr, "recon error: %v\n", err)
			os.Exit(1)
		}
	case "validate":
		if err := runValidate(args); err != nil {
			fmt.Fprintf(os.Stderr, "validate error: %v\n", err)
			os.Exit(1)
		}
	default:
		usage()
		os.Exit(1)
	}
}

func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	target := fs.String("t", "", "Target domain or URL")
	workers := fs.Int("w", 50, "Number of concurrent workers")
	output := fs.String("o", "", "Findings output file")
	quiet := fs.Bool("q", false, "Silence info logs")
	timeout := fs.Duration("timeout", 10*time.Minute, "Global scan timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*target) == "" {
		return errors.New("target is required")
	}
	engine := core.NewEngine()
	engine.SetWorkers(*workers)
	engine.SetOutput(*output)
	engine.SetQuiet(*quiet)
	engine.SetTimeout(*timeout)
	engine.Scan(*target, "")
	return nil
}

func runRecon(args []string) error {
	fs := flag.NewFlagSet("recon", flag.ContinueOnError)
	target := fs.String("t", "", "Target domain")
	output := fs.String("o", "", "Output file for subdomains")
	wordlist := fs.String("w", "", "Custom wordlist path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*target) == "" {
		return errors.New("target is required")
	}
	r := recon.NewSimpleRecon()
	subs := r.EnumSubdomains(*target, *wordlist, 60)
	if *output != "" {
		if err := os.WriteFile(*output, []byte(strings.Join(subs, "\n")), 0o644); err != nil {
			return err
		}
	}
	for _, sub := range subs {
		fmt.Println(sub)
	}
	return nil
}

func runValidate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	target := fs.String("t", "", "Target URL")
	param := fs.String("param", "huntsuite", "Parameter name to probe")
	dbPath := fs.String("o", "", "Findings database path")
	useOOB := fs.Bool("oob", true, "Enable OOB confirmation")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*target) == "" {
		return errors.New("target is required")
	}
	store, err := validator.InitDB(*dbPath)
	if err != nil {
		return err
	}
	if *useOOB {
		finding, err := validator.ProbeSSRF(store, *target, *param)
		if err != nil {
			return err
		}
		fmt.Printf("Stored finding #%d of type %s\n", finding.ID, finding.Type)
	} else {
		fmt.Println("OOB validation disabled; no probes executed")
	}
	return nil
}

func usage() {
	fmt.Println("HUNTSUITE offensive toolkit")
	fmt.Println("Usage:")
	fmt.Println("  huntsuite scan -t <target> [-w workers] [-o findings.json] [-q] [--timeout duration]")
	fmt.Println("  huntsuite recon -t <domain> [-o subs.txt] [-w wordlist]")
	fmt.Println("  huntsuite validate -t <url> [--param name] [-o findings.json]")
}
