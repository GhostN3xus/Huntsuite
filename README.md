```
██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██╗   ██╗███████╗████████╗
██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██║   ██║██╔════╝╚══██╔══╝
███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██║   ██║█████╗     ██║   
██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ╚██╗ ██╔╝██╔══╝     ██║   
██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗ ╚████╔╝ ███████╗   ██║   
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝  ╚═══╝  ╚══════╝   ╚═╝   
```

HuntSuite is an offensive automation engine focused on high-signal reconnaissance and validation. The default scan pipeline runs DNS reconnaissance, structural mapping, sensitive file disclosure probing, and automatic OOB validation (SSRF, Blind XSS, Log4Shell) in sequence. Everything is built to run headless on Linux with Go 1.21+.

## Installation

```bash
go install github.com/GhostN3xus/Huntsuite@latest
```

The resulting binary (`huntsuite`) exposes three primary commands:

| Command | Description |
|---------|-------------|
| `scan`  | Executes the full engine (recon → mapper → disclosure → validators) with a fixed worker pool (default 50) and a 10 minute global timeout. Findings are appended to `~/.huntsuite/findings.json` with file locking. |
| `recon` | Performs wordlist-based subdomain enumeration with wildcard detection and writes the result set to stdout or an optional file. |
| `validate` | Fires an OOB-backed SSRF probe against a single target URL and stores confirmed interactions. |

### Examples

```bash
huntsuite scan -t example.com -w 100 -o findings.json
huntsuite recon -t example.com -o subs.txt
huntsuite validate -t https://sub.example.com --oob
```

### Global Flags

* `-t` / `--target` — primary target (domain or URL).
* `-w` — number of workers for the scan pipeline.
* `-o` — custom output path (defaults to `~/.huntsuite/findings.json`).
* `-q` — quiet mode (logs suppressed, errors still emitted).
* `--timeout` — overrides the 10 minute global scan timeout.
* `--oob` — toggle OOB validation when using the `validate` command.

## Architecture Overview

* **Recon:** `pkg/recon` embeds a bundled subdomain wordlist (`pkg/recon/wordlists/subdomains.txt`), resolves entries with a custom DNS resolver, and filters wildcard responses by testing three random subdomains per run.
* **Mapper:** `pkg/mapper` relies on a lightweight, gocolly-compatible crawler (bundled under `third_party/gocolly`) with depth 3 and a hard cap of 500 unique pages, constrained to the base domain.
* **Disclosure:** `pkg/disclosure` aggressively hits 30+ high-value paths with a dedicated HTTP client (`huntsuite/1.0` user agent, 8s timeout, 2× retry backoff) and writes reports into `~/.huntsuite/`.
* **Validators & OOB:** `pkg/validator` integrates with a vendored Interactsh client (`third_party/interactsh/pkg/client`). Each scan session generates a unique subdomain, polls until timeout or 100 interactions, and classifies tokens (`ssrf-*`, `bxss-*`, `log4j-*`) to confirm findings automatically while persisting JSON lines with a `sync.Mutex`.
* **Engine:** `pkg/core` orchestrates the full pipeline with a fixed worker pool (50 workers by default) and structured JSON logging to stdout. Results are appended to `~/.huntsuite/findings.json` and all network stages respect the global timeout window.

## Development

### Prerequisites

* Go 1.21+
* Linux x86_64 environment

### Running Tests

```bash
go test ./...
```

The suite includes mocks for DNS, HTTP, and the OOB client so the tests are deterministic and network-free.

### Building the Binary

```bash
go build ./cmd/huntsuite
```

For release builds matching the acceptance checklist:

```bash
go build -ldflags="-s -w" -o huntsuite ./cmd/huntsuite
```

### Key Outputs

* Logs (JSON) stream to stdout by default (`-q` to silence informational events).
* Findings are appended to `~/.huntsuite/findings.json` (newline-delimited JSON, locked per write).
* Disclosure artifacts are written to `~/.huntsuite/` with timestamped filenames.

---

Use HuntSuite responsibly. Offensive testing must only target assets you own or have explicit permission to assess.
