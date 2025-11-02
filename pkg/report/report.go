package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	htmlTemplate "html/template"
	"os"
	"path/filepath"
	"strings"
	textTemplate "text/template"
	"time"

	"huntsuite/pkg/storage/sqlite"
)

const findingTemplate = `## {{.Type | upper}} in {{.TargetURL}}

**Severity**: {{.Severity}}
**CVSS Score**: {{.CVSS}}

### Description
{{.Description}}

### Steps to Reproduce
1. Launch HuntSuite scan targeting {{.TargetURL}}
2. Inject the payload in parameter {{.Parameter}}
3. Observe the behaviour detailed below

### Proof of Concept
    {{.PoC}}

### Evidence
{{.Evidence}}

### Impact
{{.Impact}}

### Remediation
{{.Remediation}}

---
`

var tmpl = textTemplate.Must(textTemplate.New("finding").Funcs(textTemplate.FuncMap{
	"upper": strings.ToUpper,
}).Parse(findingTemplate))

const htmlReportTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>HuntSuite Scan Report</title>
  <style>
    :root { color-scheme: dark; font-family: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    * { box-sizing: border-box; }
    body { margin: 0; background: radial-gradient(circle at top, #1e293b, #0f172a 60%, #020617); color: #e2e8f0; }
    a { color: inherit; }
    .container { max-width: 960px; margin: 0 auto; padding: 3rem 1.75rem 4rem; }
    header { text-align: center; margin-bottom: 2.75rem; }
    header h1 { font-size: 2.4rem; letter-spacing: 0.08em; text-transform: uppercase; margin-bottom: 0.35rem; }
    header p { margin: 0.2rem 0; color: #94a3b8; font-size: 1rem; }
    .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1.2rem; margin-bottom: 2.5rem; }
    .summary-card { background: rgba(15, 23, 42, 0.78); border: 1px solid rgba(148, 163, 184, 0.25); border-radius: 16px; padding: 1.3rem 1.5rem; box-shadow: 0 22px 38px rgba(15, 23, 42, 0.45); }
    .summary-card span { display: block; font-size: 0.75rem; letter-spacing: 0.12em; text-transform: uppercase; color: #64748b; margin-bottom: 0.4rem; }
    .summary-card strong { font-size: 1.1rem; color: #e2e8f0; }
    .finding { background: rgba(15, 23, 42, 0.88); border: 1px solid rgba(59, 130, 246, 0.25); border-radius: 18px; padding: 1.75rem; margin-bottom: 1.75rem; box-shadow: 0 26px 45px rgba(2, 6, 23, 0.55); }
    .finding h2 { margin-top: 0; font-size: 1.45rem; margin-bottom: 0.4rem; }
    .meta { display: flex; flex-wrap: wrap; gap: 0.6rem; margin-bottom: 1.1rem; }
    .badge { display: inline-flex; align-items: center; justify-content: center; padding: 0.3rem 0.85rem; border-radius: 999px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.08em; background: rgba(148, 163, 184, 0.16); color: #e2e8f0; }
    .severity-critical { background: linear-gradient(120deg, #ef4444, #b91c1c); color: #fff; }
    .severity-high { background: linear-gradient(120deg, #f97316, #c2410c); color: #fff; }
    .severity-medium { background: linear-gradient(120deg, #facc15, #ca8a04); color: #0f172a; }
    .severity-low { background: linear-gradient(120deg, #0ea5e9, #2563eb); color: #f8fafc; }
    .severity-info { background: linear-gradient(120deg, #94a3b8, #64748b); color: #0f172a; }
    p { line-height: 1.6; margin: 0; }
    dl { display: grid; grid-template-columns: minmax(140px, 200px) 1fr; gap: 0.55rem 1.4rem; margin: 1.6rem 0 0; }
    dt { font-weight: 600; color: #94a3b8; }
    dd { margin: 0; }
    pre { background: rgba(15, 23, 42, 0.92); border: 1px solid rgba(148, 163, 184, 0.25); border-radius: 14px; padding: 1rem 1.25rem; overflow-x: auto; font-size: 0.85rem; line-height: 1.55; color: #f8fafc; }
    code { font-family: "JetBrains Mono", "Fira Code", monospace; }
    footer { text-align: center; color: #64748b; margin-top: 3.2rem; font-size: 0.85rem; }
    @media (max-width: 760px) {
      .container { padding: 2.25rem 1.35rem 3rem; }
      dl { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>HuntSuite Scan Report</h1>
      <p>Resultados consolidados gerados pelo engine de varredura</p>
    </header>
    <div class="summary-grid">
      <div class="summary-card"><span>Target</span><strong>{{.Target}}</strong></div>
      <div class="summary-card"><span>Scan ID</span><strong>#{{.ScanID}}</strong></div>
      <div class="summary-card"><span>Generated</span><strong>{{formatTime .Generated}}</strong></div>
      <div class="summary-card"><span>Total findings</span><strong>{{.TotalFindings}}</strong></div>
    </div>
    {{if .HasFindings}}
      {{range .Findings}}
      <section class="finding">
        <h2>{{.Title}}</h2>
        <div class="meta">
          <span class="badge severity-{{.SeverityClass}}">{{.Severity}}</span>
          <span class="badge">{{.Type}}</span>
          {{if .CVSS}}<span class="badge">CVSS {{.CVSS}}</span>{{end}}
        </div>
        <p>{{.Description}}</p>
        <dl>
          <dt>Parameter</dt><dd><code>{{.Parameter}}</code></dd>
          <dt>Evidence</dt><dd>{{.Evidence}}</dd>
          <dt>Proof of Concept</dt><dd><pre>{{.PoC}}</pre></dd>
          <dt>Impact</dt><dd>{{.Impact}}</dd>
          <dt>Remediation</dt><dd>{{.Remediation}}</dd>
        </dl>
      </section>
      {{end}}
    {{else}}
      <section class="finding">
        <h2>Nenhum achado registrado</h2>
        <p>O scan foi executado com sucesso, porém nenhuma vulnerabilidade foi identificada para os parâmetros analisados.</p>
      </section>
    {{end}}
    <footer>Relatório gerado automaticamente por HuntSuite.</footer>
  </div>
</body>
</html>`

var htmlTmpl = htmlTemplate.Must(htmlTemplate.New("html-report").Funcs(htmlTemplate.FuncMap{
	"formatTime": func(t time.Time) string { return t.Format(time.RFC3339) },
}).Parse(htmlReportTemplate))

type htmlFinding struct {
	Title         string
	Type          string
	Severity      string
	SeverityClass string
	CVSS          string
	Description   string
	Parameter     string
	Evidence      string
	PoC           string
	Impact        string
	Remediation   string
}

type htmlReportData struct {
	ScanID        int64
	Target        string
	Generated     time.Time
	Findings      []htmlFinding
	HasFindings   bool
	TotalFindings int
}

// MarkdownFinding represents the data fed to the Markdown template.
type MarkdownFinding struct {
	Type        string
	TargetURL   string
	Severity    string
	CVSS        string
	Description string
	Parameter   string
	PoC         string
	Evidence    string
	Impact      string
	Remediation string
}

// WriteMarkdownReport renders a markdown report containing the provided findings.
func WriteMarkdownReport(outputDir string, scan *sqlite.Scan, target *sqlite.Target, findings []sqlite.Finding) (string, error) {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return "", err
	}

	var buf bytes.Buffer
	header := fmt.Sprintf("# HuntSuite Scan Report\n\nTarget: %s\nScan ID: %d\nGenerated: %s\n\n---\n\n", target.Name, scan.ID, time.Now().Format(time.RFC3339))
	buf.WriteString(header)

	if len(findings) == 0 {
		buf.WriteString("No findings were recorded for this scan.\n")
	}

	for _, f := range findings {
		data := MarkdownFinding{
			Type:        f.Type,
			TargetURL:   target.Name,
			Severity:    strings.ToUpper(f.Severity),
			CVSS:        formatCVSS(f.CVSS),
			Description: coalesce(ptrValue(f.Description), "No description available."),
			Parameter:   inferParameter(f.Title),
			PoC:         coalesce(ptrValue(f.PoC), "N/A"),
			Evidence:    coalesce(ptrValue(f.Evidence), "N/A"),
			Impact:      defaultImpact(f.Type),
			Remediation: defaultRemediation(f.Type),
		}
		if err := tmpl.Execute(&buf, data); err != nil {
			return "", err
		}
	}

	filename := filepath.Join(outputDir, fmt.Sprintf("scan-%d-report.md", scan.ID))
	if err := os.WriteFile(filename, buf.Bytes(), 0o644); err != nil {
		return "", err
	}
	return filename, nil
}

// WriteHTMLReport produces an HTML representation of the scan report.
func WriteHTMLReport(outputDir string, scan *sqlite.Scan, target *sqlite.Target, findings []sqlite.Finding) (string, error) {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return "", err
	}

	data := htmlReportData{
		ScanID:        scan.ID,
		Target:        target.Name,
		Generated:     time.Now(),
		Findings:      make([]htmlFinding, 0, len(findings)),
		HasFindings:   len(findings) > 0,
		TotalFindings: len(findings),
	}

	for _, f := range findings {
		severity := strings.ToUpper(f.Severity)
		finding := htmlFinding{
			Title:         f.Title,
			Type:          strings.ToUpper(f.Type),
			Severity:      severity,
			SeverityClass: strings.ToLower(severity),
			CVSS:          formatCVSS(f.CVSS),
			Description:   coalesce(ptrValue(f.Description), "No description available."),
			Parameter:     inferParameter(f.Title),
			Evidence:      coalesce(ptrValue(f.Evidence), "N/A"),
			PoC:           coalesce(ptrValue(f.PoC), "N/A"),
			Impact:        defaultImpact(f.Type),
			Remediation:   defaultRemediation(f.Type),
		}
		data.Findings = append(data.Findings, finding)
	}

	var buf bytes.Buffer
	if err := htmlTmpl.Execute(&buf, data); err != nil {
		return "", err
	}

	path := filepath.Join(outputDir, fmt.Sprintf("scan-%d-report.html", scan.ID))
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

type jsonReportFinding struct {
	Title       string `json:"title"`
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	CVSS        string `json:"cvss"`
	Description string `json:"description"`
	Parameter   string `json:"parameter"`
	PoC         string `json:"poc"`
	Evidence    string `json:"evidence"`
	Impact      string `json:"impact"`
	Remediation string `json:"remediation"`
}

type jsonReport struct {
	ScanID    int64               `json:"scan_id"`
	Target    string              `json:"target"`
	Generated time.Time           `json:"generated_at"`
	Summary   *string             `json:"summary,omitempty"`
	Status    string              `json:"status"`
	Findings  []jsonReportFinding `json:"findings"`
}

// WriteJSONScanReport writes a JSON file describing the scan and associated findings.
func WriteJSONScanReport(outputDir string, scan *sqlite.Scan, target *sqlite.Target, findings []sqlite.Finding) (string, error) {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return "", err
	}

	report := jsonReport{
		ScanID:    scan.ID,
		Target:    target.Name,
		Generated: time.Now(),
		Summary:   scan.Summary,
		Status:    scan.Status,
		Findings:  make([]jsonReportFinding, 0, len(findings)),
	}

	for _, f := range findings {
		report.Findings = append(report.Findings, jsonReportFinding{
			Title:       f.Title,
			Type:        f.Type,
			Severity:    strings.ToUpper(f.Severity),
			CVSS:        formatCVSS(f.CVSS),
			Description: coalesce(ptrValue(f.Description), "No description available."),
			Parameter:   inferParameter(f.Title),
			PoC:         coalesce(ptrValue(f.PoC), "N/A"),
			Evidence:    coalesce(ptrValue(f.Evidence), "N/A"),
			Impact:      defaultImpact(f.Type),
			Remediation: defaultRemediation(f.Type),
		})
	}

	path := filepath.Join(outputDir, fmt.Sprintf("scan-%d-report.json", scan.ID))
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return "", err
	}
	defer file.Close()

	enc := json.NewEncoder(file)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		return "", err
	}
	return path, nil
}

func formatCVSS(val *float64) string {
	if val == nil {
		return "N/A"
	}
	return fmt.Sprintf("%.1f", *val)
}

func coalesce(val string, fallback string) string {
	if strings.TrimSpace(val) == "" {
		return fallback
	}
	return val
}

func ptrValue(val *string) string {
	if val == nil {
		return ""
	}
	return *val
}

func inferParameter(title string) string {
	parts := strings.Fields(title)
	if len(parts) == 0 {
		return "unknown"
	}
	last := parts[len(parts)-1]
	last = strings.Trim(last, "`\"')(")
	return last
}

func defaultImpact(scannerType string) string {
	switch strings.ToLower(scannerType) {
	case "xss":
		return "An attacker can execute arbitrary JavaScript in the victim's browser, leading to credential theft or session hijacking."
	case "sqli":
		return "An attacker can manipulate database queries leading to data leakage, authentication bypass or remote code execution."
	case "ssrf":
		return "An attacker may coerce the application to issue arbitrary HTTP requests to internal resources, potentially exposing sensitive services."
	default:
		return "The issue can be exploited to impact confidentiality, integrity or availability of the application."
	}
}

func defaultRemediation(scannerType string) string {
	switch strings.ToLower(scannerType) {
	case "xss":
		return "Ensure output encoding and input validation is enforced for all user-supplied data before rendering in HTML contexts."
	case "sqli":
		return "Use parameterised queries or stored procedures and avoid direct concatenation of user input in SQL statements."
	case "ssrf":
		return "Validate and restrict user supplied URLs, block access to internal IP ranges and implement allow-lists."
	default:
		return "Apply appropriate security controls and input validation to mitigate this vulnerability."
	}
}

// WriteJSONReport serialises arbitrary data into a timestamped JSON file under reports/.
func WriteJSONReport(prefix string, data any) string {
	if err := os.MkdirAll("reports", 0o755); err != nil {
		return ""
	}
	path := filepath.Join("reports", fmt.Sprintf("%s-%s.json", prefix, time.Now().Format("20060102-150405")))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return ""
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(data); err != nil {
		return ""
	}
	return path
}
