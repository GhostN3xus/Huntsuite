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
  <title>HuntSuite Scan Report</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 2rem; color: #111; }
    h1 { margin-bottom: 0.2rem; }
    h2 { color: #b00020; margin-bottom: 0.2rem; }
    .meta { color: #444; margin-bottom: 1.5rem; }
    .finding { border: 1px solid #ccc; border-radius: 8px; padding: 1.2rem; margin-bottom: 1.2rem; background: #fafafa; }
    .badge { display: inline-block; padding: 0.1rem 0.6rem; border-radius: 999px; font-size: 0.8rem; margin-right: 0.4rem; }
    .severity-critical { background: #780000; color: #fff; }
    .severity-high { background: #b00020; color: #fff; }
    .severity-medium { background: #c77d00; color: #fff; }
    .severity-low { background: #0b7285; color: #fff; }
    .severity-info { background: #495057; color: #fff; }
    pre { background: #272822; color: #f8f8f2; padding: 0.8rem; border-radius: 6px; overflow-x: auto; }
    dl { display: grid; grid-template-columns: max-content 1fr; grid-gap: 0.4rem 1rem; }
    dt { font-weight: 600; }
  </style>
</head>
<body>
  <h1>HuntSuite Scan Report</h1>
  <div class="meta">
    <div><strong>Target:</strong> {{.Target}}</div>
    <div><strong>Scan ID:</strong> {{.ScanID}}</div>
    <div><strong>Generated:</strong> {{formatTime .Generated}}</div>
    <div><strong>Total findings:</strong> {{.TotalFindings}}</div>
  </div>
  {{if .HasFindings}}
    {{range .Findings}}
    <section class="finding">
      <h2>{{.Title}}</h2>
      <div>
        <span class="badge severity-{{.SeverityClass}}">{{.Severity}}</span>
        <span class="badge">{{.Type}}</span>
        {{if .CVSS}}<span class="badge">CVSS {{.CVSS}}</span>{{end}}
      </div>
      <p>{{.Description}}</p>
      <dl>
        <dt>Parameter</dt><dd>{{.Parameter}}</dd>
        <dt>Evidence</dt><dd>{{.Evidence}}</dd>
        <dt>Proof of Concept</dt><dd><pre>{{.PoC}}</pre></dd>
        <dt>Impact</dt><dd>{{.Impact}}</dd>
        <dt>Remediation</dt><dd>{{.Remediation}}</dd>
      </dl>
    </section>
    {{end}}
  {{else}}
    <p>No findings were recorded for this scan.</p>
  {{end}}
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
