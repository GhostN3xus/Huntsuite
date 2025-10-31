package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"
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

var tmpl = template.Must(template.New("finding").Funcs(template.FuncMap{
	"upper": strings.ToUpper,
}).Parse(findingTemplate))

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
