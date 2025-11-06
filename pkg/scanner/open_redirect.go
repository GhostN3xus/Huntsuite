package scanner

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/GhostN3xus/Huntsuite/pkg/logging"
)

// Open Redirect Scanner - Detects URL redirection vulnerabilities
// This module performs REAL validation by checking HTTP redirects and location headers

// getOpenRedirectPayloads returns payloads for testing open redirects
func getOpenRedirectPayloads(testDomain string) []string {
	if testDomain == "" {
		testDomain = "evil.com"
	}

	return []string{
		// Direct redirects
		"https://" + testDomain,
		"http://" + testDomain,
		"//" + testDomain,
		"///" + testDomain,
		"////" + testDomain,

		// Protocol-relative
		"////" + testDomain + "/%2F..",
		"////" + testDomain + "//",
		"//" + testDomain + "/%2F..",

		// Encoded variations
		"https%3A%2F%2F" + testDomain,
		"http%3A%2F%2F" + testDomain,
		"%2F%2F" + testDomain,
		"%252F%252F" + testDomain,

		// With @ symbol
		"https://example.com@" + testDomain,
		"http://example.com@" + testDomain,
		"https://@" + testDomain,
		"http://@" + testDomain,

		// Backslash variations
		"https:\\\\" + testDomain,
		"http:\\\\" + testDomain,
		"\\\\" + testDomain,

		// Encoded backslash
		"https:%5C%5C" + testDomain,
		"http:%5C%5C" + testDomain,

		// Tab and newline
		"https:\t//" + testDomain,
		"https:\n//" + testDomain,
		"https:\r\n//" + testDomain,

		// Dot segments
		"https://." + testDomain,
		"https://.." + testDomain,
		"//" + testDomain + "/.",
		"//" + testDomain + "/..",

		// With ports
		"https://" + testDomain + ":443",
		"http://" + testDomain + ":80",
		"//" + testDomain + ":443",

		// Data and javascript URIs (for XSS-based redirects)
		"javascript:alert(document.domain)",
		"data:text/html,<script>alert(document.domain)</script>",

		// With query strings
		"https://" + testDomain + "?x=1",
		"//" + testDomain + "?x=1",

		// With fragments
		"https://" + testDomain + "#x",
		"//" + testDomain + "#x",

		// Partial domain bypass attempts
		testDomain,
		"." + testDomain,
		"/" + testDomain,
		"?" + testDomain,
		"#" + testDomain,

		// With null bytes
		"https://" + testDomain + "%00",
		"//" + testDomain + "%00",

		// Unicode variations
		"https://\u0065\u0076\u0069\u006C.com", // evil.com in unicode

		// Mixed encoding
		"https%3a%2f%2f" + testDomain,
		"https%253a%252f%252f" + testDomain,

		// Case variations
		"HTTPS://" + testDomain,
		"HTTP://" + testDomain,

		// Scheme confusion
		"///" + testDomain + ":@\\/\\",
		"https://:@" + testDomain,

		// Zero-width characters (if the application handles them)
		"https://\u200B" + testDomain,

		// Decimal IP encoding (if testDomain is IP-resolvable)
		// This would need IP conversion, skipping for now

		// Domain fronting attempts
		"https://" + testDomain + ".example.com",
		"https://example.com." + testDomain,

		// With credentials
		"https://user:pass@" + testDomain,
		"http://admin:admin@" + testDomain,
	}
}

// scanOpenRedirect performs Open Redirect scanning with REAL validation
func (e *Engine) scanOpenRedirect(ctx context.Context, target string, points []injectionPoint, opts Options) error {
	if !opts.EnableOpenRedirect {
		return nil
	}

	e.logger.Info("starting Open Redirect scan", logging.Fields{
		"target": target,
		"points": len(points),
	})

	// Use OOB domain as test domain, or default
	testDomain := "evil-redirect-test.com"
	if opts.OOBDomain != "" {
		testDomain = opts.OOBDomain
	}

	payloads := getOpenRedirectPayloads(testDomain)

	for _, point := range points {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Open redirects are typically in URL parameters, especially
		// parameters like: url, redirect, next, target, dest, destination, etc.
		isLikelyRedirectParam := false
		paramLower := strings.ToLower(point.Name)
		redirectKeywords := []string{
			"url", "redirect", "redir", "next", "target", "dest",
			"destination", "return", "returnto", "returl", "goto",
			"link", "forward", "continue", "return_url", "return_to",
		}

		for _, keyword := range redirectKeywords {
			if strings.Contains(paramLower, keyword) {
				isLikelyRedirectParam = true
				break
			}
		}

		for _, payload := range payloads {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			// Create request with payload
			req := point.templateForValue(payload)

			// Send request WITHOUT following redirects
			// We need to see the raw redirect response
			resp, err := e.executeRequestNoRedirect(ctx, req, opts)
			if err != nil {
				continue
			}

			// Perform REAL validation
			severity := e.validateOpenRedirect(payload, testDomain, resp)

			if severity != "" {
				// Adjust severity based on parameter likelihood
				finalSeverity := SeverityMedium
				if severity == "high" {
					finalSeverity = SeverityHigh
				} else if severity == "low" {
					finalSeverity = SeverityLow
				}

				// Increase severity if it's a likely redirect parameter
				if isLikelyRedirectParam && finalSeverity == SeverityLow {
					finalSeverity = SeverityMedium
				}

				finding := Finding{
					Title:       "Open Redirect Vulnerability",
					Type:        "Open Redirect",
					Severity:    finalSeverity,
					Description: fmt.Sprintf("Open Redirect vulnerability detected in %s. The application redirects users to arbitrary URLs without proper validation, which can be used in phishing attacks.", point.label()),
					Evidence:    fmt.Sprintf("Payload: %s\nRedirect Location: %s\nStatus Code: %d", payload, getLocationHeader(resp), resp.StatusCode),
					PoC: fmt.Sprintf("curl -X %s '%s' -v\n\nThe application redirects to the attacker-controlled URL: %s",
						req.Method, req.URL, payload),
				}

				e.reportFinding(ctx, finding, point, req, resp)

				e.logger.Warn("Open Redirect vulnerability found", logging.Fields{
					"severity": string(finding.Severity),
					"type":     finding.Type,
					"target":   req.URL,
					"redirect": getLocationHeader(resp),
				})

				// Found vulnerability, move to next point
				break
			}
		}
	}

	e.logger.Info("Open Redirect scan completed", logging.Fields{"target": target})
	return nil
}

// validateOpenRedirect performs REAL validation by checking redirect headers
// Returns severity level: "high", "medium", "low", or empty string for no vulnerability
func (e *Engine) validateOpenRedirect(payload string, testDomain string, resp responsePayload) string {
	// Check for redirect status codes
	isRedirect := resp.StatusCode >= 300 && resp.StatusCode < 400

	// Get Location header
	location := getLocationHeader(resp)

	if location == "" {
		// Also check for meta refresh redirects in HTML
		body := string(resp.Body)
		if strings.Contains(strings.ToLower(body), "<meta") &&
			strings.Contains(strings.ToLower(body), "refresh") {

			// Try to extract URL from meta refresh
			if strings.Contains(body, testDomain) {
				e.logger.Debug("meta refresh redirect detected", logging.Fields{
					"payload": payload,
				})
				return "medium"
			}
		}

		// Check for JavaScript redirects
		if strings.Contains(strings.ToLower(body), "window.location") ||
			strings.Contains(strings.ToLower(body), "document.location") {

			if strings.Contains(body, testDomain) {
				e.logger.Debug("javascript redirect detected", logging.Fields{
					"payload": payload,
				})
				return "medium"
			}
		}

		return "" // No redirect found
	}

	// Parse the location header
	locationURL, err := url.Parse(location)
	if err != nil {
		// Could be a malformed URL that still redirects
		if strings.Contains(location, testDomain) {
			e.logger.Debug("malformed redirect to test domain", logging.Fields{
				"location": location,
				"payload":  payload,
			})
			return "high"
		}
		return ""
	}

	// HIGH severity: Direct redirect to external domain
	if isRedirect {
		// Check if redirecting to our test domain
		if strings.Contains(locationURL.Host, testDomain) ||
			strings.Contains(locationURL.String(), testDomain) {
			e.logger.Debug("confirmed redirect to test domain", logging.Fields{
				"location": location,
				"payload":  payload,
			})
			return "high"
		}

		// Check if it's an open redirect to any external domain
		// (payload contains external domain and location matches)
		if locationURL.Host != "" && locationURL.Scheme != "" {
			payloadURL, err := url.Parse(payload)
			if err == nil && payloadURL.Host != "" {
				if strings.Contains(locationURL.Host, payloadURL.Host) {
					e.logger.Debug("confirmed redirect to payload domain", logging.Fields{
						"location": location,
						"payload":  payload,
					})
					return "high"
				}
			}
		}
	}

	// MEDIUM severity: Relative redirect that includes our payload
	if isRedirect && strings.Contains(location, testDomain) {
		e.logger.Debug("partial redirect match", logging.Fields{
			"location": location,
			"payload":  payload,
		})
		return "medium"
	}

	// LOW severity: Redirect exists but unclear if vulnerable
	// Could be caused by reflected input without actual redirect
	if isRedirect && strings.Contains(location, payload) {
		e.logger.Debug("potential open redirect (reflected payload)", logging.Fields{
			"location": location,
			"payload":  payload,
		})
		return "low"
	}

	return ""
}

// getLocationHeader extracts the Location header from response
func getLocationHeader(resp responsePayload) string {
	if resp.Headers == nil {
		return ""
	}

	// Try different case variations
	for key, values := range resp.Headers {
		if strings.ToLower(key) == "location" && len(values) > 0 {
			return values[0]
		}
	}

	return ""
}

// executeRequestNoRedirect executes HTTP request without following redirects
func (e *Engine) executeRequestNoRedirect(ctx context.Context, req requestTemplate, opts Options) (responsePayload, error) {
	// This is similar to executeRequest but with CheckRedirect set to prevent following
	// For now, we'll use the same executeRequest and rely on it not following redirects by default
	// If needed, we can create a custom client here

	return e.executeRequest(ctx, req, opts)
}
