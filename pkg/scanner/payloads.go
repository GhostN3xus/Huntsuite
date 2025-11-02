package scanner

import (
	"bufio"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

//go:embed xss_payloads.txt
var rawXSSPayloads string

var (
	payloadCache sync.Map
)

func loadPayloadTemplates(kind string, defaults []string) []string {
	combined := append([]string{}, defaults...)
	if extras := readPayloadFile(kind); len(extras) > 0 {
		combined = append(combined, extras...)
	}
	return dedupePayloads(combined)
}

func readPayloadFile(kind string) []string {
	if cached, ok := payloadCache.Load(kind); ok {
		if values, valid := cached.([]string); valid {
			return values
		}
	}
	for _, dir := range payloadDirectories() {
		path := filepath.Join(dir, kind+".txt")
		if lines, err := readPayloadLines(path); err == nil {
			payloadCache.Store(kind, lines)
			return lines
		}
	}
	payloadCache.Store(kind, []string{})
	return nil
}

func readPayloadLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lines := make([]string, 0)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

func payloadDirectories() []string {
	dirs := []string{}
	if env := strings.TrimSpace(os.Getenv("HUNTSUITE_PAYLOAD_DIR")); env != "" {
		dirs = append(dirs, env)
	}
	if exe, err := os.Executable(); err == nil {
		base := filepath.Dir(exe)
		dirs = append(dirs,
			filepath.Join(base, "payloads"),
			filepath.Join(base, "..", "payloads"),
		)
	}
	dirs = append(dirs, "payloads")
	return dirs
}

func dedupePayloads(payloads []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(payloads))
	for _, payload := range payloads {
		p := strings.TrimSpace(payload)
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

func materialisePayload(tpl string, vars map[string]string) string {
	result := tpl
	if vars != nil {
		for key, value := range vars {
			token := "{{" + strings.ToUpper(key) + "}}"
			result = strings.ReplaceAll(result, token, value)
		}
	}
	for strings.Contains(result, "{{RAND}}") {
		result = strings.Replace(result, "{{RAND}}", randomToken(10), 1)
	}
	return result
}

func randomToken(length int) string {
	if length <= 0 {
		length = 8
	}
	bytesNeeded := (length + 1) / 2
	buf := make([]byte, bytesNeeded)
	if _, err := rand.Read(buf); err == nil {
		token := hex.EncodeToString(buf)
		if len(token) > length {
			token = token[:length]
		}
		return token
	}
	fallback := fmt.Sprintf("%d", time.Now().UnixNano())
	if len(fallback) > length {
		return fallback[:length]
	}
	return fallback
}

func defaultXSSPayloads() []string {
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
		payload := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if payload == "" || strings.HasPrefix(payload, "#") {
			continue
		}
		base = append(base, payload)
	}
	return base
}

type booleanPayload struct {
	TruePayload  string
	FalsePayload string
}

type timePayload struct {
	Payload string
	Delay   time.Duration
}

func defaultSQLiPayloads() ([]string, []booleanPayload, []timePayload) {
	errors := []string{"'", "\"", "' OR '1'='1"}
	booleans := []booleanPayload{{TruePayload: "' AND 1=1--", FalsePayload: "' AND 1=2--"}}
	times := []timePayload{{Payload: "' AND SLEEP(5)--", Delay: 5 * time.Second}, {Payload: "' AND pg_sleep(5)--", Delay: 5 * time.Second}}
	return errors, booleans, times
}

func loadSQLiPayloads() ([]string, []booleanPayload, []timePayload) {
	errorPayloads, boolPayloads, timePayloads := defaultSQLiPayloads()
	extras := readPayloadFile("sqli")
	for _, line := range extras {
		fields := strings.Split(line, "|")
		if len(fields) == 0 {
			continue
		}
		category := strings.ToLower(strings.TrimSpace(fields[0]))
		switch category {
		case "error":
			if len(fields) < 2 {
				continue
			}
			payload := strings.TrimSpace(fields[1])
			if payload != "" {
				errorPayloads = append(errorPayloads, payload)
			}
		case "boolean":
			if len(fields) < 3 {
				continue
			}
			truePayload := strings.TrimSpace(fields[1])
			falsePayload := strings.TrimSpace(fields[2])
			if truePayload != "" && falsePayload != "" {
				boolPayloads = append(boolPayloads, booleanPayload{TruePayload: truePayload, FalsePayload: falsePayload})
			}
		case "time":
			if len(fields) < 3 {
				continue
			}
			payload := strings.TrimSpace(fields[1])
			delayStr := strings.TrimSpace(fields[2])
			if payload == "" || delayStr == "" {
				continue
			}
			delay, err := time.ParseDuration(delayStr)
			if err != nil {
				if parsed, convErr := parseSeconds(delayStr); convErr == nil {
					delay = parsed
				} else {
					continue
				}
			}
			timePayloads = append(timePayloads, timePayload{Payload: payload, Delay: delay})
		default:
			payload := strings.TrimSpace(line)
			if payload != "" {
				errorPayloads = append(errorPayloads, payload)
			}
		}
	}
	return dedupePayloads(errorPayloads), dedupeBooleanPayloads(boolPayloads), dedupeTimePayloads(timePayloads)
}

func parseSeconds(val string) (time.Duration, error) {
	if val == "" {
		return 0, errors.New("empty value")
	}
	if !strings.HasSuffix(val, "s") {
		val = val + "s"
	}
	return time.ParseDuration(val)
}

func dedupeBooleanPayloads(payloads []booleanPayload) []booleanPayload {
	seen := map[string]struct{}{}
	out := make([]booleanPayload, 0, len(payloads))
	for _, payload := range payloads {
		key := payload.TruePayload + "||" + payload.FalsePayload
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, payload)
	}
	return out
}

func dedupeTimePayloads(payloads []timePayload) []timePayload {
	seen := map[string]struct{}{}
	out := make([]timePayload, 0, len(payloads))
	for _, payload := range payloads {
		key := fmt.Sprintf("%s|%s", payload.Payload, payload.Delay)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, payload)
	}
	return out
}

func defaultSSRFPayloads() []string {
	return []string{
		"http://{{OOB}}/",
		"https://{{OOB}}/",
		"http://{{OOB}}/ping/{{RAND}}",
		"https://{{OOB}}/fetch/{{RAND}}",
		"gopher://{{OOB}}/_GET%20/{{RAND}}",
	}
}
