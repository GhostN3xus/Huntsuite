package scanner

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/GhostN3xus/Huntsuite/pkg/logging"
)

type formInput struct {
	Name  string
	Value string
}

type discoveredForm struct {
	Method    string
	Action    *url.URL
	Inputs    []formInput
	Enctype   string
	Source    string
	RawAction string
}

var attributeRegexp = regexp.MustCompile(`(?i)([a-z0-9_:-]+)\s*=\s*("[^"]*"|'[^']*')`)
var booleanAttributeTokens = []string{"selected", "checked", "multiple", "disabled", "required"}

func (e *Engine) discoverForms(ctx context.Context, scanID int64, target *url.URL, opts Options) ([]discoveredForm, error) {
	logger := e.logger.With(logging.Fields{"stage": "discovery"})
	template := requestTemplate{
		Method: http.MethodGet,
		URL:    target.String(),
		Headers: http.Header{
			"Accept": []string{"text/html,application/xhtml+xml"},
		},
	}
	resp, err := e.execute(ctx, scanID, template, opts.UserAgent, opts.Headers)
	if err != nil {
		return nil, err
	}
	if resp == nil || len(resp.Body) == 0 {
		return nil, nil
	}

	body := string(resp.Body)
	if !strings.Contains(strings.ToLower(resp.Headers.Get("Content-Type")), "html") {
		lower := strings.ToLower(body)
		if !strings.Contains(lower, "<form") {
			return nil, nil
		}
	}

	rawForms := extractForms(body)
	forms := make([]discoveredForm, 0, len(rawForms))
	for idx, raw := range rawForms {
		method := strings.ToUpper(strings.TrimSpace(raw.attrs["method"]))
		if method == "" {
			method = http.MethodGet
		}
		actionAttr := strings.TrimSpace(raw.attrs["action"])
		actionURL := cloneURL(target)
		if actionAttr != "" {
			if parsed, err := target.Parse(actionAttr); err == nil {
				actionURL = parsed
			}
		}
		enctype := strings.ToLower(strings.TrimSpace(raw.attrs["enctype"]))
		if enctype == "" {
			enctype = "application/x-www-form-urlencoded"
		}

		inputs := collectFormInputs(raw.body)
		if len(inputs) == 0 {
			continue
		}

		source := raw.attrs["id"]
		if source == "" {
			source = raw.attrs["name"]
		}
		if source == "" {
			source = fmt.Sprintf("form#%d", idx+1)
		}

		forms = append(forms, discoveredForm{
			Method:    method,
			Action:    actionURL,
			Inputs:    inputs,
			Enctype:   enctype,
			Source:    source,
			RawAction: actionAttr,
		})
	}

	logger.Debug("forms discovered", logging.Fields{"count": len(forms)})
	return forms, nil
}

type rawForm struct {
	attrs map[string]string
	body  string
}

func extractForms(doc string) []rawForm {
	lower := strings.ToLower(doc)
	forms := []rawForm{}
	search := 0
	for {
		start := strings.Index(lower[search:], "<form")
		if start == -1 {
			break
		}
		start += search
		openEnd := strings.Index(lower[start:], ">")
		if openEnd == -1 {
			break
		}
		openEnd += start + 1
		closeIdx := strings.Index(lower[openEnd:], "</form")
		var body string
		var next int
		if closeIdx == -1 {
			body = doc[openEnd:]
			next = len(doc)
		} else {
			closeIdx += openEnd
			body = doc[openEnd:closeIdx]
			next = strings.Index(lower[closeIdx:], ">")
			if next == -1 {
				next = closeIdx + len("</form>")
			} else {
				next = closeIdx + next + 1
			}
		}
		openTag := doc[start:openEnd]
		attrs := parseAttributes(openTag)
		forms = append(forms, rawForm{attrs: attrs, body: body})
		if next <= search {
			search = start + 1
		} else {
			search = next
		}
	}
	return forms
}

func parseAttributes(tag string) map[string]string {
	attrs := map[string]string{}
	matches := attributeRegexp.FindAllStringSubmatch(tag, -1)
	for _, match := range matches {
		if len(match) < 3 {
			continue
		}
		key := strings.ToLower(match[1])
		val := strings.Trim(match[2], "'\"")
		attrs[key] = html.UnescapeString(val)
	}
	stripped := attributeRegexp.ReplaceAllString(strings.ToLower(tag), " ")
	for _, token := range booleanAttributeTokens {
		if strings.Contains(stripped, " "+token) {
			if _, exists := attrs[token]; !exists {
				attrs[token] = ""
			}
		}
	}
	return attrs
}

func collectFormInputs(body string) []formInput {
	seen := map[string]formInput{}
	order := []string{}
	lower := strings.ToLower(body)

	search := 0
	for {
		idx := strings.Index(lower[search:], "<input")
		if idx == -1 {
			break
		}
		idx += search
		end := strings.Index(lower[idx:], ">")
		if end == -1 {
			break
		}
		end += idx + 1
		tag := body[idx:end]
		attrs := parseAttributes(tag)
		name := strings.TrimSpace(attrs["name"])
		if name == "" {
			search = end
			continue
		}
		typ := strings.ToLower(strings.TrimSpace(attrs["type"]))
		switch typ {
		case "submit", "button", "image", "reset":
			search = end
			continue
		}
		value := attrs["value"]
		if _, ok := seen[name]; !ok {
			seen[name] = formInput{Name: name, Value: value}
			order = append(order, name)
		}
		search = end
	}

	search = 0
	for {
		idx := strings.Index(lower[search:], "<textarea")
		if idx == -1 {
			break
		}
		idx += search
		openEnd := strings.Index(lower[idx:], ">")
		if openEnd == -1 {
			break
		}
		openEnd += idx + 1
		closeIdx := strings.Index(lower[openEnd:], "</textarea")
		if closeIdx == -1 {
			break
		}
		closeIdx += openEnd
		tag := body[idx:openEnd]
		attrs := parseAttributes(tag)
		name := strings.TrimSpace(attrs["name"])
		if name == "" {
			search = closeIdx
			continue
		}
		value := html.UnescapeString(body[openEnd:closeIdx])
		if _, ok := seen[name]; !ok {
			seen[name] = formInput{Name: name, Value: strings.TrimSpace(value)}
			order = append(order, name)
		}
		search = closeIdx + len("</textarea>")
	}

	search = 0
	for {
		idx := strings.Index(lower[search:], "<select")
		if idx == -1 {
			break
		}
		idx += search
		openEnd := strings.Index(lower[idx:], ">")
		if openEnd == -1 {
			break
		}
		openEnd += idx + 1
		closeIdx := strings.Index(lower[openEnd:], "</select")
		if closeIdx == -1 {
			break
		}
		closeIdx += openEnd
		tag := body[idx:openEnd]
		attrs := parseAttributes(tag)
		name := strings.TrimSpace(attrs["name"])
		if name == "" {
			search = closeIdx
			continue
		}
		value := selectDefaultValue(body[openEnd:closeIdx])
		if _, ok := seen[name]; !ok {
			seen[name] = formInput{Name: name, Value: value}
			order = append(order, name)
		}
		search = closeIdx + len("</select>")
	}

	inputs := make([]formInput, 0, len(order))
	for _, name := range order {
		inputs = append(inputs, seen[name])
	}
	return inputs
}

func selectDefaultValue(body string) string {
	lower := strings.ToLower(body)
	search := 0
	first := ""
	for {
		idx := strings.Index(lower[search:], "<option")
		if idx == -1 {
			break
		}
		idx += search
		end := strings.Index(lower[idx:], ">")
		if end == -1 {
			break
		}
		end += idx + 1
		tag := body[idx:end]
		attrs := parseAttributes(tag)
		value := attrs["value"]
		if value == "" {
			value = html.UnescapeString(extractOptionText(body[end:]))
		}
		if _, hasSelected := attrs["selected"]; hasSelected {
			return value
		}
		if first == "" {
			first = value
		}
		search = end
	}
	return first
}

func extractOptionText(remaining string) string {
	end := strings.Index(strings.ToLower(remaining), "</option")
	if end == -1 {
		end = len(remaining)
	}
	return strings.TrimSpace(remaining[:end])
}
