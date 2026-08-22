package githubapi

import (
	"errors"
	"net/url"
	"path"
	"strings"
)

func (c *Client) nextLink(header string) (*url.URL, error) {
	for _, part := range splitLinkHeader(header) {
		part = strings.TrimSpace(part)
		if part == "" || part[0] != '<' {
			continue
		}
		end := strings.IndexByte(part, '>')
		if end < 1 {
			return nil, errors.New("malformed Link header")
		}
		if !hasLinkRelation(part[end+1:], "next") {
			continue
		}
		candidate, err := url.Parse(part[1:end])
		if err != nil || !candidate.IsAbs() {
			return nil, errors.New("next Link target is not an absolute URL")
		}
		if err := c.validateAPIURL(candidate); err != nil {
			return nil, err
		}
		return candidate, nil
	}
	return nil, nil
}

func paginationParameters(base map[string]string, next *url.URL) map[string]string {
	result := make(map[string]string, len(base)+4)
	for key, value := range base {
		result[key] = value
	}
	if next == nil {
		return result
	}
	for key, values := range next.Query() {
		result["query."+key] = strings.Join(values, ",")
	}
	return result
}

func safePaginationQuery(candidate *url.URL) error {
	for key := range candidate.Query() {
		normalized := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "-", ""), "_", ""))
		switch normalized {
		case "token", "accesstoken", "authorization", "sig", "signature", "xamzsignature":
			return errors.New("next Link target contained a credential-like query parameter")
		}
	}
	if cleaned := path.Clean(candidate.Path); cleaned != candidate.Path {
		return errors.New("next Link target contained a non-canonical path")
	}
	return nil
}

func splitLinkHeader(value string) []string {
	var result []string
	start := 0
	inAngles := false
	inQuotes := false
	escaped := false
	for index, r := range value {
		switch {
		case escaped:
			escaped = false
		case r == '\\' && inQuotes:
			escaped = true
		case r == '"':
			inQuotes = !inQuotes
		case r == '<' && !inQuotes:
			inAngles = true
		case r == '>' && !inQuotes:
			inAngles = false
		case r == ',' && !inAngles && !inQuotes:
			result = append(result, value[start:index])
			start = index + 1
		}
	}
	result = append(result, value[start:])
	return result
}

func hasLinkRelation(parameters, wanted string) bool {
	for _, parameter := range strings.Split(parameters, ";") {
		key, value, ok := strings.Cut(strings.TrimSpace(parameter), "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(key), "rel") {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"`)
		for _, relation := range strings.Fields(value) {
			if relation == wanted {
				return true
			}
		}
	}
	return false
}
