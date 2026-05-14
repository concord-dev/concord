package evidence

import (
	"os"
	"regexp"
)

var envRefRe = regexp.MustCompile(`\$\{env\.([A-Z_][A-Z0-9_]*)\}`)

// StringParam reads a string-valued param, resolving ${env.X} references against the process environment.
func StringParam(params map[string]any, key, def string) string {
	if params == nil {
		return def
	}
	raw, ok := params[key]
	if !ok {
		return def
	}
	s, ok := raw.(string)
	if !ok {
		return def
	}
	resolved := ResolveEnv(s)
	if resolved == "" {
		return def
	}
	return resolved
}

// ResolveEnv replaces every ${env.NAME} occurrence in s with os.Getenv(NAME).
func ResolveEnv(s string) string {
	return envRefRe.ReplaceAllStringFunc(s, func(m string) string {
		match := envRefRe.FindStringSubmatch(m)
		if len(match) < 2 {
			return ""
		}
		return os.Getenv(match[1])
	})
}

// IntParam reads an int-valued param. Accepts native ints/floats from YAML
// and falls back to def when the param is missing or not a number.
func IntParam(params map[string]any, key string, def int) int {
	if params == nil {
		return def
	}
	raw, ok := params[key]
	if !ok {
		return def
	}
	switch v := raw.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	}
	return def
}

// StringSliceParam reads a []string-valued param, resolving ${env.X} per element.
// Non-string elements and empty resolved values are dropped.
func StringSliceParam(params map[string]any, key string) []string {
	if params == nil {
		return nil
	}
	raw, ok := params[key]
	if !ok {
		return nil
	}
	list, ok := raw.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		s, ok := item.(string)
		if !ok {
			continue
		}
		if r := ResolveEnv(s); r != "" {
			out = append(out, r)
		}
	}
	return out
}
