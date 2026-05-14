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
