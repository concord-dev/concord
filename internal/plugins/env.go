package plugins

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

const allowedEnvFile = "capabilities.json"

type capabilitiesRecord struct {
	RequiredEnv []string `json:"required_env,omitempty"`
	OptionalEnv []string `json:"optional_env,omitempty"`
}

// readAllowedEnv loads the env allowlist recorded next to a discovered binary.
// Returns nil when the sidecar file is absent — in which case the parent's
// full environment is passed through for backwards compatibility.
func readAllowedEnv(versionDir string) []string {
	raw, err := os.ReadFile(filepath.Join(versionDir, allowedEnvFile))
	if err != nil {
		return nil
	}
	var rec capabilitiesRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil
	}
	out := make([]string, 0, len(rec.RequiredEnv)+len(rec.OptionalEnv))
	out = append(out, rec.RequiredEnv...)
	out = append(out, rec.OptionalEnv...)
	if len(out) == 0 {
		return nil
	}
	return out
}

// WriteAllowedEnv persists a plugin's required+optional env vars to a sidecar
// JSON next to the binary so subsequent Discover calls can pre-scope the
// environment without re-querying the plugin.
func WriteAllowedEnv(versionDir string, required, optional []string) error {
	rec := capabilitiesRecord{RequiredEnv: required, OptionalEnv: optional}
	raw, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(versionDir, allowedEnvFile), raw, 0o644)
}

// essentialEnv names variables every plugin process needs regardless of its
// declared Required/Optional env list (PATH, locale, time zone, etc.).
var essentialEnv = []string{
	"PATH",
	"HOME",
	"USER",
	"LANG",
	"LC_ALL",
	"TZ",
	"TMPDIR",
	"SystemRoot",
	"PATHEXT",
	"HOSTNAME",
}

// scopedEnv returns the subset of os.Environ() that matches an essential
// variable or a key in allowed. When allowed is nil, scoping is disabled
// and the full parent environment is returned (legacy behaviour).
func scopedEnv(allowed []string) []string {
	if allowed == nil {
		return os.Environ()
	}
	allow := make(map[string]struct{}, len(allowed)+len(essentialEnv))
	for _, k := range essentialEnv {
		allow[k] = struct{}{}
	}
	for _, k := range allowed {
		allow[k] = struct{}{}
	}
	out := make([]string, 0, len(allow))
	for _, kv := range os.Environ() {
		eq := strings.IndexByte(kv, '=')
		if eq < 0 {
			continue
		}
		if _, ok := allow[kv[:eq]]; ok {
			out = append(out, kv)
		}
	}
	return out
}

// SetAllowedEnv pins the env-var allowlist for a discovered source so the
// next spawn passes only that subset (plus essentials) to the plugin
// process. Typically populated from the plugin's Capabilities response.
func (m *Manager) SetAllowedEnv(source string, allowed []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.discovered[source]; ok {
		e.allowedEnv = append([]string(nil), allowed...)
	}
}
