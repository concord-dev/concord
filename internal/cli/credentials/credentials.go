// Package credentials owns the CLI's on-disk session-credentials file. One
// instance per user, mode-0600, JSON-encoded, multi-profile so a single
// developer machine can hold prod + staging sessions side by side.
//
// File layout follows the XDG Base Directory spec: the file lives at
// $XDG_CONFIG_HOME/concord/credentials.json, falling back to
// $HOME/.config/concord/credentials.json when XDG_CONFIG_HOME is unset.
// Tests can pin a temp path via the CONCORD_CREDENTIALS_FILE env var.
//
// Reading uses Load(); writing uses Save(). Save is atomic — it writes a
// sibling file then renames over the target, so a crashed CLI can never
// leave a half-written credentials file that would log the user out.
package credentials

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// DefaultProfileName is the profile created when `concord login` is run
// without --profile. Picked once at file-creation and persisted under
// `current` thereafter — switching is opt-in.
const DefaultProfileName = "default"

// ErrNoCredentials is returned by Load when the credentials file is absent.
// Distinguishable so callers can hint the user toward `concord login`.
var ErrNoCredentials = errors.New("credentials: no credentials file (run `concord login`)")

// ErrNoCurrentProfile is returned by File.Current when the named profile
// is missing — including when `current` points at a profile that has
// since been deleted.
var ErrNoCurrentProfile = errors.New("credentials: current profile not found")

// File is the on-disk shape. JSON because the file is human-eyeballable
// during debugging, not because we expect any reader other than the CLI.
type File struct {
	Current  string              `json:"current"`
	Profiles map[string]*Profile `json:"profiles"`
}

// Profile is one named (server, identity, session) tuple. A user with two
// Concord deployments keeps two profiles; switching between them is a
// one-liner (`concord orgs use` / future `concord profile use`).
type Profile struct {
	// Server is the base URL of the Concord deployment this profile points
	// at (e.g. "https://concord.example.com"). Always stored without a
	// trailing slash so URL composition is predictable.
	Server string `json:"server"`

	// Token is the session token plaintext (`concord_sess_…`). Stored
	// rather than re-derivable because there's no refresh-token path yet
	// — when ExpiresAt passes the user re-runs `concord login`.
	Token string `json:"token,omitempty"`

	// UserID and UserEmail are denormalized off `/v1/me` at login time so
	// `concord whoami` is offline-friendly. They're hints; the API is the
	// source of truth on every real call.
	UserID    string `json:"user_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`

	// DefaultOrg is the slug `push` / `check --to` / `watch --to` fall
	// back to when --org-slug isn't supplied. Set via `concord orgs use`.
	DefaultOrg string `json:"default_org,omitempty"`

	// ExpiresAt mirrors the session row in the server's user_session
	// table. Used by the CLI to print "your session expires in N hours"
	// hints; the server is authoritative on actual rejection.
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// CurrentProfile returns the active profile or ErrNoCurrentProfile when the
// file is empty / the cursor (Current field) points at a deleted profile.
func (f *File) CurrentProfile() (*Profile, error) {
	if f == nil || f.Current == "" {
		return nil, ErrNoCurrentProfile
	}
	p, ok := f.Profiles[f.Current]
	if !ok || p == nil {
		return nil, ErrNoCurrentProfile
	}
	return p, nil
}

// SetCurrent points the cursor at the named profile, creating it if it
// doesn't exist.
func (f *File) SetCurrent(name string) {
	if f.Profiles == nil {
		f.Profiles = map[string]*Profile{}
	}
	if _, ok := f.Profiles[name]; !ok {
		f.Profiles[name] = &Profile{}
	}
	f.Current = name
}

// Path returns the resolved credentials file path. Respects
// CONCORD_CREDENTIALS_FILE (tests + bespoke setups), XDG_CONFIG_HOME, then
// $HOME/.config/concord/credentials.json.
func Path() (string, error) {
	if v := os.Getenv("CONCORD_CREDENTIALS_FILE"); v != "" {
		return v, nil
	}
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return filepath.Join(dir, "concord", "credentials.json"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolving home directory: %w", err)
	}
	return filepath.Join(home, ".config", "concord", "credentials.json"), nil
}

// Load reads + parses the credentials file. ErrNoCredentials when the file
// doesn't exist — caller decides whether that's fatal or just "fall back to
// flags/env".
func Load() (*File, error) {
	path, err := Path()
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrNoCredentials
		}
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var f File
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if f.Profiles == nil {
		f.Profiles = map[string]*Profile{}
	}
	return &f, nil
}

// LoadOrInit returns Load's result OR a fresh empty File when the file is
// absent. Useful in writers (login, orgs-use) that should create the file
// rather than error.
func LoadOrInit() (*File, error) {
	f, err := Load()
	if errors.Is(err, ErrNoCredentials) {
		return &File{Profiles: map[string]*Profile{}}, nil
	}
	return f, err
}

// Save atomically writes the file with mode 0600. Uses temp-file + rename
// so a crash mid-write can't truncate the previous version into corruption.
// Parent directory is created with 0700 — same logic, no other user has
// any reason to traverse it.
func Save(f *File) error {
	path, err := Path()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("creating credentials dir: %w", err)
	}
	body, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding credentials: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".credentials-*.tmp")
	if err != nil {
		return fmt.Errorf("creating temp credentials: %w", err)
	}
	tmpPath := tmp.Name()
	// chmod BEFORE the rename so the final file lands at 0600 without
	// briefly existing as the default 0644 on filesystems where the umask
	// would otherwise apply.
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("chmod temp credentials: %w", err)
	}
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("writing temp credentials: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("closing temp credentials: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("installing credentials: %w", err)
	}
	return nil
}

// Delete removes the credentials file. Used by `concord logout` after the
// server has revoked the session. Missing file is not an error — the
// user's intent is "be logged out" and they already are.
func Delete() error {
	path, err := Path()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
