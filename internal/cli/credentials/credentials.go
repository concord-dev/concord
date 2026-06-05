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

const DefaultProfileName = "default"

var ErrNoCredentials = errors.New("credentials: no credentials file (run `concord login`)")

var ErrNoCurrentProfile = errors.New("credentials: current profile not found")

type File struct {
	Current  string              `json:"current"`
	Profiles map[string]*Profile `json:"profiles"`
}

type Profile struct {
	Server string `json:"server"`

	Token string `json:"token,omitempty"`

	UserID    string `json:"user_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`

	DefaultOrg string `json:"default_org,omitempty"`

	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

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

func (f *File) SetCurrent(name string) {
	if f.Profiles == nil {
		f.Profiles = map[string]*Profile{}
	}
	if _, ok := f.Profiles[name]; !ok {
		f.Profiles[name] = &Profile{}
	}
	f.Current = name
}

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

func LoadOrInit() (*File, error) {
	f, err := Load()
	if errors.Is(err, ErrNoCredentials) {
		return &File{Profiles: map[string]*Profile{}}, nil
	}
	return f, err
}

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
