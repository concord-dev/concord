package plugins_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/concord-dev/concord/internal/plugins"
)

// TestRemediatorSpawn smoke-tests the host-side wrapper by spawning the
// locally-installed concord-plugin-aws-remediator and calling
// Capabilities. Skips when the plugin is not installed.
func TestRemediatorSpawn(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("home dir: %v", err)
	}
	bin := filepath.Join(home, ".concord", "plugins", "aws-remediator", "v0.1.0", "concord-plugin-aws-remediator")
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("aws-remediator not installed at %s: %v", bin, err)
	}
	mgr := plugins.New(plugins.Options{})
	if err := mgr.Discover(); err != nil {
		t.Fatalf("discover: %v", err)
	}
	entry := mgr.FindRemediator("aws")
	if entry == nil {
		t.Fatalf("aws-remediator not discovered (available: %v)", mgr.Available())
	}
	if entry.Source != "aws-remediator" {
		t.Errorf("entry.Source = %q, want aws-remediator", entry.Source)
	}
	rem, err := plugins.SpawnRemediator(*entry, 30*time.Second)
	if err != nil {
		t.Fatalf("spawn: %v", err)
	}
	defer rem.Close()
	caps, err := rem.Capabilities(context.Background())
	if err != nil {
		t.Fatalf("capabilities: %v", err)
	}
	want := []string{
		"s3.enable_public_access_block",
		"iam.attach_mfa_policy",
		"kms.enable_key_rotation",
	}
	for _, w := range want {
		found := false
		for _, a := range caps.Actions {
			if a == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("plugin did not advertise action %q (got %v)", w, caps.Actions)
		}
	}
}
